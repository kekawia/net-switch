package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kekawia/net-switch/internal/engine/platform"
)

const (
	socks5Version = 0x05
	authNone      = 0x00
	authUserPass  = 0x02
	authNoAccept  = 0xFF
	userPassVer   = 0x01

	cmdConnect      = 0x01
	cmdUDPAssociate = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	SOCKS5UDPv4HeaderLen = 10
	SOCKS5UDPv6HeaderLen = 22
	maxUDPFrameSize      = 65535
)

var (
	errFragmentedDatagram = errors.New("SOCKS5 UDP fragmentation is not supported")
	errInvalidUDPHeader   = errors.New("invalid SOCKS5 UDP header")
)

var udpFramePool = sync.Pool{
	New: func() any {
		b := make([]byte, maxUDPFrameSize)
		return &b
	},
}

// socks5TCPConn wraps a platform.TCPConn without exposing platform.ReadyTCP so
// the engine uses the standard Splice relay cleanly across all proxy types,
// while still forwarding WaitReadable so idle flows release pool buffers.
type socks5TCPConn struct {
	platform.TCPConn
}

func (c *socks5TCPConn) WaitReadable(ctx context.Context) error {
	if ready, ok := c.TCPConn.(interface{ WaitReadable(context.Context) error }); ok {
		return ready.WaitReadable(ctx)
	}
	return nil
}

func dialSOCKS5TCP(ctx context.Context, raw platform.TCPConn, dst netip.AddrPort, creds Credentials) (platform.TCPConn, error) {
	stop := abortConnOnCancel(ctx, raw)

	if err := socks5Negotiate(raw, creds); err != nil {
		stop()
		raw.Close()
		return nil, err
	}
	dst = unmapAddrPort(dst)
	req, err := buildSOCKS5Request(cmdConnect, dst)
	if err != nil {
		stop()
		raw.Close()
		return nil, err
	}
	if _, err := raw.Write(req); err != nil {
		stop()
		raw.Close()
		return nil, &Error{Kind: KindUnreachable, Protocol: "socks5", Detail: "write connect", Cause: err}
	}
	rep, _, _, err := socks5ReadReply(raw)
	if err != nil {
		stop()
		raw.Close()
		return nil, err
	}
	if err := classifySOCKS5Rep(rep); err != nil {
		stop()
		raw.Close()
		return nil, err
	}
	if !stop() {
		raw.Close()
		return nil, &Error{Kind: KindUnreachable, Protocol: "socks5", Detail: "handshake canceled", Cause: ctx.Err()}
	}
	_ = raw.SetDeadline(time.Time{})
	return &socks5TCPConn{TCPConn: raw}, nil
}

func openSOCKS5UDP(ctx context.Context, tcpConn platform.TCPConn, udpConn platform.UDPConn, proxyServerIP netip.Addr, creds Credentials, release func()) (platform.UDPConn, error) {
	stop := abortConnOnCancel(ctx, tcpConn)
	fail := func(err error) (platform.UDPConn, error) {
		stop()
		tcpConn.Close()
		udpConn.Close()
		return nil, err
	}

	if err := socks5Negotiate(tcpConn, creds); err != nil {
		return fail(err)
	}

	local := unmapAddrPort(udpConn.LocalAddr())
	assocTarget := netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
	if local.Addr().Is6() {
		assocTarget = netip.AddrPortFrom(netip.IPv6Unspecified(), 0)
	}
	req, err := buildSOCKS5Request(cmdUDPAssociate, assocTarget)
	if err != nil {
		return fail(err)
	}
	if _, err := tcpConn.Write(req); err != nil {
		return fail(&Error{Kind: KindUnreachable, Protocol: "socks5", Detail: "write udp associate", Cause: err})
	}
	rep, bndAddr, bndPort, err := socks5ReadReply(tcpConn)
	if err != nil {
		return fail(err)
	}
	if rep == 0x07 {
		return fail(platform.ErrUnsupportedUDP)
	}
	if err := classifySOCKS5Rep(rep); err != nil {
		return fail(err)
	}
	if bndPort == 0 {
		return fail(&Error{Kind: KindProtocol, Protocol: "socks5", Detail: "UDP ASSOCIATE returned port 0"})
	}
	relayIP := resolveRelayAddr(bndAddr, proxyServerIP.Unmap())
	if !relayIP.IsValid() {
		return fail(&Error{Kind: KindProtocol, Protocol: "socks5", Detail: "UDP ASSOCIATE returned invalid relay address"})
	}
	if relayIP.Is6() != local.Addr().Is6() {
		return fail(&Error{Kind: KindProxyRejected, Protocol: "socks5", Detail: "UDP ASSOCIATE relay address family mismatch"})
	}
	if !stop() {
		tcpConn.Close()
		udpConn.Close()
		return nil, &Error{Kind: KindUnreachable, Protocol: "socks5", Detail: "handshake canceled", Cause: ctx.Err()}
	}

	_ = tcpConn.SetDeadline(time.Time{})
	c := &socks5UDPConn{
		tcp:     tcpConn,
		udp:     udpConn,
		relay:   netip.AddrPortFrom(relayIP, bndPort),
		done:    make(chan struct{}),
		release: release,
	}
	go c.watchControl()
	return c, nil
}

// resolveRelayAddr substitutes the proxy's own TCP address when BND.ADDR is
// unspecified (0.0.0.0 / ::) or loopback/private while the proxy itself is
// reached at a public address (PROXY-VPN-STUDY 3.2).
func resolveRelayAddr(bndAddr, proxyIP netip.Addr) netip.Addr {
	bnd := bndAddr.Unmap()
	if !bnd.IsValid() || bnd.IsUnspecified() {
		return proxyIP
	}
	if proxyIP.IsValid() && !proxyIP.IsLoopback() && bnd.IsLoopback() {
		return proxyIP
	}
	if proxyIP.IsValid() && !proxyIP.IsPrivate() && !proxyIP.IsLoopback() && bnd.IsPrivate() {
		return proxyIP
	}
	return bnd
}

func socks5Negotiate(rw io.ReadWriter, creds Credentials) error {
	if len(creds.Username) > 255 || len(creds.Password) > 255 {
		return &Error{Kind: KindConfig, Protocol: "socks5", Detail: "credentials exceed 255 bytes"}
	}
	var greeting []byte
	if creds.Empty() {
		greeting = []byte{socks5Version, 0x01, authNone}
	} else {
		greeting = []byte{socks5Version, 0x02, authNone, authUserPass}
	}
	if _, err := rw.Write(greeting); err != nil {
		return &Error{Kind: KindUnreachable, Protocol: "socks5", Detail: "write greeting", Cause: err}
	}
	var reply [2]byte
	if _, err := io.ReadFull(rw, reply[:]); err != nil {
		return &Error{Kind: KindUnreachable, Protocol: "socks5", Detail: "read greeting", Cause: err}
	}
	if reply[0] != socks5Version {
		return &Error{Kind: KindProtocol, Protocol: "socks5", Code: int(reply[0]), Detail: fmt.Sprintf("unexpected version 0x%02x", reply[0])}
	}
	switch reply[1] {
	case authNone:
		return nil
	case authUserPass:
		if creds.Empty() {
			return &Error{Kind: KindAuth, Protocol: "socks5", Code: int(authUserPass), Detail: "proxy requires username and password"}
		}
		u := []byte(creds.Username)
		p := []byte(creds.Password)
		sub := make([]byte, 0, 3+len(u)+len(p))
		sub = append(sub, userPassVer, byte(len(u)))
		sub = append(sub, u...)
		sub = append(sub, byte(len(p)))
		sub = append(sub, p...)
		if _, err := rw.Write(sub); err != nil {
			return &Error{Kind: KindUnreachable, Protocol: "socks5", Detail: "write auth", Cause: err}
		}
		var authReply [2]byte
		if _, err := io.ReadFull(rw, authReply[:]); err != nil {
			return &Error{Kind: KindAuth, Protocol: "socks5", Detail: "read auth reply", Cause: err}
		}
		if authReply[0] != userPassVer {
			return &Error{Kind: KindProtocol, Protocol: "socks5", Code: int(authReply[0]), Detail: fmt.Sprintf("unexpected auth version 0x%02x", authReply[0])}
		}
		if authReply[1] != 0x00 {
			return &Error{Kind: KindAuth, Protocol: "socks5", Code: int(authReply[1]), Detail: "proxy rejected username or password"}
		}
		return nil
	case authNoAccept:
		return &Error{Kind: KindAuth, Protocol: "socks5", Code: int(authNoAccept), Detail: "no acceptable authentication method"}
	default:
		return &Error{Kind: KindProtocol, Protocol: "socks5", Code: int(reply[1]), Detail: fmt.Sprintf("unsupported auth method 0x%02x", reply[1])}
	}
}

func buildSOCKS5Request(cmd byte, dst netip.AddrPort) ([]byte, error) {
	addr := dst.Addr().Unmap()
	if !addr.IsValid() {
		return nil, &Error{Kind: KindConfig, Protocol: "socks5", Detail: "invalid target address"}
	}
	if addr.Is4() {
		b := make([]byte, 10)
		b[0], b[1], b[2], b[3] = socks5Version, cmd, 0x00, atypIPv4
		ip4 := addr.As4()
		copy(b[4:8], ip4[:])
		binary.BigEndian.PutUint16(b[8:10], dst.Port())
		return b, nil
	}
	b := make([]byte, 22)
	b[0], b[1], b[2], b[3] = socks5Version, cmd, 0x00, atypIPv6
	ip6 := addr.As16()
	copy(b[4:20], ip6[:])
	binary.BigEndian.PutUint16(b[20:22], dst.Port())
	return b, nil
}

func socks5ReadReply(r io.Reader) (rep byte, bndAddr netip.Addr, bndPort uint16, err error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, netip.Addr{}, 0, &Error{Kind: KindUnreachable, Protocol: "socks5", Detail: "read reply header", Cause: err}
	}
	if hdr[0] != socks5Version {
		return 0, netip.Addr{}, 0, &Error{Kind: KindProtocol, Protocol: "socks5", Code: int(hdr[0]), Detail: fmt.Sprintf("unexpected reply version 0x%02x", hdr[0])}
	}
	rep = hdr[1]
	switch hdr[3] {
	case atypIPv4:
		var tail [6]byte
		if _, err := io.ReadFull(r, tail[:]); err != nil {
			if rep != 0 {
				return rep, netip.Addr{}, 0, nil
			}
			return 0, netip.Addr{}, 0, &Error{Kind: KindProtocol, Protocol: "socks5", Detail: "truncated IPv4 reply", Cause: err}
		}
		bndAddr = netip.AddrFrom4([4]byte(tail[0:4]))
		bndPort = binary.BigEndian.Uint16(tail[4:6])
	case atypIPv6:
		var tail [18]byte
		if _, err := io.ReadFull(r, tail[:]); err != nil {
			if rep != 0 {
				return rep, netip.Addr{}, 0, nil
			}
			return 0, netip.Addr{}, 0, &Error{Kind: KindProtocol, Protocol: "socks5", Detail: "truncated IPv6 reply", Cause: err}
		}
		bndAddr = netip.AddrFrom16([16]byte(tail[0:16]))
		bndPort = binary.BigEndian.Uint16(tail[16:18])
	case atypDomain:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			if rep != 0 {
				return rep, netip.Addr{}, 0, nil
			}
			return 0, netip.Addr{}, 0, &Error{Kind: KindProtocol, Protocol: "socks5", Detail: "truncated domain length", Cause: err}
		}
		tail := make([]byte, int(n[0])+2)
		if _, err := io.ReadFull(r, tail); err != nil {
			if rep != 0 {
				return rep, netip.Addr{}, 0, nil
			}
			return 0, netip.Addr{}, 0, &Error{Kind: KindProtocol, Protocol: "socks5", Detail: "truncated domain reply", Cause: err}
		}
		if ip, parseErr := netip.ParseAddr(string(tail[:n[0]])); parseErr == nil {
			bndAddr = ip
		}
		bndPort = binary.BigEndian.Uint16(tail[n[0]:])
	default:
		if rep != 0 {
			return rep, netip.Addr{}, 0, nil
		}
		return 0, netip.Addr{}, 0, &Error{Kind: KindProtocol, Protocol: "socks5", Code: int(hdr[3]), Detail: fmt.Sprintf("unsupported reply ATYP 0x%02x", hdr[3])}
	}
	return rep, bndAddr, bndPort, nil
}

func classifySOCKS5Rep(rep byte) error {
	switch rep {
	case 0x00:
		return nil
	case 0x01:
		return &Error{Kind: KindProxyRejected, Protocol: "socks5", Code: int(rep), Detail: "general SOCKS server failure"}
	case 0x02:
		return &Error{Kind: KindProxyRejected, Protocol: "socks5", Code: int(rep), Detail: "blocked by proxy ruleset"}
	case 0x03:
		return &Error{Kind: KindDestination, Protocol: "socks5", Code: int(rep), Detail: "destination network unreachable"}
	case 0x04:
		return &Error{Kind: KindDestination, Protocol: "socks5", Code: int(rep), Detail: "destination host unreachable"}
	case 0x05:
		return &Error{Kind: KindDestination, Protocol: "socks5", Code: int(rep), Detail: "destination refused connection"}
	case 0x06:
		return &Error{Kind: KindDestination, Protocol: "socks5", Code: int(rep), Detail: "TTL expired"}
	case 0x07:
		return &Error{Kind: KindProxyRejected, Protocol: "socks5", Code: int(rep), Detail: "command not supported by proxy"}
	case 0x08:
		return &Error{Kind: KindProxyRejected, Protocol: "socks5", Code: int(rep), Detail: "address type not supported by proxy"}
	default:
		return &Error{Kind: KindProtocol, Protocol: "socks5", Code: int(rep), Detail: fmt.Sprintf("unknown SOCKS5 reply code 0x%02x", rep)}
	}
}

// EncodeSOCKS5UDP writes a SOCKS5 UDP request header + payload into dst,
// returning (totalFrameBytes, headerBytes, error).
func EncodeSOCKS5UDP(dst []byte, target netip.AddrPort, payload []byte) (int, int, error) {
	addr := target.Addr().Unmap()
	if !addr.IsValid() {
		return 0, 0, errInvalidUDPHeader
	}
	hdrLen := SOCKS5UDPv4HeaderLen
	if addr.Is6() {
		hdrLen = SOCKS5UDPv6HeaderLen
	}
	total := hdrLen + len(payload)
	if total > len(dst) {
		return 0, hdrLen, &platform.TooBig{MTU: uint32(max(len(dst)-hdrLen, 0))}
	}
	dst[0], dst[1], dst[2] = 0x00, 0x00, 0x00 // RSV=0, FRAG=0
	if addr.Is4() {
		dst[3] = atypIPv4
		ip4 := addr.As4()
		copy(dst[4:8], ip4[:])
		binary.BigEndian.PutUint16(dst[8:10], target.Port())
	} else {
		dst[3] = atypIPv6
		ip6 := addr.As16()
		copy(dst[4:20], ip6[:])
		binary.BigEndian.PutUint16(dst[20:22], target.Port())
	}
	copy(dst[hdrLen:total], payload)
	return total, hdrLen, nil
}

// DecodeSOCKS5UDP parses an inbound SOCKS5 UDP datagram per RFC 1928 section 7.
// Fragmented datagrams (FRAG != 0) are rejected as required when reassembly is
// not implemented.
func DecodeSOCKS5UDP(frame []byte) (netip.AddrPort, []byte, error) {
	if len(frame) < SOCKS5UDPv4HeaderLen {
		return netip.AddrPort{}, nil, errInvalidUDPHeader
	}
	if frame[0] != 0x00 || frame[1] != 0x00 {
		return netip.AddrPort{}, nil, errInvalidUDPHeader
	}
	if frame[2] != 0x00 {
		return netip.AddrPort{}, nil, errFragmentedDatagram
	}
	switch frame[3] {
	case atypIPv4:
		ip := netip.AddrFrom4([4]byte(frame[4:8]))
		port := binary.BigEndian.Uint16(frame[8:10])
		return netip.AddrPortFrom(ip, port), frame[10:], nil
	case atypIPv6:
		if len(frame) < SOCKS5UDPv6HeaderLen {
			return netip.AddrPort{}, nil, errInvalidUDPHeader
		}
		ip := netip.AddrFrom16([16]byte(frame[4:20]))
		port := binary.BigEndian.Uint16(frame[20:22])
		return netip.AddrPortFrom(ip, port), frame[22:], nil
	case atypDomain:
		n := int(frame[4])
		hdrLen := 4 + 1 + n + 2
		if len(frame) < hdrLen {
			return netip.AddrPort{}, nil, errInvalidUDPHeader
		}
		ip, err := netip.ParseAddr(string(frame[5 : 5+n]))
		if err != nil {
			return netip.AddrPort{}, nil, errInvalidUDPHeader
		}
		port := binary.BigEndian.Uint16(frame[5+n : hdrLen])
		return netip.AddrPortFrom(ip.Unmap(), port), frame[hdrLen:], nil
	default:
		return netip.AddrPort{}, nil, errInvalidUDPHeader
	}
}

type socks5UDPConn struct {
	tcp     platform.TCPConn
	udp     platform.UDPConn
	relay   netip.AddrPort
	done    chan struct{}
	closed  atomic.Bool
	once    sync.Once
	release func()
}

// watchControl closes the UDP association as soon as the TCP control connection
// terminates (RFC 1928 section 6).
func (c *socks5UDPConn) watchControl() {
	var scratch [64]byte
	for {
		if _, err := c.tcp.Read(scratch[:]); err != nil {
			_ = c.Close()
			return
		}
	}
}

func (c *socks5UDPConn) WaitReadable(ctx context.Context) error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	return c.udp.WaitReadable(ctx)
}

func (c *socks5UDPConn) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	if c.closed.Load() {
		return 0, netip.AddrPort{}, net.ErrClosed
	}
	bufPtr := udpFramePool.Get().(*[]byte)
	defer udpFramePool.Put(bufPtr)
	raw := *bufPtr

	n, src, err := c.udp.ReadFrom(raw)
	if err != nil {
		if c.closed.Load() {
			return 0, netip.AddrPort{}, net.ErrClosed
		}
		return 0, netip.AddrPort{}, err
	}
	if unmapAddrPort(src) != c.relay {
		return 0, netip.AddrPort{}, platform.ErrDatagramDropped
	}
	origin, payload, decErr := DecodeSOCKS5UDP(raw[:n])
	if decErr != nil {
		return 0, netip.AddrPort{}, platform.ErrDatagramDropped
	}
	// A 1-byte discard read under reply-budget pressure drains the datagram
	// without failing on payload length (internal/engine/udp/reply.go).
	if len(b) > 1 && len(payload) > len(b) {
		return 0, netip.AddrPort{}, &platform.TooBig{MTU: uint32(len(b))}
	}
	copied := copy(b, payload)
	return copied, origin, nil
}

func (c *socks5UDPConn) WriteTo(payload []byte, dst netip.AddrPort, df bool) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	dst = unmapAddrPort(dst)
	bufPtr := udpFramePool.Get().(*[]byte)
	defer udpFramePool.Put(bufPtr)
	raw := *bufPtr

	frameLen, hdrLen, err := EncodeSOCKS5UDP(raw, dst, payload)
	if err != nil {
		return 0, err
	}
	if _, err := c.udp.WriteTo(raw[:frameLen], c.relay, df); err != nil {
		if c.closed.Load() {
			return 0, net.ErrClosed
		}
		var big *platform.TooBig
		if errors.As(err, &big) {
			inner := uint32(0)
			if big.MTU > uint32(hdrLen) {
				inner = big.MTU - uint32(hdrLen)
			}
			return 0, &platform.TooBig{MTU: inner}
		}
		if platform.IsTooBig(err) {
			return 0, &platform.TooBig{MTU: 0}
		}
		return 0, err
	}
	return len(payload), nil
}

func (c *socks5UDPConn) LocalAddr() netip.AddrPort {
	return c.udp.LocalAddr()
}

func (c *socks5UDPConn) Close() error {
	var closeErr error
	c.once.Do(func() {
		c.closed.Store(true)
		close(c.done)
		if c.release != nil {
			c.release()
		}
		errUDP := c.udp.Close()
		errTCP := c.tcp.Close()
		closeErr = errors.Join(errUDP, errTCP)
	})
	return closeErr
}

func unmapAddrPort(ap netip.AddrPort) netip.AddrPort {
	if !ap.IsValid() {
		return ap
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

func abortConnOnCancel(ctx context.Context, c net.Conn) func() bool {
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	return context.AfterFunc(ctx, func() {
		_ = c.SetDeadline(time.Unix(1, 0))
		_ = c.Close()
	})
}
