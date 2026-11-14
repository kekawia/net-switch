package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

const (
	CarrierLocal = "local"

	DefaultMaxHandshakes      = 128
	DefaultMaxUDPAssociations = 256
)

// Options configures a proxy-aware LineDialer wrapper.
type Options struct {
	MaxHandshakes      int
	MaxUDPAssociations int
	TLSConfig          *tls.Config
	Resolver           func(ctx context.Context, host string) ([]netip.Addr, error)
}

type lineRuntime struct {
	cfg          platform.ProxyLine
	handshakes   atomic.Int32
	associations atomic.Int32
}

// Dialer wraps a platform.LineDialer, routing physical and VPN lines directly
// to Base while executing SOCKS5 and HTTP/HTTPS CONNECT over the configured
// carrier line (or loopback "local") for proxy lines.
type Dialer struct {
	base    platform.LineDialer
	maxHS   int32
	maxUDP  int32
	tlsCfg  *tls.Config
	resolve func(ctx context.Context, host string) ([]netip.Addr, error)

	mu    sync.RWMutex
	lines map[string]*lineRuntime
	creds map[string]Credentials
}

func NewDialer(base platform.LineDialer, opts Options) *Dialer {
	maxHS := opts.MaxHandshakes
	if maxHS <= 0 {
		maxHS = DefaultMaxHandshakes
	}
	maxUDP := opts.MaxUDPAssociations
	if maxUDP <= 0 {
		maxUDP = DefaultMaxUDPAssociations
	}
	resolve := opts.Resolver
	if resolve == nil {
		resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	return &Dialer{
		base:    base,
		maxHS:   int32(maxHS),
		maxUDP:  int32(maxUDP),
		tlsCfg:  opts.TLSConfig,
		resolve: resolve,
		lines:   map[string]*lineRuntime{},
		creds:   map[string]Credentials{},
	}
}

// SetLines updates the active proxy line definitions while preserving live
// concurrency counters for unchanged proxy line IDs.
func (d *Dialer) SetLines(lines []platform.Line) {
	d.mu.Lock()
	defer d.mu.Unlock()
	next := make(map[string]*lineRuntime, len(lines))
	for _, l := range lines {
		if l.Proxy == nil {
			continue
		}
		if prev, ok := d.lines[l.ID]; ok {
			updated := &lineRuntime{cfg: *l.Proxy}
			updated.handshakes.Store(prev.handshakes.Load())
			updated.associations.Store(prev.associations.Load())
			next[l.ID] = updated
			continue
		}
		next[l.ID] = &lineRuntime{cfg: *l.Proxy}
	}
	d.lines = next
}

// SetCredentials atomically replaces the in-memory credential map keyed by
// CredentialsRef. Secrets are copied defensively.
func (d *Dialer) SetCredentials(creds map[string]Credentials) {
	cp := make(map[string]Credentials, len(creds))
	for k, v := range creds {
		if k != "" {
			cp[k] = v
		}
	}
	d.mu.Lock()
	d.creds = cp
	d.mu.Unlock()
}

func (d *Dialer) lookup(lineID string) (*lineRuntime, Credentials, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	rt, ok := d.lines[lineID]
	if !ok {
		return nil, Credentials{}, false
	}
	var c Credentials
	if rt.cfg.CredentialsRef != "" {
		c = d.creds[rt.cfg.CredentialsRef]
	}
	return rt, c, true
}

// LineDialer returns a platform.LineDialer view of d that exposes
// platform.DestinationDialer if and only if Base implements it, preserving
// FlowDialer precedence on platforms that do not use DestinationDialer.
func (d *Dialer) LineDialer() platform.LineDialer {
	if dd, ok := d.base.(platform.DestinationDialer); ok {
		return &destinationDialer{Dialer: d, dest: dd}
	}
	return d
}

type destinationDialer struct {
	*Dialer
	dest platform.DestinationDialer
}

func (dd *destinationDialer) OpenUDPTo(ctx context.Context, line string, dst netip.AddrPort) (platform.UDPConn, error) {
	rt, creds, isProxy := dd.lookup(line)
	if !isProxy {
		return dd.dest.OpenUDPTo(ctx, line, dst)
	}
	return dd.openProxyUDP(ctx, line, rt, creds, dst.Addr().Unmap().Is6(), nil)
}

func (d *Dialer) DialTCP(ctx context.Context, line string, dst netip.AddrPort) (conn platform.TCPConn, err error) {
	rt, creds, isProxy := d.lookup(line)
	if !isProxy {
		return d.base.DialTCP(ctx, line, dst)
	}
	return d.dialProxyTCP(ctx, line, rt, creds, dst, nil)
}

func (d *Dialer) DialFlowTCP(ctx context.Context, line string, dst netip.AddrPort, flow platform.FlowIdentity) (platform.TCPConn, error) {
	rt, creds, isProxy := d.lookup(line)
	if !isProxy {
		if fd, ok := d.base.(platform.FlowDialer); ok {
			return fd.DialFlowTCP(ctx, line, dst, flow)
		}
		return d.base.DialTCP(ctx, line, dst)
	}
	return d.dialProxyTCP(ctx, line, rt, creds, dst, &flow)
}

func (d *Dialer) OpenUDP(ctx context.Context, line string, ipv6 bool) (platform.UDPConn, error) {
	rt, creds, isProxy := d.lookup(line)
	if !isProxy {
		return d.base.OpenUDP(ctx, line, ipv6)
	}
	return d.openProxyUDP(ctx, line, rt, creds, ipv6, nil)
}

func (d *Dialer) OpenFlowUDP(ctx context.Context, line string, ipv6 bool, flow platform.FlowIdentity) (platform.UDPConn, error) {
	rt, creds, isProxy := d.lookup(line)
	if !isProxy {
		if fd, ok := d.base.(platform.FlowDialer); ok {
			return fd.OpenFlowUDP(ctx, line, ipv6, flow)
		}
		return d.base.OpenUDP(ctx, line, ipv6)
	}
	return d.openProxyUDP(ctx, line, rt, creds, ipv6, &flow)
}

func (d *Dialer) dialProxyTCP(ctx context.Context, lineID string, rt *lineRuntime, creds Credentials, dst netip.AddrPort, flow *platform.FlowIdentity) (conn platform.TCPConn, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = &Error{Kind: KindProtocol, Protocol: rt.cfg.Protocol, Detail: fmt.Sprintf("recovered panic: %v", r)}
		}
	}()

	proto := strings.ToLower(rt.cfg.Protocol)
	if proto != "socks5" && proto != "http" && proto != "https" {
		return nil, &Error{Kind: KindConfig, Protocol: proto, Detail: "unsupported proxy protocol"}
	}
	if err := d.validateCarrier(lineID, rt.cfg.Carrier); err != nil {
		return nil, err
	}

	if rt.handshakes.Add(1) > d.maxHS {
		rt.handshakes.Add(-1)
		return nil, &Error{Kind: KindCapExceeded, Protocol: proto, Detail: "proxy concurrent handshake cap reached"}
	}
	defer rt.handshakes.Add(-1)

	targets, hostName, err := d.resolveServer(ctx, proto, rt.cfg)
	if err != nil {
		return nil, err
	}
	raw, _, err := d.dialCarrierTCP(ctx, proto, rt.cfg.Carrier, targets, flow)
	if err != nil {
		return nil, err
	}

	sni := rt.cfg.ServerName
	if sni == "" {
		sni = hostName
	}
	switch proto {
	case "socks5":
		return dialSOCKS5TCP(ctx, raw, dst, creds)
	case "http":
		return dialHTTPConnect(ctx, raw, false, d.tlsCfg, sni, dst, creds)
	case "https":
		return dialHTTPConnect(ctx, raw, true, d.tlsCfg, sni, dst, creds)
	default:
		raw.Close()
		return nil, &Error{Kind: KindConfig, Protocol: proto, Detail: "unsupported proxy protocol"}
	}
}

func (d *Dialer) openProxyUDP(ctx context.Context, lineID string, rt *lineRuntime, creds Credentials, ipv6 bool, flow *platform.FlowIdentity) (conn platform.UDPConn, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = &Error{Kind: KindProtocol, Protocol: rt.cfg.Protocol, Detail: fmt.Sprintf("recovered panic: %v", r)}
		}
	}()

	proto := strings.ToLower(rt.cfg.Protocol)
	if proto != "socks5" || !rt.cfg.UDP {
		return nil, platform.ErrUnsupportedUDP
	}
	if err := d.validateCarrier(lineID, rt.cfg.Carrier); err != nil {
		return nil, err
	}

	if rt.handshakes.Add(1) > d.maxHS {
		rt.handshakes.Add(-1)
		return nil, &Error{Kind: KindCapExceeded, Protocol: proto, Detail: "proxy concurrent handshake cap reached"}
	}
	defer rt.handshakes.Add(-1)

	if rt.associations.Add(1) > d.maxUDP {
		rt.associations.Add(-1)
		return nil, &Error{Kind: KindCapExceeded, Protocol: proto, Detail: "proxy UDP association cap reached"}
	}
	released := false
	releaseAssoc := func() {
		rt.associations.Add(-1)
	}
	defer func() {
		if !released {
			releaseAssoc()
		}
	}()

	targets, _, err := d.resolveServer(ctx, proto, rt.cfg)
	if err != nil {
		return nil, err
	}
	tcpConn, chosenServer, err := d.dialCarrierTCP(ctx, proto, rt.cfg.Carrier, targets, flow)
	if err != nil {
		return nil, err
	}
	udpIPv6 := chosenServer.Addr().Unmap().Is6()
	_ = ipv6 // inner target family is encoded per datagram; carrier leg matches the proxy server's family
	udpConn, err := d.openCarrierUDP(ctx, proto, rt.cfg.Carrier, chosenServer, udpIPv6, flow)
	if err != nil {
		tcpConn.Close()
		return nil, err
	}

	assoc, err := openSOCKS5UDP(ctx, tcpConn, udpConn, chosenServer.Addr(), creds, releaseAssoc)
	if err != nil {
		return nil, err
	}
	released = true
	return assoc, nil
}

func (d *Dialer) validateCarrier(lineID, carrier string) error {
	if carrier == "" || carrier == lineID {
		return &Error{Kind: KindConfig, Detail: "invalid or self-referential proxy carrier"}
	}
	if carrier == CarrierLocal {
		return nil
	}
	d.mu.RLock()
	_, carrierIsProxy := d.lines[carrier]
	d.mu.RUnlock()
	if carrierIsProxy {
		return &Error{Kind: KindConfig, Detail: "proxy carrier cannot be another proxy line"}
	}
	return nil
}

func (d *Dialer) resolveServer(ctx context.Context, proto string, cfg platform.ProxyLine) ([]netip.AddrPort, string, error) {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(cfg.Server))
	if err != nil || host == "" {
		return nil, "", &Error{Kind: KindConfig, Protocol: proto, Detail: "invalid proxy server address"}
	}
	portNum, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || portNum == 0 {
		return nil, "", &Error{Kind: KindConfig, Protocol: proto, Detail: "invalid proxy server port"}
	}
	port := uint16(portNum)

	if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
		ip = ip.Unmap()
		if cfg.Carrier == CarrierLocal && !ip.IsLoopback() {
			return nil, "", &Error{Kind: KindConfig, Protocol: proto, Detail: "local carrier requires a loopback proxy address (127.0.0.1 or ::1)"}
		}
		return []netip.AddrPort{netip.AddrPortFrom(ip, port)}, ip.String(), nil
	}

	if cfg.Carrier == CarrierLocal && !strings.EqualFold(host, "localhost") {
		return nil, "", &Error{Kind: KindConfig, Protocol: proto, Detail: "local carrier requires localhost, 127.0.0.1, or ::1"}
	}

	ips, err := d.resolve(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, "", &Error{Kind: KindUnreachable, Protocol: proto, Detail: "resolve proxy host", Cause: err}
	}
	out := make([]netip.AddrPort, 0, len(ips))
	for _, ip := range ips {
		ip = ip.Unmap()
		if cfg.Carrier == CarrierLocal && !ip.IsLoopback() {
			continue
		}
		out = append(out, netip.AddrPortFrom(ip, port))
	}
	if len(out) == 0 {
		return nil, "", &Error{Kind: KindConfig, Protocol: proto, Detail: "resolved proxy address is not loopback for local carrier"}
	}
	return out, host, nil
}

func (d *Dialer) dialCarrierTCP(ctx context.Context, proto, carrier string, targets []netip.AddrPort, flow *platform.FlowIdentity) (platform.TCPConn, netip.AddrPort, error) {
	var lastErr error
	for _, target := range targets {
		if carrier == CarrierLocal {
			c, err := dialLocalTCP(ctx, target)
			if err == nil {
				return c, target, nil
			}
			lastErr = err
			continue
		}
		if d.base == nil {
			return nil, netip.AddrPort{}, &Error{Kind: KindConfig, Protocol: proto, Detail: "missing carrier dialer"}
		}
		var (
			c   platform.TCPConn
			err error
		)
		if flow != nil {
			if fd, ok := d.base.(platform.FlowDialer); ok {
				f := *flow
				f.Destination = target
				c, err = fd.DialFlowTCP(ctx, carrier, target, f)
			} else {
				c, err = d.base.DialTCP(ctx, carrier, target)
			}
		} else {
			c, err = d.base.DialTCP(ctx, carrier, target)
		}
		if err == nil {
			return c, target, nil
		}
		lastErr = err
	}
	return nil, netip.AddrPort{}, &Error{Kind: KindUnreachable, Protocol: proto, Detail: "dial proxy server", Cause: lastErr}
}

func (d *Dialer) openCarrierUDP(ctx context.Context, proto, carrier string, server netip.AddrPort, ipv6 bool, flow *platform.FlowIdentity) (platform.UDPConn, error) {
	if carrier == CarrierLocal {
		c, err := openLocalUDP(ipv6)
		if err != nil {
			return nil, &Error{Kind: KindUnreachable, Protocol: proto, Detail: "open local UDP socket", Cause: err}
		}
		return c, nil
	}
	if d.base == nil {
		return nil, &Error{Kind: KindConfig, Protocol: proto, Detail: "missing carrier dialer"}
	}
	var (
		c   platform.UDPConn
		err error
	)
	if dd, ok := d.base.(platform.DestinationDialer); ok {
		c, err = dd.OpenUDPTo(ctx, carrier, server)
	} else if flow != nil {
		if fd, ok := d.base.(platform.FlowDialer); ok {
			f := *flow
			f.Destination = server
			c, err = fd.OpenFlowUDP(ctx, carrier, ipv6, f)
		} else {
			c, err = d.base.OpenUDP(ctx, carrier, ipv6)
		}
	} else {
		c, err = d.base.OpenUDP(ctx, carrier, ipv6)
	}
	if err != nil {
		return nil, &Error{Kind: KindUnreachable, Protocol: proto, Detail: "open carrier UDP socket", Cause: err}
	}
	return c, nil
}

type localTCPConn struct {
	*net.TCPConn
}

func dialLocalTCP(ctx context.Context, target netip.AddrPort) (platform.TCPConn, error) {
	network := "tcp4"
	localIP := net.IPv4(127, 0, 0, 1)
	if target.Addr().Is6() {
		network = "tcp6"
		localIP = net.IPv6loopback
	}
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: localIP}}
	c, err := dialer.DialContext(ctx, network, target.String())
	if err != nil {
		return nil, err
	}
	tc, ok := c.(*net.TCPConn)
	if !ok {
		c.Close()
		return nil, errors.New("unexpected non-TCP connection")
	}
	return &localTCPConn{TCPConn: tc}, nil
}

type localUDPConn struct {
	*net.UDPConn
	raw    syscall.RawConn
	closed atomic.Bool
}

func openLocalUDP(ipv6 bool) (platform.UDPConn, error) {
	network := "udp4"
	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	if ipv6 {
		network = "udp6"
		localAddr = &net.UDPAddr{IP: net.IPv6loopback, Port: 0}
	}
	uc, err := net.ListenUDP(network, localAddr)
	if err != nil {
		return nil, err
	}
	rc, err := uc.SyscallConn()
	if err != nil {
		uc.Close()
		return nil, err
	}
	return &localUDPConn{UDPConn: uc, raw: rc}, nil
}

func (u *localUDPConn) WaitReadable(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if u.closed.Load() {
		return net.ErrClosed
	}
	stop := context.AfterFunc(ctx, func() {
		_ = u.UDPConn.SetReadDeadline(time.Unix(1, 0))
	})
	defer func() {
		if stop() && !u.closed.Load() {
			_ = u.UDPConn.SetReadDeadline(time.Time{})
		}
	}()
	err := waitLoopbackUDPReadable(u.raw)
	if err != nil {
		if u.closed.Load() {
			return net.ErrClosed
		}
		if ctx.Err() != nil {
			if !u.closed.Load() {
				_ = u.UDPConn.SetReadDeadline(time.Time{})
			}
			return ctx.Err()
		}
		return err
	}
	return nil
}

func (u *localUDPConn) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	if u.closed.Load() {
		return 0, netip.AddrPort{}, net.ErrClosed
	}
	n, ap, err := u.UDPConn.ReadFromUDPAddrPort(b)
	if err != nil {
		if u.closed.Load() {
			return 0, netip.AddrPort{}, net.ErrClosed
		}
		if platform.IsTooBig(err) {
			return 0, netip.AddrPort{}, &platform.TooBig{MTU: uint32(len(b))}
		}
		return 0, netip.AddrPort{}, err
	}
	return n, unmapAddrPort(ap), nil
}

func (u *localUDPConn) WriteTo(payload []byte, dst netip.AddrPort, _ bool) (int, error) {
	if u.closed.Load() {
		return 0, net.ErrClosed
	}
	n, err := u.UDPConn.WriteToUDPAddrPort(payload, unmapAddrPort(dst))
	if err != nil {
		if u.closed.Load() {
			return 0, net.ErrClosed
		}
		if platform.IsTooBig(err) {
			return 0, &platform.TooBig{MTU: uint32(len(payload))}
		}
		return 0, err
	}
	return n, nil
}

func (u *localUDPConn) LocalAddr() netip.AddrPort {
	if addr, ok := u.UDPConn.LocalAddr().(*net.UDPAddr); ok && addr != nil {
		return unmapAddrPort(addr.AddrPort())
	}
	return netip.AddrPort{}
}

func (u *localUDPConn) Close() error {
	u.closed.Store(true)
	return u.UDPConn.Close()
}
