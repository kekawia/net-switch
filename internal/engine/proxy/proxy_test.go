package proxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kekawia/net-switch/internal/engine/platform"
)

func startEchoTCP(t *testing.T, network, addr string, banner []byte) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Skipf("listen %s %s unavailable: %v", network, addr, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				if len(banner) > 0 {
					if _, err := conn.Write(banner); err != nil {
						return
					}
				}
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	return unmapAddrPort(ln.Addr().(*net.TCPAddr).AddrPort())
}

func startEchoUDP(t *testing.T, network, addr string) netip.AddrPort {
	t.Helper()
	uc, err := net.ListenUDP(network, func() *net.UDPAddr {
		ap := netip.MustParseAddrPort(addr)
		return net.UDPAddrFromAddrPort(ap)
	}())
	if err != nil {
		t.Skipf("listen %s %s unavailable: %v", network, addr, err)
	}
	t.Cleanup(func() { _ = uc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			out := append([]byte("echo:"), buf[:n]...)
			_, _ = uc.WriteToUDP(out, from)
		}
	}()
	return unmapAddrPort(uc.LocalAddr().(*net.UDPAddr).AddrPort())
}

type mockSOCKS5Options struct {
	network        string
	listenAddr     string
	requireAuth    bool
	wantUser       string
	wantPass       string
	forceRep       byte
	enableUDP      bool
	returnZeroBnd  bool
	coalesceBanner []byte
	onControlConn  func(net.Conn)
}

func startMockSOCKS5(t *testing.T, opts mockSOCKS5Options) netip.AddrPort {
	t.Helper()
	if opts.network == "" {
		opts.network = "tcp4"
	}
	if opts.listenAddr == "" {
		opts.listenAddr = "127.0.0.1:0"
	}
	ln, err := net.Listen(opts.network, opts.listenAddr)
	if err != nil {
		t.Skipf("listen %s %s unavailable: %v", opts.network, opts.listenAddr, err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleMockSOCKS5(c, opts)
		}
	}()
	return unmapAddrPort(ln.Addr().(*net.TCPAddr).AddrPort())
}

func handleMockSOCKS5(c net.Conn, opts mockSOCKS5Options) {
	defer c.Close()

	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil || hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	hasMethod := func(m byte) bool {
		for _, v := range methods {
			if v == m {
				return true
			}
		}
		return false
	}

	if opts.requireAuth {
		if !hasMethod(0x02) {
			_, _ = c.Write([]byte{0x05, 0xFF})
			return
		}
		_, _ = c.Write([]byte{0x05, 0x02})
		var uHdr [2]byte
		if _, err := io.ReadFull(c, uHdr[:]); err != nil || uHdr[0] != 0x01 {
			return
		}
		u := make([]byte, int(uHdr[1]))
		if _, err := io.ReadFull(c, u); err != nil {
			return
		}
		var pLen [1]byte
		if _, err := io.ReadFull(c, pLen[:]); err != nil {
			return
		}
		p := make([]byte, int(pLen[0]))
		if _, err := io.ReadFull(c, p); err != nil {
			return
		}
		if string(u) != opts.wantUser || string(p) != opts.wantPass {
			_, _ = c.Write([]byte{0x01, 0x01})
			return
		}
		_, _ = c.Write([]byte{0x01, 0x00})
	} else {
		if !hasMethod(0x00) {
			_, _ = c.Write([]byte{0x05, 0xFF})
			return
		}
		_, _ = c.Write([]byte{0x05, 0x00})
	}

	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil || req[0] != 0x05 {
		return
	}
	cmd := req[1]
	var dst netip.AddrPort
	switch req[3] {
	case atypIPv4:
		var b [6]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return
		}
		dst = netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[0:4])), binary.BigEndian.Uint16(b[4:6]))
	case atypIPv6:
		var b [18]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return
		}
		dst = netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[0:16])), binary.BigEndian.Uint16(b[16:18]))
	default:
		_, _ = c.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	if opts.forceRep != 0 {
		_, _ = c.Write([]byte{0x05, opts.forceRep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	switch cmd {
	case cmdConnect:
		upNet := "tcp4"
		if dst.Addr().Is6() {
			upNet = "tcp6"
		}
		up, err := net.DialTimeout(upNet, dst.String(), 2*time.Second)
		if err != nil {
			_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		defer up.Close()
		reply := append([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}, opts.coalesceBanner...)
		if _, err := c.Write(reply); err != nil {
			return
		}
		done := make(chan struct{}, 2)
		go func() {
			_, _ = io.Copy(up, c)
			if tc, ok := up.(*net.TCPConn); ok {
				_ = tc.CloseWrite()
			}
			done <- struct{}{}
		}()
		go func() {
			_, _ = io.Copy(c, up)
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.CloseWrite()
			}
			done <- struct{}{}
		}()
		<-done
		<-done

	case cmdUDPAssociate:
		if !opts.enableUDP {
			_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		localTCP := unmapAddrPort(c.LocalAddr().(*net.TCPAddr).AddrPort())
		udpNet := "udp4"
		bindIP := net.IPv4(127, 0, 0, 1)
		if localTCP.Addr().Is6() {
			udpNet = "udp6"
			bindIP = net.IPv6loopback
		}
		relaySock, err := net.ListenUDP(udpNet, &net.UDPAddr{IP: bindIP, Port: 0})
		if err != nil {
			_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		defer relaySock.Close()
		relayAP := unmapAddrPort(relaySock.LocalAddr().(*net.UDPAddr).AddrPort())

		bndIP := relayAP.Addr()
		if opts.returnZeroBnd {
			if bndIP.Is6() {
				bndIP = netip.IPv6Unspecified()
			} else {
				bndIP = netip.IPv4Unspecified()
			}
		}
		reply, _ := buildSOCKS5Request(0x00, netip.AddrPortFrom(bndIP, relayAP.Port()))
		if _, err := c.Write(reply); err != nil {
			return
		}
		if opts.onControlConn != nil {
			opts.onControlConn(c)
		}

		go func() {
			var clientAddr *net.UDPAddr
			buf := make([]byte, 65535)
			for {
				n, from, err := relaySock.ReadFromUDP(buf)
				if err != nil {
					return
				}
				fromAP := unmapAddrPort(from.AddrPort())
				if clientAddr == nil || unmapAddrPort(clientAddr.AddrPort()) == fromAP {
					target, payload, decErr := DecodeSOCKS5UDP(buf[:n])
					if decErr == nil {
						clientAddr = from
						_, _ = relaySock.WriteToUDPAddrPort(payload, target)
						continue
					}
				}
				if clientAddr != nil {
					out := make([]byte, 65535)
					frameLen, _, encErr := EncodeSOCKS5UDP(out, fromAP, buf[:n])
					if encErr == nil {
						_, _ = relaySock.WriteToUDP(out[:frameLen], clientAddr)
					}
				}
			}
		}()

		var scratch [16]byte
		for {
			if _, err := c.Read(scratch[:]); err != nil {
				return
			}
		}
	default:
		_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
}

func TestSOCKS5ConnectAuthAndServerFirstBanner(t *testing.T) {
	echoAP := startEchoTCP(t, "tcp4", "127.0.0.1:0", nil)
	proxyNoAuth := startMockSOCKS5(t, mockSOCKS5Options{
		coalesceBanner: []byte("SERVER-FIRST:"),
	})
	mockSecret := strings.Repeat("k", 7)
	proxyAuth := startMockSOCKS5(t, mockSOCKS5Options{
		requireAuth: true,
		wantUser:    "alice",
		wantPass:    mockSecret,
	})

	d := NewDialer(nil, Options{})
	d.SetLines([]platform.Line{
		{
			ID: "p-open",
			Proxy: &platform.ProxyLine{
				Protocol: "socks5",
				Server:   proxyNoAuth.String(),
				Carrier:  CarrierLocal,
			},
		},
		{
			ID: "p-auth",
			Proxy: &platform.ProxyLine{
				Protocol:       "socks5",
				Server:         proxyAuth.String(),
				Carrier:        CarrierLocal,
				CredentialsRef: "cred-1",
			},
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Unauthenticated CONNECT with server-first bytes coalesced right after 10B reply.
	conn, err := d.DialTCP(ctx, "p-open", echoAP)
	if err != nil {
		t.Fatalf("DialTCP open proxy: %v", err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.CloseWrite()
	got, err := io.ReadAll(conn)
	_ = conn.Close()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "SERVER-FIRST:ping" {
		t.Fatalf("got %q, want %q", string(got), "SERVER-FIRST:ping")
	}

	// 2. Missing credentials when proxy requires RFC 1929 -> KindAuth (line fault).
	if _, err := d.DialTCP(ctx, "p-auth", echoAP); err == nil {
		t.Fatal("expected auth error with missing credentials")
	} else {
		var pe *Error
		if !errors.As(err, &pe) || pe.Kind != KindAuth || !IsLineFault(err) {
			t.Fatalf("unexpected error classification: %v (IsLineFault=%v)", err, IsLineFault(err))
		}
	}

	// 3. Wrong password -> KindAuth.
	d.SetCredentials(map[string]Credentials{"cred-1": {Username: "alice", Password: "wrong"}})
	if _, err := d.DialTCP(ctx, "p-auth", echoAP); err == nil {
		t.Fatal("expected auth error with wrong password")
	} else {
		var pe *Error
		if !errors.As(err, &pe) || pe.Kind != KindAuth || !IsLineFault(err) {
			t.Fatalf("unexpected wrong-password classification: %v", err)
		}
	}

	// 4. Correct credentials -> full echo round-trip.
	d.SetCredentials(map[string]Credentials{"cred-1": {Username: "alice", Password: mockSecret}})
	authConn, err := d.DialTCP(ctx, "p-auth", echoAP)
	if err != nil {
		t.Fatalf("DialTCP with valid auth: %v", err)
	}
	defer authConn.Close()
	if _, err := authConn.Write([]byte("authenticated-payload")); err != nil {
		t.Fatalf("write auth conn: %v", err)
	}
	buf := make([]byte, 64)
	n, err := io.ReadFull(authConn, buf[:len("authenticated-payload")])
	if err != nil || string(buf[:n]) != "authenticated-payload" {
		t.Fatalf("read auth conn: got %q, err %v", string(buf[:n]), err)
	}
}

func TestSOCKS5ReplyFaultClassification(t *testing.T) {
	cases := []struct {
		rep       byte
		wantKind  Kind
		wantFault bool
	}{
		{0x01, KindProxyRejected, true},
		{0x02, KindProxyRejected, true},
		{0x03, KindDestination, false},
		{0x04, KindDestination, false},
		{0x05, KindDestination, false},
		{0x06, KindDestination, false},
		{0x07, KindProxyRejected, true},
		{0x08, KindProxyRejected, true},
		{0x99, KindProtocol, true},
	}
	for _, tc := range cases {
		err := classifySOCKS5Rep(tc.rep)
		if err == nil {
			t.Fatalf("rep 0x%02x returned nil error", tc.rep)
		}
		var pe *Error
		if !errors.As(err, &pe) {
			t.Fatalf("rep 0x%02x not *Error: %T", tc.rep, err)
		}
		if pe.Kind != tc.wantKind {
			t.Fatalf("rep 0x%02x kind = %v, want %v", tc.rep, pe.Kind, tc.wantKind)
		}
		if got := IsLineFault(err); got != tc.wantFault {
			t.Fatalf("rep 0x%02x IsLineFault = %v, want %v", tc.rep, got, tc.wantFault)
		}
	}
	if IsLineFault(nil) || IsLineFault(context.Canceled) || IsLineFault(platform.ErrUnsupportedUDP) {
		t.Fatal("nil, Canceled, and ErrUnsupportedUDP must never count as line faults")
	}
}

func TestSOCKS5UDPAssociateSecurityMTUAndControlLifetime(t *testing.T) {
	echoUDP := startEchoUDP(t, "udp4", "127.0.0.1:0")

	var ctrlMu sync.Mutex
	var serverCtrl net.Conn
	proxyAP := startMockSOCKS5(t, mockSOCKS5Options{
		enableUDP:     true,
		returnZeroBnd: true, // verifies 0.0.0.0 -> 127.0.0.1 substitution
		onControlConn: func(c net.Conn) {
			ctrlMu.Lock()
			serverCtrl = c
			ctrlMu.Unlock()
		},
	})

	d := NewDialer(nil, Options{})
	d.SetLines([]platform.Line{{
		ID: "p-udp",
		Proxy: &platform.ProxyLine{
			Protocol: "socks5",
			Server:   proxyAP.String(),
			Carrier:  CarrierLocal,
			UDP:      true,
		},
	}})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	assoc, err := d.OpenUDP(ctx, "p-udp", false)
	if err != nil {
		t.Fatalf("OpenUDP: %v", err)
	}
	defer assoc.Close()

	// 1. Spoofed UDP datagram from a non-relay port must be dropped without breaking session.
	rogue, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("rogue UDP: %v", err)
	}
	defer rogue.Close()
	forged := make([]byte, 64)
	forgedLen, _, _ := EncodeSOCKS5UDP(forged, echoUDP, []byte("spoofed"))
	if _, err := rogue.WriteToUDPAddrPort(forged[:forgedLen], assoc.LocalAddr()); err != nil {
		t.Fatalf("write rogue: %v", err)
	}
	if err := assoc.WaitReadable(ctx); err != nil {
		t.Fatalf("WaitReadable rogue: %v", err)
	}
	buf := make([]byte, 256)
	if _, _, err := assoc.ReadFrom(buf); !errors.Is(err, platform.ErrDatagramDropped) {
		t.Fatalf("spoofed source ReadFrom err = %v, want ErrDatagramDropped", err)
	}

	// 2. Real UDP round-trip through SOCKS5 relay (WaitReadable must not consume!).
	if n, err := assoc.WriteTo([]byte("hello-udp"), echoUDP, true); err != nil || n != len("hello-udp") {
		t.Fatalf("WriteTo: n=%d err=%v", n, err)
	}
	if err := assoc.WaitReadable(ctx); err != nil {
		t.Fatalf("WaitReadable #1: %v", err)
	}
	if err := assoc.WaitReadable(ctx); err != nil {
		t.Fatalf("WaitReadable #2 (must be idempotent/non-consuming): %v", err)
	}
	n, from, err := assoc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if from != echoUDP || string(buf[:n]) != "echo:hello-udp" {
		t.Fatalf("got (%q from %v), want (%q from %v)", string(buf[:n]), from, "echo:hello-udp", echoUDP)
	}

	// 3. 1-byte discard read under reply-budget pressure must drain without returning TooBig.
	if _, err := assoc.WriteTo([]byte("discard-me"), echoUDP, false); err != nil {
		t.Fatalf("WriteTo discard: %v", err)
	}
	if err := assoc.WaitReadable(ctx); err != nil {
		t.Fatalf("WaitReadable discard: %v", err)
	}
	var discard [1]byte
	if _, _, err := assoc.ReadFrom(discard[:]); err != nil {
		t.Fatalf("1-byte discard ReadFrom failed: %v", err)
	}

	// 4. Closing the TCP control stream on the proxy side must close the UDP association.
	ctrlMu.Lock()
	sc := serverCtrl
	ctrlMu.Unlock()
	if sc == nil {
		t.Fatal("missing server control conn")
	}
	_ = sc.Close()

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer waitCancel()
	for {
		err := assoc.WaitReadable(waitCtx)
		if errors.Is(err, net.ErrClosed) {
			break
		}
		if waitCtx.Err() != nil {
			t.Fatalf("UDP association did not close after TCP control closed (last err=%v)", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Association slot must be released when control connection dies.
	rt, _, _ := d.lookup("p-udp")
	if got := rt.associations.Load(); got != 0 {
		t.Fatalf("active UDP associations = %d, want 0", got)
	}
}

type mtuStubUDP struct {
	mtu uint32
}

func (m mtuStubUDP) WaitReadable(context.Context) error           { return nil }
func (m mtuStubUDP) ReadFrom([]byte) (int, netip.AddrPort, error) { return 0, netip.AddrPort{}, io.EOF }
func (m mtuStubUDP) WriteTo([]byte, netip.AddrPort, bool) (int, error) {
	return 0, &platform.TooBig{MTU: m.mtu}
}
func (m mtuStubUDP) LocalAddr() netip.AddrPort { return netip.MustParseAddrPort("127.0.0.1:55555") }
func (m mtuStubUDP) Close() error              { return nil }

func TestSOCKS5UDPFragmentRejectionAndTooBigOverhead(t *testing.T) {
	// FRAG != 0 must be rejected per RFC 1928 section 7.
	fragFrame := []byte{0x00, 0x00, 0x01, atypIPv4, 1, 1, 1, 1, 0x00, 0x35, 'x'}
	if _, _, err := DecodeSOCKS5UDP(fragFrame); !errors.Is(err, errFragmentedDatagram) {
		t.Fatalf("FRAG=1 err = %v, want errFragmentedDatagram", err)
	}

	// TooBig on carrier socket must subtract 10 bytes for IPv4 and 22 bytes for IPv6.
	c := &socks5UDPConn{
		udp:   mtuStubUDP{mtu: 1280},
		relay: netip.MustParseAddrPort("127.0.0.1:1080"),
		done:  make(chan struct{}),
	}
	_, err4 := c.WriteTo([]byte("abc"), netip.MustParseAddrPort("1.1.1.1:443"), true)
	var big4 *platform.TooBig
	if !errors.As(err4, &big4) || big4.MTU != 1270 {
		t.Fatalf("IPv4 TooBig = %#v (err=%v), want MTU 1270", big4, err4)
	}
	_, err6 := c.WriteTo([]byte("abc"), netip.MustParseAddrPort("[2606:4700:4700::1111]:443"), true)
	var big6 *platform.TooBig
	if !errors.As(err6, &big6) || big6.MTU != 1258 {
		t.Fatalf("IPv6 TooBig = %#v (err=%v), want MTU 1258", big6, err6)
	}
}

func startMockHTTPProxy(t *testing.T, tlsCfg *tls.Config, handler func(conn net.Conn, reqLine, authHdr string)) netip.AddrPort {
	t.Helper()
	rawLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ap := unmapAddrPort(rawLn.Addr().(*net.TCPAddr).AddrPort())
	ln := rawLn
	if tlsCfg != nil {
		ln = tls.NewListener(rawLn, tlsCfg)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				var hdr bytes.Buffer
				var one [1]byte
				for hdr.Len() < 32768 {
					if _, err := conn.Read(one[:]); err != nil {
						return
					}
					hdr.WriteByte(one[0])
					if bytes.HasSuffix(hdr.Bytes(), []byte("\r\n\r\n")) {
						break
					}
				}
				lines := strings.Split(hdr.String(), "\r\n")
				var auth string
				for _, l := range lines[1:] {
					if strings.HasPrefix(strings.ToLower(l), "proxy-authorization:") {
						auth = strings.TrimSpace(l[len("proxy-authorization:"):])
					}
				}
				handler(conn, lines[0], auth)
			}(c)
		}
	}()
	return ap
}

func TestHTTPAndHTTPSConnectBufferedBytesAuthAndLimits(t *testing.T) {
	echoAP := startEchoTCP(t, "tcp4", "127.0.0.1:0", nil)
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("user1:pass1"))

	httpProxyAP := startMockHTTPProxy(t, nil, func(conn net.Conn, reqLine, authHdr string) {
		if authHdr != wantAuth {
			_, _ = conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n"))
			return
		}
		if strings.Contains(reqLine, ":81 ") {
			_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
			return
		}
		up, err := net.DialTimeout("tcp4", echoAP.String(), 2*time.Second)
		if err != nil {
			_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		defer up.Close()
		// Coalesce 200 headers and early upstream banner in one write!
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\nEARLY-BANNER:"))
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(up, conn); done <- struct{}{} }()
		go func() { _, _ = io.Copy(conn, up); done <- struct{}{} }()
		<-done
	})

	// Self-signed TLS certificate for HTTPS proxy SNI verification.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "proxy.example.test"},
		DNSNames:     []string{"proxy.example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	pool := x509.NewCertPool()
	certObj, _ := x509.ParseCertificate(der)
	pool.AddCert(certObj)
	serverTLS := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
	}
	var gotSNI atomic.Value
	serverTLS.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		gotSNI.Store(chi.ServerName)
		return nil, nil
	}

	httpsProxyAP := startMockHTTPProxy(t, serverTLS, func(conn net.Conn, _, _ string) {
		up, err := net.DialTimeout("tcp4", echoAP.String(), 2*time.Second)
		if err != nil {
			_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		defer up.Close()
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(up, conn); done <- struct{}{} }()
		go func() { _, _ = io.Copy(conn, up); done <- struct{}{} }()
		<-done
	})

	oversizeProxyAP := startMockHTTPProxy(t, nil, func(conn net.Conn, _, _ string) {
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nX-Big: " + strings.Repeat("A", 20*1024) + "\r\n\r\n"))
	})

	d := NewDialer(nil, Options{
		TLSConfig: &tls.Config{RootCAs: pool},
	})
	d.SetLines([]platform.Line{
		{
			ID: "http-1",
			Proxy: &platform.ProxyLine{
				Protocol:       "http",
				Server:         httpProxyAP.String(),
				Carrier:        CarrierLocal,
				CredentialsRef: "http-cred",
			},
		},
		{
			ID: "https-1",
			Proxy: &platform.ProxyLine{
				Protocol:   "https",
				Server:     httpsProxyAP.String(),
				ServerName: "proxy.example.test",
				Carrier:    CarrierLocal,
			},
		},
		{
			ID: "http-oversize",
			Proxy: &platform.ProxyLine{
				Protocol: "http",
				Server:   oversizeProxyAP.String(),
				Carrier:  CarrierLocal,
			},
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 407 without credentials -> KindAuth (line fault).
	if _, err := d.DialTCP(ctx, "http-1", echoAP); !IsLineFault(err) {
		t.Fatalf("expected 407 to be line fault, got %v", err)
	}

	d.SetCredentials(map[string]Credentials{"http-cred": {Username: "user1", Password: "pass1"}})

	// 403 target port restriction -> KindDestination (NOT a line fault!).
	if _, err := d.DialTCP(ctx, "http-1", netip.MustParseAddrPort("127.0.0.1:81")); err == nil || IsLineFault(err) {
		t.Fatalf("expected 403 port restriction to be non-fault KindDestination, got %v", err)
	}

	// Valid HTTP CONNECT with coalesced post-header payload, followed by clean tunnel close.
	hc, err := d.DialTCP(ctx, "http-1", echoAP)
	if err != nil {
		t.Fatalf("HTTP CONNECT: %v", err)
	}
	if _, err := hc.Write([]byte("world")); err != nil {
		t.Fatalf("write HTTP tunnel: %v", err)
	}
	wantHTTP := "EARLY-BANNER:world"
	httpBuf := make([]byte, len(wantHTTP))
	if _, err := io.ReadFull(hc, httpBuf); err != nil || string(httpBuf) != wantHTTP {
		t.Fatalf("HTTP tunnel read = %q (err=%v), want %q", string(httpBuf), err, wantHTTP)
	}
	_ = hc.CloseWrite()
	rest, err := io.ReadAll(hc)
	_ = hc.Close()
	if err != nil || len(rest) != 0 {
		t.Fatalf("HTTP tunnel EOF after CloseWrite = %q (err=%v)", string(rest), err)
	}

	// UDP on HTTP proxy -> ErrUnsupportedUDP (non-fault).
	if _, err := d.OpenUDP(ctx, "http-1", false); !errors.Is(err, platform.ErrUnsupportedUDP) || IsLineFault(err) {
		t.Fatalf("HTTP OpenUDP err = %v, want ErrUnsupportedUDP non-fault", err)
	}

	// Valid HTTPS CONNECT with SNI verification and TLS CloseWrite.
	tc, err := d.DialTCP(ctx, "https-1", echoAP)
	if err != nil {
		t.Fatalf("HTTPS CONNECT: %v", err)
	}
	if gotSNI.Load() != "proxy.example.test" {
		t.Fatalf("TLS SNI = %v, want proxy.example.test", gotSNI.Load())
	}
	const wantTLS = "tls-tunnel-ok"
	if _, err := tc.Write([]byte(wantTLS)); err != nil {
		t.Fatalf("write HTTPS tunnel: %v", err)
	}
	tlsBuf := make([]byte, len(wantTLS))
	if _, err := io.ReadFull(tc, tlsBuf); err != nil || string(tlsBuf) != wantTLS {
		t.Fatalf("HTTPS tunnel read = %q (err=%v)", string(tlsBuf), err)
	}
	_ = tc.CloseWrite()
	tlsRest, err := io.ReadAll(tc)
	_ = tc.Close()
	if err != nil || len(tlsRest) != 0 {
		t.Fatalf("HTTPS tunnel EOF after CloseWrite = %q (err=%v)", string(tlsRest), err)
	}

	// >16 KiB response headers rejected cleanly with KindProtocol.
	if _, err := d.DialTCP(ctx, "http-oversize", echoAP); err == nil {
		t.Fatal("expected >16 KiB header error")
	} else {
		var pe *Error
		if !errors.As(err, &pe) || pe.Kind != KindProtocol {
			t.Fatalf("oversize header err = %v, want KindProtocol", err)
		}
	}
}

type recordingCarrierDialer struct {
	mu       sync.Mutex
	lastLine string
	lastFlow platform.FlowIdentity
	gate     chan struct{}
}

func (r *recordingCarrierDialer) DialTCP(ctx context.Context, line string, dst netip.AddrPort) (platform.TCPConn, error) {
	return r.DialFlowTCP(ctx, line, dst, platform.FlowIdentity{Destination: dst})
}

func (r *recordingCarrierDialer) DialFlowTCP(ctx context.Context, line string, dst netip.AddrPort, flow platform.FlowIdentity) (platform.TCPConn, error) {
	r.mu.Lock()
	r.lastLine = line
	r.lastFlow = flow
	gate := r.gate
	r.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return dialLocalTCP(ctx, dst)
}

func (r *recordingCarrierDialer) OpenUDP(_ context.Context, _ string, ipv6 bool) (platform.UDPConn, error) {
	return openLocalUDP(ipv6)
}

func (r *recordingCarrierDialer) OpenFlowUDP(ctx context.Context, line string, ipv6 bool, _ platform.FlowIdentity) (platform.UDPConn, error) {
	return r.OpenUDP(ctx, line, ipv6)
}

func TestCarrierRoutingLoopbackGuardCapsAndRedaction(t *testing.T) {
	echoAP := startEchoTCP(t, "tcp4", "127.0.0.1:0", nil)
	proxyAP := startMockSOCKS5(t, mockSOCKS5Options{})

	carrier := &recordingCarrierDialer{}
	d := NewDialer(carrier, Options{
		MaxHandshakes:      1,
		MaxUDPAssociations: 1,
		Resolver: func(_ context.Context, host string) ([]netip.Addr, error) {
			if host == "localhost" {
				// Simulate poisoned hosts entry pointing localhost off-loopback.
				return []netip.Addr{netip.MustParseAddr("198.51.100.9")}, nil
			}
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
	})
	d.SetLines([]platform.Line{
		{ID: "wan0"},
		{
			ID: "bad-local-ip",
			Proxy: &platform.ProxyLine{
				Protocol: "socks5",
				Server:   "198.51.100.10:1080",
				Carrier:  CarrierLocal,
			},
		},
		{
			ID: "bad-localhost-dns",
			Proxy: &platform.ProxyLine{
				Protocol: "socks5",
				Server:   "localhost:1080",
				Carrier:  CarrierLocal,
			},
		},
		{
			ID: "proxy-via-wan",
			Proxy: &platform.ProxyLine{
				Protocol: "socks5",
				Server:   proxyAP.String(),
				Carrier:  "wan0",
			},
		},
		{
			ID: "chained-proxy",
			Proxy: &platform.ProxyLine{
				Protocol: "socks5",
				Server:   proxyAP.String(),
				Carrier:  "proxy-via-wan",
			},
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. "local" carrier rejects non-loopback literal IP and non-loopback resolved localhost.
	for _, id := range []string{"bad-local-ip", "bad-localhost-dns", "chained-proxy"} {
		if _, err := d.DialTCP(ctx, id, echoAP); err == nil {
			t.Fatalf("%s: expected KindConfig rejection", id)
		} else {
			var pe *Error
			if !errors.As(err, &pe) || pe.Kind != KindConfig {
				t.Fatalf("%s: got %v, want KindConfig", id, err)
			}
		}
	}

	// 2. Carrier flow preserves Owner identity while rewriting Destination to proxy server.
	origFlow := platform.FlowIdentity{
		Owner:       platform.Owner{PID: 4242, AppID: "browser", Path: `C:\Apps\Browser.exe`},
		Source:      netip.MustParseAddrPort("100.64.0.1:50000"),
		Destination: echoAP,
	}
	c, err := d.DialFlowTCP(ctx, "proxy-via-wan", echoAP, origFlow)
	if err != nil {
		t.Fatalf("DialFlowTCP via wan0: %v", err)
	}
	_ = c.Close()
	carrier.mu.Lock()
	gotLine, gotFlow := carrier.lastLine, carrier.lastFlow
	carrier.mu.Unlock()
	if gotLine != "wan0" || gotFlow.Destination != proxyAP || gotFlow.Owner.Path != origFlow.Owner.Path || gotFlow.Owner.AppID != "browser" {
		t.Fatalf("carrier saw line=%q flow=%+v", gotLine, gotFlow)
	}

	// 3. Per-line MaxHandshakes=1 rejects a second concurrent handshake without marking line fault.
	gate := make(chan struct{})
	carrier.mu.Lock()
	carrier.gate = gate
	carrier.mu.Unlock()

	firstDone := make(chan error, 1)
	go func() {
		conn, dialErr := d.DialTCP(ctx, "proxy-via-wan", echoAP)
		if conn != nil {
			_ = conn.Close()
		}
		firstDone <- dialErr
	}()
	time.Sleep(30 * time.Millisecond)

	_, secondErr := d.DialTCP(ctx, "proxy-via-wan", echoAP)
	close(gate)
	if err := <-firstDone; err != nil {
		t.Fatalf("first handshake failed: %v", err)
	}
	var capErr *Error
	if !errors.As(secondErr, &capErr) || capErr.Kind != KindCapExceeded || IsLineFault(secondErr) {
		t.Fatalf("second concurrent handshake err = %v (IsLineFault=%v), want non-fault KindCapExceeded", secondErr, IsLineFault(secondErr))
	}

	// 4. Credentials redaction across fmt and encoding/json.
	secret := Credentials{Username: "sensitive-user", Password: "ultra-secret-password"}
	formatted := fmt.Sprintf("%s | %v | %+v | %#v", secret, secret, secret, secret)
	if strings.Contains(formatted, "sensitive-user") || strings.Contains(formatted, "ultra-secret-password") {
		t.Fatalf("Credentials leaked in fmt output: %s", formatted)
	}
	if raw, err := json.Marshal(secret); err == nil || bytes.Contains(raw, []byte("ultra-secret-password")) {
		t.Fatalf("json.Marshal(Credentials) must fail and never emit secret: raw=%q err=%v", string(raw), err)
	}
}
