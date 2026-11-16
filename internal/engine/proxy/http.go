package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/kekawia/net-switch/internal/engine/platform"
)

const maxConnectResponseBytes = 16 * 1024

var errHeaderTooLarge = errors.New("HTTP CONNECT response exceeded 16 KiB limit")

type boundedReader struct {
	r         io.Reader
	remaining int
	capped    bool
}

func (b *boundedReader) Read(p []byte) (int, error) {
	if !b.capped {
		return b.r.Read(p)
	}
	if b.remaining <= 0 {
		return 0, errHeaderTooLarge
	}
	if len(p) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.r.Read(p)
	b.remaining -= n
	return n, err
}

// httpTunnelConn wraps the established HTTP/HTTPS CONNECT stream and drains any
// server bytes already buffered past the response headers before reading from
// the underlying connection directly.
type httpTunnelConn struct {
	net.Conn
	raw      platform.TCPConn
	tlsConn  *tls.Conn
	buffered []byte
}

func (c *httpTunnelConn) Read(p []byte) (int, error) {
	if len(c.buffered) > 0 {
		n := copy(p, c.buffered)
		c.buffered = c.buffered[n:]
		if len(c.buffered) == 0 {
			c.buffered = nil
		}
		return n, nil
	}
	return c.Conn.Read(p)
}

func (c *httpTunnelConn) CloseRead() error {
	return c.raw.CloseRead()
}

func (c *httpTunnelConn) CloseWrite() error {
	if c.tlsConn != nil {
		return c.tlsConn.CloseWrite()
	}
	return c.raw.CloseWrite()
}

func (c *httpTunnelConn) SetLinger(sec int) error {
	return c.raw.SetLinger(sec)
}

func (c *httpTunnelConn) WaitReadable(ctx context.Context) error {
	if len(c.buffered) > 0 || c.tlsConn != nil {
		return nil
	}
	if ready, ok := c.raw.(interface{ WaitReadable(context.Context) error }); ok {
		return ready.WaitReadable(ctx)
	}
	return nil
}

func dialHTTPConnect(ctx context.Context, raw platform.TCPConn, useTLS bool, tlsConfig *tls.Config, serverName string, dst netip.AddrPort, creds Credentials) (platform.TCPConn, error) {
	var stream net.Conn = raw
	var tlsConn *tls.Conn
	proto := "http"
	if useTLS {
		proto = "https"
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if tlsConfig != nil {
			cfg = tlsConfig.Clone()
			if cfg.MinVersion < tls.VersionTLS12 {
				cfg.MinVersion = tls.VersionTLS12
			}
		}
		if cfg.ServerName == "" {
			cfg.ServerName = serverName
		}
		if cfg.ServerName == "" && !cfg.InsecureSkipVerify {
			raw.Close()
			return nil, &Error{Kind: KindConfig, Protocol: proto, Detail: "HTTPS proxy requires a server hostname or IP"}
		}
		tlsConn = tls.Client(raw, cfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, &Error{Kind: KindUnreachable, Protocol: proto, Detail: "TLS handshake failed", Cause: err}
		}
		stream = tlsConn
	}

	stop := abortConnOnCancel(ctx, stream)

	authority := unmapAddrPort(dst).String()
	reqWire, err := buildHTTPConnectRequest(authority, creds)
	if err != nil {
		stop()
		stream.Close()
		return nil, err
	}
	if _, err := stream.Write(reqWire); err != nil {
		stop()
		stream.Close()
		return nil, &Error{Kind: KindUnreachable, Protocol: proto, Detail: "write CONNECT", Cause: err}
	}

	extra, err := ReadHTTPConnectReply(stream, proto, authority)
	if err != nil {
		stop()
		stream.Close()
		return nil, err
	}
	if !stop() {
		stream.Close()
		return nil, &Error{Kind: KindUnreachable, Protocol: proto, Detail: "handshake canceled", Cause: ctx.Err()}
	}
	_ = stream.SetDeadline(time.Time{})
	return &httpTunnelConn{
		Conn:     stream,
		raw:      raw,
		tlsConn:  tlsConn,
		buffered: extra,
	}, nil
}

func buildHTTPConnectRequest(authority string, creds Credentials) ([]byte, error) {
	if strings.ContainsAny(authority, "\r\n ") {
		return nil, &Error{Kind: KindConfig, Protocol: "http", Detail: "invalid CONNECT authority"}
	}
	var b strings.Builder
	b.Grow(128)
	b.WriteString("CONNECT ")
	b.WriteString(authority)
	b.WriteString(" HTTP/1.1\r\nHost: ")
	b.WriteString(authority)
	b.WriteString("\r\n")
	if !creds.Empty() {
		if strings.ContainsRune(creds.Username, ':') {
			return nil, &Error{Kind: KindConfig, Protocol: "http", Detail: "HTTP Basic username cannot contain ':'"}
		}
		token := base64.StdEncoding.EncodeToString([]byte(creds.Username + ":" + creds.Password))
		b.WriteString("Proxy-Authorization: Basic ")
		b.WriteString(token)
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	return []byte(b.String()), nil
}

// ReadHTTPConnectReply parses an HTTP CONNECT response under a strict 16 KiB
// bound and returns any tunnel payload bytes already buffered after the headers.
func ReadHTTPConnectReply(r io.Reader, proto, authority string) ([]byte, error) {
	lim := &boundedReader{r: r, remaining: maxConnectResponseBytes, capped: true}
	br := bufio.NewReaderSize(lim, 4096)
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: authority},
		Host:   authority,
	}
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		if errors.Is(err, errHeaderTooLarge) {
			return nil, &Error{Kind: KindProtocol, Protocol: proto, Detail: errHeaderTooLarge.Error(), Cause: err}
		}
		return nil, &Error{Kind: KindProtocol, Protocol: proto, Detail: "invalid CONNECT response", Cause: err}
	}
	_ = resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		lim.capped = false
		var extra []byte
		if n := br.Buffered(); n > 0 {
			extra = make([]byte, n)
			_, _ = io.ReadFull(br, extra)
		}
		return extra, nil
	}
	return nil, classifyHTTPStatus(proto, resp.StatusCode, resp.Status)
}

func classifyHTTPStatus(proto string, code int, status string) error {
	switch code {
	case http.StatusProxyAuthRequired:
		return &Error{Kind: KindAuth, Protocol: proto, Code: code, Detail: "proxy authentication required (407)"}
	case http.StatusBadGateway, http.StatusGatewayTimeout:
		return &Error{Kind: KindDestination, Protocol: proto, Code: code, Detail: fmt.Sprintf("destination unreachable via proxy (%s)", status)}
	case http.StatusForbidden:
		// RFC 9110 section 9.3.6: HTTP proxies commonly restrict CONNECT to
		// allowed destination ports (e.g. Squid allowing 443 only).
		return &Error{Kind: KindDestination, Protocol: proto, Code: code, Detail: fmt.Sprintf("proxy refused target port or destination (%s)", status)}
	default:
		return &Error{Kind: KindProxyRejected, Protocol: proto, Code: code, Detail: fmt.Sprintf("CONNECT rejected (%s)", status)}
	}
}
