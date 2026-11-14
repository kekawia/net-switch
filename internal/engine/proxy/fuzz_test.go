package proxy

import (
	"bytes"
	"net/netip"
	"testing"
)

func FuzzSOCKS5Reply(f *testing.F) {
	f.Add([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38})
	f.Add([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0x05, 0x00, 0x00, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x04, 0x38})
	f.Add([]byte{0x05, 0x00, 0x00, 0x03, 9, '1', '2', '7', '.', '0', '.', '0', '.', '1', 0x04, 0x38})
	f.Add([]byte{0x04, 0x5a, 0x00, 0x50})

	f.Fuzz(func(t *testing.T, data []byte) {
		rep, addr, port, err := socks5ReadReply(bytes.NewReader(data))
		if err == nil {
			_ = classifySOCKS5Rep(rep)
			_ = resolveRelayAddr(addr, netip.MustParseAddr("198.51.100.1"))
			_ = port
		}
	})
}

func FuzzSOCKS5UDP(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0x00, 0x01, 1, 1, 1, 1, 0x00, 0x35, 'd', 'n', 's'})
	f.Add([]byte{0x00, 0x00, 0x01, 0x01, 1, 1, 1, 1, 0x00, 0x35, 'f', 'r', 'a', 'g'})
	f.Add([]byte{0x00, 0x00, 0x00, 0x04, 0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11, 0x01, 0xbb, 'q'})

	f.Fuzz(func(t *testing.T, frame []byte) {
		origin, payload, err := DecodeSOCKS5UDP(frame)
		if err != nil {
			return
		}
		if !origin.IsValid() {
			t.Fatalf("DecodeSOCKS5UDP returned invalid AddrPort without error")
		}
		buf := make([]byte, len(payload)+SOCKS5UDPv6HeaderLen)
		n, _, encErr := EncodeSOCKS5UDP(buf, origin, payload)
		if encErr != nil {
			t.Fatalf("re-encode failed: %v", encErr)
		}
		rtOrigin, rtPayload, decErr := DecodeSOCKS5UDP(buf[:n])
		if decErr != nil {
			t.Fatalf("round-trip decode failed: %v", decErr)
		}
		if rtOrigin != unmapAddrPort(origin) || !bytes.Equal(rtPayload, payload) {
			t.Fatalf("round-trip mismatch: got (%v, %x), want (%v, %x)", rtOrigin, rtPayload, origin, payload)
		}
	})
}

func FuzzHTTPConnectReply(f *testing.F) {
	f.Add([]byte("HTTP/1.1 200 Connection Established\r\n\r\nhello"))
	f.Add([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n"))
	f.Add([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
	f.Add([]byte("NOT-HTTP\r\n\r\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ReadHTTPConnectReply(bytes.NewReader(data), "http", "1.1.1.1:443")
	})
}
