// Package proxy implements pure-stdlib SOCKS5 (RFC 1928/1929) and HTTP/HTTPS
// CONNECT (RFC 9110) outbound line dialers without external dependencies.
package proxy

import (
	"context"
	"errors"
	"fmt"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

// Kind classifies a proxy dial or association failure so callers can separate
// proxy/carrier faults (which penalize line health) from destination faults.
type Kind uint8

const (
	KindUnreachable Kind = iota + 1
	KindAuth
	KindProxyRejected
	KindDestination
	KindProtocol
	KindCapExceeded
	KindConfig
)

func (k Kind) String() string {
	switch k {
	case KindUnreachable:
		return "unreachable"
	case KindAuth:
		return "auth"
	case KindProxyRejected:
		return "proxy-rejected"
	case KindDestination:
		return "destination"
	case KindProtocol:
		return "protocol"
	case KindCapExceeded:
		return "cap-exceeded"
	case KindConfig:
		return "config"
	default:
		return "unknown"
	}
}

// Error is a classified failure returned by the proxy dialer.
type Error struct {
	Kind     Kind
	Protocol string
	Code     int
	Detail   string
	Cause    error
}

func (e *Error) Error() string {
	prefix := e.Protocol
	if prefix == "" {
		prefix = "proxy"
	}
	if e.Cause != nil {
		if e.Detail != "" {
			return fmt.Sprintf("%s %s (%s): %v", prefix, e.Kind, e.Detail, e.Cause)
		}
		return fmt.Sprintf("%s %s: %v", prefix, e.Kind, e.Cause)
	}
	if e.Detail != "" {
		return fmt.Sprintf("%s %s: %s", prefix, e.Kind, e.Detail)
	}
	return fmt.Sprintf("%s %s", prefix, e.Kind)
}

func (e *Error) Unwrap() error { return e.Cause }

// LineFault reports whether this error indicates a problem with the proxy line
// or its carrier (rather than the remote destination refusing/timing out or a
// local concurrency cap).
func (e *Error) LineFault() bool {
	switch e.Kind {
	case KindDestination, KindCapExceeded:
		return false
	default:
		return true
	}
}

// IsLineFault reports whether err should be recorded as a line health error.
// Non-proxy errors preserve the engine's existing behavior (true unless nil,
// canceled, or unsupported UDP).
func IsLineFault(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, platform.ErrUnsupportedUDP) {
		return false
	}
	var pe *Error
	if errors.As(err, &pe) {
		return pe.LineFault()
	}
	return true
}

// Credentials holds a proxy username and password in memory only. Formatting
// and JSON marshaling are deliberately blocked/redacted so secrets cannot leak
// into logs, journals, or API responses.
type Credentials struct {
	Username string
	Password string
}

func (c Credentials) Empty() bool {
	return c.Username == "" && c.Password == ""
}

func (Credentials) String() string   { return "[redacted]" }
func (Credentials) GoString() string { return "proxy.Credentials{[redacted]}" }

func (Credentials) MarshalJSON() ([]byte, error) {
	return nil, errors.New("proxy.Credentials must never be marshaled to JSON")
}
