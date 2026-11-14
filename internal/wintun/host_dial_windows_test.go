//go:build windows

package wintun

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/winclock"
	"golang.org/x/sys/windows"
)

// Windows' automatic port choice (bind to port 0, or deferred ConnectEx) can
// refuse with WSAENOBUFS or WSAEADDRINUSE while dynamic ports are free
// (SYSTEM-DESIGN 5.9), such as when concurrent host streams cross the RFC 6056
// 65535 -> 49152 wrap-around on a freshly created test adapter. Match the
// engine's bounded fresh-socket retry and log every retry via report(t, ...) so
// host-side retries are never silent.
const (
	hostPortFreshAttempts = 4
	hostPortFreshWindow   = 10 * time.Millisecond
)

func hostPortRefusal(err error) bool {
	return errors.Is(err, windows.WSAENOBUFS) || errors.Is(err, windows.WSAEADDRINUSE)
}

func retryHostOpen[T any](now func() time.Duration, attempt func() (T, error)) (result T, attempts int, firstErr error, err error) {
	result, err = attempt()
	attempts = 1
	if err == nil || !hostPortRefusal(err) {
		return result, attempts, nil, err
	}
	if now == nil {
		now = winclock.Now
	}
	firstErr = err
	refused := now()
	for range hostPortFreshAttempts {
		if now()-refused >= hostPortFreshWindow {
			break
		}
		attempts++
		if result, err = attempt(); err == nil || !hostPortRefusal(err) {
			return result, attempts, firstErr, err
		}
	}
	return result, attempts, firstErr, err
}

func dialHostTCP4(t *testing.T) (net.Conn, error) {
	t.Helper()
	const (
		localIP = "198.19.240.1"
		remote  = "198.19.240.2:9002"
	)
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(localIP)}, Timeout: 5 * time.Second}
	c, attempts, firstErr, err := retryHostOpen(winclock.Now, func() (net.Conn, error) {
		return d.Dial("tcp4", remote)
	})
	if attempts > 1 {
		report(t, map[string]any{
			"test":        "host_port_retry",
			"network":     "tcp4",
			"local":       localIP + ":0",
			"remote":      remote,
			"attempts":    attempts,
			"recovered":   err == nil,
			"first_error": firstErr.Error(),
		})
	}
	return c, err
}

func dialHostUDP(t *testing.T, network string, local, remote *net.UDPAddr) (*net.UDPConn, error) {
	t.Helper()
	c, attempts, firstErr, err := retryHostOpen(winclock.Now, func() (*net.UDPConn, error) {
		return net.DialUDP(network, local, remote)
	})
	if attempts > 1 {
		report(t, map[string]any{
			"test":        "host_port_retry",
			"network":     network,
			"local":       local.String(),
			"remote":      remote.String(),
			"attempts":    attempts,
			"recovered":   err == nil,
			"first_error": firstErr.Error(),
		})
	}
	return c, err
}

func TestHostPortRetriesAreBoundedAndLogged(t *testing.T) {
	local := &net.TCPAddr{IP: net.ParseIP("198.19.240.1")}
	remote := &net.TCPAddr{IP: net.ParseIP("198.19.240.2"), Port: 9002}
	bindNoBufs := &net.OpError{Op: "dial", Net: "tcp4", Source: local, Addr: remote, Err: os.NewSyscallError("bind", windows.WSAENOBUFS)}
	connectInUse := &net.OpError{Op: "dial", Net: "tcp4", Source: local, Addr: remote, Err: os.NewSyscallError("connectex", windows.WSAEADDRINUSE)}
	peerRefused := &net.OpError{Op: "dial", Net: "tcp4", Source: local, Addr: remote, Err: os.NewSyscallError("connectex", windows.WSAECONNREFUSED)}
	denied := &net.OpError{Op: "dial", Net: "tcp4", Source: local, Addr: remote, Err: os.NewSyscallError("bind", windows.WSAEACCES)}

	script := func(errs ...error) func() (int, error) {
		calls := 0
		return func() (int, error) {
			calls++
			if calls <= len(errs) {
				return 0, errs[calls-1]
			}
			return calls, nil
		}
	}

	for _, refused := range []error{bindNoBufs, connectInUse} {
		for _, tc := range []struct {
			name      string
			errs      []error
			attempts  int
			hadFirst  bool
			wantValue int
			wantErr   error
		}{
			{"first attempt succeeds", nil, 1, false, 1, nil},
			{"recovers on first fresh socket", []error{refused}, 2, true, 2, nil},
			{"recovers on second fresh socket", []error{refused, refused}, 3, true, 3, nil},
			{"stops at fresh attempt cap", []error{refused, refused, refused, refused, refused, refused}, 1 + hostPortFreshAttempts, true, 0, refused},
			{"non-port error is not retried", []error{denied}, 1, false, 0, windows.WSAEACCES},
			{"peer refusal after port retry stops immediately", []error{refused, peerRefused}, 2, true, 0, windows.WSAECONNREFUSED},
			{"cancellation after port retry stops immediately", []error{refused, context.Canceled}, 2, true, 0, context.Canceled},
		} {
			t.Run(refused.Error()+"/"+tc.name, func(t *testing.T) {
				clock := time.Second
				got, attempts, firstErr, err := retryHostOpen(func() time.Duration { return clock }, script(tc.errs...))
				if attempts != tc.attempts || got != tc.wantValue || (firstErr != nil) != tc.hadFirst {
					t.Fatalf("got=%d attempts=%d firstErr=%v, want value=%d attempts=%d hadFirst=%v", got, attempts, firstErr, tc.wantValue, tc.attempts, tc.hadFirst)
				}
				if tc.wantErr == nil && err != nil || tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
			})
		}
	}

	for _, tc := range []struct {
		name     string
		elapsed  time.Duration
		attempts int
	}{
		{"window expired", hostPortFreshWindow, 2},
		{"window expired past coarse tick", hostPortFreshWindow + 15625*time.Microsecond, 2},
		{"inside window", hostPortFreshWindow - time.Nanosecond, 1 + hostPortFreshAttempts},
	} {
		t.Run("window/"+tc.name, func(t *testing.T) {
			clock := 5 * time.Second
			calls := 0
			_, attempts, firstErr, err := retryHostOpen(func() time.Duration { return clock }, func() (int, error) {
				calls++
				if calls == 2 {
					clock += tc.elapsed
				}
				return 0, bindNoBufs
			})
			if !errors.Is(err, windows.WSAENOBUFS) || firstErr == nil || calls != tc.attempts || attempts != tc.attempts {
				t.Fatalf("calls=%d attempts=%d firstErr=%v err=%v, want attempts=%d WSAENOBUFS", calls, attempts, firstErr, err, tc.attempts)
			}
		})
	}
}
