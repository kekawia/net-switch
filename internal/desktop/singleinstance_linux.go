//go:build linux

package desktop

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// SingleInstanceLock coordinates per-UID single-instance activation on Linux.
type SingleInstanceLock struct {
	AlreadyRunning bool

	mu       sync.Mutex
	closed   bool
	lockFile *os.File
	listener *net.UnixListener
	sockPath string
	done     chan struct{}
}

// AcquireSingleInstance acquires a per-user flock + UNIX domain socket in
// $XDG_RUNTIME_DIR (verified owned by the current UID) or a 0700 temp fallback.
func AcquireSingleInstance(ctx context.Context, scope string, show bool, onShow func()) (*SingleInstanceLock, error) {
	dir, err := singleInstanceDir(scope)
	if err != nil {
		return nil, err
	}
	lockPath := filepath.Join(dir, "desktop.lock")
	sockPath := filepath.Join(dir, "desktop.sock")

	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open single-instance lock: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			if show {
				_ = notifyExistingUnix(ctx, sockPath)
			}
			return &SingleInstanceLock{AlreadyRunning: true}, nil
		}
		return nil, fmt.Errorf("lock single-instance: %w", err)
	}

	if err := os.Remove(sockPath); err != nil && !os.IsNotExist(err) {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
		return nil, fmt.Errorf("remove stale socket: %w", err)
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
		return nil, fmt.Errorf("listen single-instance socket: %w", err)
	}
	if err := os.Chmod(sockPath, 0600); err != nil {
		_ = ln.Close()
		_ = os.Remove(sockPath)
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
		return nil, err
	}

	lock := &SingleInstanceLock{
		lockFile: f,
		listener: ln,
		sockPath: sockPath,
		done:     make(chan struct{}),
	}
	go lock.serve(onShow)
	return lock, nil
}

func singleInstanceDir(scope string) (string, error) {
	uid := uint32(os.Getuid())
	sub := "netswitch"
	if scope != "" {
		sub = "netswitch-" + scope
	}
	var base string
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" && filepath.IsAbs(xdg) {
		if info, err := os.Lstat(xdg); err == nil && info.IsDir() {
			if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid == uid {
				base = filepath.Join(xdg, sub)
			}
		}
	}
	if base == "" {
		base = filepath.Join(os.TempDir(), fmt.Sprintf("%s-%d", sub, uid))
	}
	if err := os.MkdirAll(base, 0700); err != nil {
		return "", err
	}
	info, err := os.Lstat(base)
	if err != nil {
		return "", err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || st.Uid != uid {
		return "", errors.New("single-instance directory is not owned by the current user")
	}
	_ = os.Chmod(base, 0700)
	return base, nil
}

func notifyExistingUnix(ctx context.Context, sockPath string) error {
	deadline := time.Now().Add(2 * time.Second)
	for {
		var d net.Dialer
		conn, err := d.DialContext(ctx, "unix", sockPath)
		if err == nil {
			_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
			_, _ = conn.Write([]byte("show\n"))
			_ = conn.Close()
			return nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (l *SingleInstanceLock) serve(onShow func()) {
	defer close(l.done)
	uid := uint32(os.Getuid())
	for {
		conn, err := l.listener.AcceptUnix()
		if err != nil {
			l.mu.Lock()
			closed := l.closed
			l.mu.Unlock()
			if closed {
				return
			}
			return
		}
		go func(c *net.UnixConn) {
			defer c.Close()
			raw, err := c.SyscallConn()
			if err != nil {
				return
			}
			var cred *unix.Ucred
			var inner error
			if err := raw.Control(func(fd uintptr) {
				cred, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
			}); err != nil || inner != nil || cred == nil || cred.Uid != uid {
				return
			}
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			line, _ := bufio.NewReaderSize(c, 64).ReadString('\n')
			if strings.TrimSpace(line) == "show" && onShow != nil {
				onShow()
			}
		}(conn)
	}
}

// Close releases the UNIX socket and flock.
func (l *SingleInstanceLock) Close() error {
	if l == nil || l.AlreadyRunning {
		return nil
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	ln := l.listener
	f := l.lockFile
	sock := l.sockPath
	l.listener = nil
	l.lockFile = nil
	l.mu.Unlock()

	if ln != nil {
		_ = ln.Close()
	}
	if l.done != nil {
		<-l.done
	}
	if sock != "" {
		_ = os.Remove(sock)
	}
	if f != nil {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}
	return nil
}
