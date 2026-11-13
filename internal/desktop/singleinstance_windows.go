//go:build windows

package desktop

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modUser32Si               = windows.NewLazySystemDLL("user32.dll")
	modKernel32Si             = windows.NewLazySystemDLL("kernel32.dll")
	procAllowSetForeground    = modUser32Si.NewProc("AllowSetForegroundWindow")
	procGetNamedPipeServerPID = modKernel32Si.NewProc("GetNamedPipeServerProcessId")
)

// SingleInstanceLock coordinates per-user single-instance activation.
type SingleInstanceLock struct {
	AlreadyRunning bool

	mu     sync.Mutex
	closed bool
	mutex  windows.Handle
	pipe   windows.Handle
	done   chan struct{}
}

// AcquireSingleInstance creates or connects to a per-SID local single-instance
// endpoint. When an instance for the current user is already active and show
// is true, it passes foreground permission and sends a "show" request.
// scope should be "" in production (or a unique suffix in unit tests).
func AcquireSingleInstance(ctx context.Context, scope string, show bool, onShow func()) (*SingleInstanceLock, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("lookup current user SID: %w", err)
	}
	sid := u.User.Sid.String()
	key := "NetSwitch-Desktop-" + sid
	if scope != "" {
		key += "-" + scope
	}
	mutexName := `Local\` + key
	pipeName := `\\.\pipe\` + key

	sddl := "D:P(A;;GA;;;" + sid + ")S:(ML;;NRNW;;;ME)"
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}

	mPtr, err := windows.UTF16PtrFromString(mutexName)
	if err != nil {
		return nil, err
	}
	hMutex, createErr := windows.CreateMutex(&sa, false, mPtr)
	if hMutex == 0 {
		return nil, fmt.Errorf("create single-instance mutex: %w", createErr)
	}
	if errors.Is(createErr, windows.ERROR_ALREADY_EXISTS) {
		_ = windows.CloseHandle(hMutex)
		if show {
			_ = notifyExistingInstance(ctx, pipeName)
		}
		return &SingleInstanceLock{AlreadyRunning: true}, nil
	}

	pPipe, err := windows.UTF16PtrFromString(pipeName)
	if err != nil {
		_ = windows.CloseHandle(hMutex)
		return nil, err
	}
	flags := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED | windows.FILE_FLAG_FIRST_PIPE_INSTANCE)
	mode := uint32(windows.PIPE_TYPE_BYTE | windows.PIPE_READMODE_BYTE | windows.PIPE_WAIT | windows.PIPE_REJECT_REMOTE_CLIENTS)
	hPipe, err := windows.CreateNamedPipe(pPipe, flags, mode, 1, 1024, 1024, 0, &sa)
	if err != nil {
		_ = windows.CloseHandle(hMutex)
		return nil, fmt.Errorf("create single-instance pipe: %w", err)
	}

	lock := &SingleInstanceLock{
		mutex: hMutex,
		pipe:  hPipe,
		done:  make(chan struct{}),
	}
	go lock.serve(onShow)
	return lock, nil
}

func notifyExistingInstance(ctx context.Context, pipeName string) error {
	p, err := windows.UTF16PtrFromString(pipeName)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		h, err := windows.CreateFile(p, windows.GENERIC_WRITE|windows.FILE_READ_ATTRIBUTES, 0, nil, windows.OPEN_EXISTING, 0, 0)
		if err == nil {
			var pid uint32
			r1, _, _ := procGetNamedPipeServerPID.Call(uintptr(h), uintptr(unsafe.Pointer(&pid)))
			if r1 != 0 && pid != 0 {
				_, _, _ = procAllowSetForeground.Call(uintptr(pid))
			}
			var written uint32
			msg := []byte("show\n")
			_ = windows.WriteFile(h, msg, &written, nil)
			_ = windows.CloseHandle(h)
			return nil
		}
		if time.Now().After(deadline) {
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
	for {
		l.mu.Lock()
		closed := l.closed
		h := l.pipe
		l.mu.Unlock()
		if closed || h == 0 {
			return
		}

		ev, err := windows.CreateEvent(nil, 1, 0, nil)
		if err != nil {
			return
		}
		over := &windows.Overlapped{HEvent: ev}
		var pinner runtime.Pinner
		pinner.Pin(over)

		err = windows.ConnectNamedPipe(h, over)
		if err == windows.ERROR_IO_PENDING {
			var ignored uint32
			err = windows.GetOverlappedResult(h, over, &ignored, true)
		}
		pinner.Unpin()
		_ = windows.CloseHandle(ev)

		if err == windows.ERROR_OPERATION_ABORTED {
			return
		}
		if err != nil && err != windows.ERROR_PIPE_CONNECTED {
			return
		}

		var pid uint32
		if err := windows.GetNamedPipeClientProcessId(h, &pid); err == nil {
			// Pipe DACL restricts clients to our own SID; read line bounded.
			buf := make([]byte, 64)
			var n uint32
			overRead := &windows.Overlapped{}
			evRead, evErr := windows.CreateEvent(nil, 1, 0, nil)
			if evErr == nil {
				overRead.HEvent = evRead
				var rp runtime.Pinner
				rp.Pin(&buf[0])
				rp.Pin(overRead)
				rErr := windows.ReadFile(h, buf, &n, overRead)
				if rErr == windows.ERROR_IO_PENDING {
					rErr = windows.GetOverlappedResult(h, overRead, &n, true)
				}
				rp.Unpin()
				_ = windows.CloseHandle(evRead)
				if rErr == nil || errors.Is(rErr, io.EOF) || rErr == windows.ERROR_BROKEN_PIPE {
					line, _ := bufio.NewReader(strings.NewReader(string(buf[:n]))).ReadString('\n')
					if strings.TrimSpace(line) == "show" && onShow != nil {
						onShow()
					}
				}
			}
		}
		_ = windows.DisconnectNamedPipe(h)
	}
}

// Close stops accepting activation requests and releases the mutex and pipe.
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
	hPipe := l.pipe
	hMutex := l.mutex
	l.pipe = 0
	l.mutex = 0
	l.mu.Unlock()

	if hPipe != 0 {
		_ = windows.CancelIoEx(hPipe, nil)
		_ = windows.CloseHandle(hPipe)
	}
	if l.done != nil {
		<-l.done
	}
	if hMutex != 0 {
		_ = windows.CloseHandle(hMutex)
	}
	return nil
}
