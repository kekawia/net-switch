package desktop

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestSingleInstanceEarlyClientClose(t *testing.T) {
	for _, initialShow := range []bool{true, false} {
		t.Run(fmt.Sprintf("show=%t", initialShow), func(t *testing.T) {
			name := fmt.Sprintf(`\\.\pipe\NetSwitch-activation-proof-%d-%d`, os.Getpid(), time.Now().UnixNano())
			encoded, err := windows.UTF16PtrFromString(name)
			if err != nil {
				t.Fatal(err)
			}
			pipe, err := windows.CreateNamedPipe(encoded,
				windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
				windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
				1, 1024, 1024, 0, nil)
			if err != nil {
				t.Fatal(err)
			}
			stop, err := windows.CreateEvent(nil, 1, 0, nil)
			if err != nil {
				windows.CloseHandle(pipe)
				t.Fatal(err)
			}
			lock := &SingleInstanceLock{pipe: pipe, stop: stop, done: make(chan struct{})}
			started := false
			t.Cleanup(func() {
				if !started {
					close(lock.done)
				}
				if err := lock.Close(); err != nil {
					t.Error(err)
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			// Deliberately finish the client before starting the real server
			// loop. This recreates the observed scheduling window without sleeps.
			if initialShow {
				if err := notifyExistingInstance(ctx, name); err != nil {
					t.Fatal(err)
				}
			} else {
				client, err := windows.CreateFile(encoded, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
				if err != nil {
					t.Fatal(err)
				}
				windows.CloseHandle(client)
			}
			shown := make(chan struct{}, 1)
			started = true
			go lock.serve(pipe, stop, func() { shown <- struct{}{} })
			if !initialShow {
				if err := notifyExistingInstance(ctx, name); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-shown:
			case <-lock.done:
				t.Fatal("activation listener stopped after an early client close")
			case <-ctx.Done():
				t.Fatal("activation sent before accept was lost")
			}
		})
	}
}
