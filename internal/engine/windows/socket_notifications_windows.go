//go:build windows

package winengine

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/kekawia/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

// The completion key is an integer registration ID. Socket notification
// entries reserve the overlapped field; it must never be treated as a pointer.
type stateEntry struct {
	key, reserved, internal uintptr
	events                  uint32
}

type stateRegistration struct {
	socket             windows.Handle
	key                uintptr
	filter             uint16
	operation, trigger uint8
	result             uint32
}

const (
	stateInput   = 0x01
	stateOutput  = 0x02
	stateHangup  = 0x04
	stateError   = 0x40
	stateRemoved = 0x80
)

var stateProc = winsock.NewProc("ProcessSocketNotifications")
var socketStateMode string

type stateQueue struct {
	port                     winhandle.Owner
	mu                       sync.Mutex
	next                     uintptr
	watches                  map[uintptr]*stateWatch
	wg                       sync.WaitGroup
	registrations, fallbacks atomic.Uint64
}

type stateWatch struct {
	queue     *stateQueue
	socket    *socketWatch
	key       uintptr
	wake      func()
	mu        sync.Mutex
	interest  uint32
	removing  bool
	removed   chan struct{}
	removeErr error
}

func newStateQueue() (*stateQueue, error) {
	if err := stateProc.Find(); err != nil {
		return nil, err
	}
	h, err := windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 1)
	if err != nil {
		return nil, err
	}
	q := &stateQueue{port: winhandle.Open(h, "TCP state notification port"), watches: make(map[uintptr]*stateWatch)}
	q.wg.Go(q.run)
	return q, nil
}

func (w *stateWatch) update(op uint8) error {
	r := stateRegistration{socket: w.socket.socket.Handle("TCP socket state registration"), key: w.key, operation: op}
	if op == 1 {
		r.filter = stateInput | stateOutput | stateHangup
		r.trigger = 0x02 | 0x08 // persistent, edge-triggered
	}
	rc, _, _ := stateProc.Call(uintptr(w.queue.port.Handle("TCP socket state update")), 1, uintptr(unsafe.Pointer(&r)), 0, 0, 0, 0)
	if rc != 0 {
		return windows.Errno(rc)
	}
	if r.result != 0 {
		return windows.Errno(r.result)
	}
	return nil
}

func (q *stateQueue) watch(s *socketWatch, wake func()) (*stateWatch, error) {
	q.mu.Lock()
	q.next++
	w := &stateWatch{queue: q, socket: s, key: q.next, wake: wake}
	q.watches[w.key] = w
	q.mu.Unlock()
	if err := w.update(1); err != nil {
		q.mu.Lock()
		delete(q.watches, w.key)
		q.mu.Unlock()
		q.fallbacks.Add(1)
		return nil, err
	}
	q.registrations.Add(1)
	return w, nil
}

func (q *stateQueue) run() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var entries [64]stateEntry
	for {
		var n uint32
		rc, _, _ := stateProc.Call(uintptr(q.port.Handle("TCP socket state wait")), 0, 0, windows.INFINITE, uintptr(len(entries)), uintptr(unsafe.Pointer(&entries[0])), uintptr(unsafe.Pointer(&n)))
		if rc != 0 {
			panic(fmt.Errorf("TCP socket state wait: %w", windows.Errno(rc)))
		}
		for _, e := range entries[:n] {
			if e.key == 0 {
				return
			}
			q.mu.Lock()
			w := q.watches[e.key]
			q.mu.Unlock()
			if w == nil {
				panic("socket state event after registration removal")
			}
			w.deliver(e.events)
		}
	}
}

func (w *stateWatch) deliver(mask uint32) {
	w.mu.Lock()
	if mask&stateRemoved != 0 {
		if !w.removing || w.removed == nil {
			panic("unexpected socket notification removal")
		}
		w.queue.mu.Lock()
		delete(w.queue.watches, w.key)
		w.queue.mu.Unlock()
		close(w.removed)
		w.mu.Unlock()
		return
	}
	interest := w.interest
	ready := !w.removing && interest != 0 && mask&(interest|stateHangup|stateError) != 0
	w.mu.Unlock()
	if ready {
		w.signal(mask&interest, mask&(stateHangup|stateError) != 0)
	}
}

func (w *stateWatch) signal(events uint32, terminal bool) {
	if socketStateMode == "state-bulk" && !terminal && events == stateInput {
		w.socket.readable(w.wake)
	} else {
		w.wake()
	}
}

// The subscription records transitions continuously. An immediate poll after
// replacing interest supplies the level check for data or EOF already present.
func (w *stateWatch) Arm(read, write bool) error {
	w.mu.Lock()
	if w.removing {
		w.mu.Unlock()
		return net.ErrClosed
	}
	var events int16
	w.interest = 0
	if read {
		events |= 0x100
		w.interest |= stateInput
	}
	if write {
		events |= pollWrNorm
		w.interest |= stateOutput
	}
	if events == 0 {
		w.mu.Unlock()
		return nil
	}
	row := pollFD{Socket: w.socket.socket.Handle("TCP state level check"), Events: events}
	rc, _, err := relayPoll.Call(uintptr(unsafe.Pointer(&row)), 1, 0)
	w.mu.Unlock()
	if int32(rc) < 0 {
		return err
	}
	if row.Returned != 0 {
		var mask uint32
		if row.Returned&0x100 != 0 {
			mask |= stateInput
		}
		if row.Returned&pollWrNorm != 0 {
			mask |= stateOutput
		}
		w.signal(mask, row.Returned & ^events != 0)
	}
	return nil
}

func (w *stateWatch) Detach() {
	w.mu.Lock()
	if !w.removing {
		w.removing = true
		w.removed = make(chan struct{})
		w.removeErr = w.update(4)
	}
	done, err := w.removed, w.removeErr
	w.mu.Unlock()
	if err != nil {
		panic(fmt.Errorf("TCP socket state removal: %w", err))
	}
	<-done
}

func (q *stateQueue) close() error {
	q.mu.Lock()
	busy := len(q.watches) != 0
	q.mu.Unlock()
	if busy {
		return errors.New("TCP state notification port still has registrations")
	}
	if err := windows.PostQueuedCompletionStatus(q.port.Handle("stop TCP socket state wait"), 0, 0, nil); err != nil {
		return err
	}
	q.wg.Wait()
	return q.port.HandleClose("close TCP socket state port")
}
