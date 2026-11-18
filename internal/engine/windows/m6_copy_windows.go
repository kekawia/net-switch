//go:build windows

package winengine

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/kekawia/net-switch/internal/engine/platform"
)

// A disposable, low-concurrency control for separating the native socket
// implementation from the shared relay on the installed traffic path.
var m6SocketTrial string
var m6ActiveCopies atomic.Int32
var m6StartedCopies atomic.Uint64

type limitedCopy struct {
	platform.TCPConn
	once sync.Once
	err  error
}

func limitCopy(c platform.TCPConn, err error) (platform.TCPConn, error) {
	if err != nil {
		return nil, err
	}
	if m6ActiveCopies.Add(1) > 16 {
		m6ActiveCopies.Add(-1)
		c.Close()
		return nil, errors.New("diagnostic copy concurrency exceeded")
	}
	m6StartedCopies.Add(1)
	return &limitedCopy{TCPConn: c}, nil
}

func (c *limitedCopy) Close() error {
	c.once.Do(func() { c.err = c.TCPConn.Close(); m6ActiveCopies.Add(-1) })
	return c.err
}

type blockingNative struct {
	platform.TCPConn
	socket           *readySocket
	watch            platform.Readiness
	mu               sync.Mutex
	reading, writing bool
	in, out, stop    chan struct{}
	once             sync.Once
	err              error
}

func nativeCopySocket(c *readySocket) (platform.TCPConn, error) {
	b := &blockingNative{TCPConn: c, socket: c, in: make(chan struct{}, 1), out: make(chan struct{}, 1), stop: make(chan struct{})}
	w, err := c.Watch(func() {
		select {
		case b.in <- struct{}{}:
		default:
		}
		select {
		case b.out <- struct{}{}:
		default:
		}
	})
	if err != nil {
		c.Close()
		return nil, err
	}
	b.watch = w
	return b, nil
}

func (b *blockingNative) wait(read bool) error {
	b.mu.Lock()
	event := b.out
	if read {
		b.reading = true
		event = b.in
	} else {
		b.writing = true
	}
	err := b.watch.Arm(b.reading, b.writing)
	b.mu.Unlock()
	if err == nil {
		select {
		case <-event:
		case <-b.stop:
			err = net.ErrClosed
		}
	}
	b.mu.Lock()
	if read {
		b.reading = false
	} else {
		b.writing = false
	}
	b.mu.Unlock()
	return err
}

func (b *blockingNative) Read(dst []byte) (int, error) {
	for {
		n, err := b.socket.TryRead(dst)
		if n != 0 || !errors.Is(err, platform.ErrWouldBlock) {
			return n, err
		}
		if err = b.wait(true); err != nil {
			return 0, err
		}
	}
}

func (b *blockingNative) Write(src []byte) (int, error) {
	total := 0
	for total < len(src) {
		n, err := b.socket.TryWrite(src[total:])
		total += n
		if n == 0 && err == nil {
			return total, io.ErrNoProgress
		}
		if errors.Is(err, platform.ErrWouldBlock) {
			err = b.wait(false)
		}
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func (b *blockingNative) Close() error {
	b.once.Do(func() { close(b.stop); b.err = b.socket.Close() })
	return b.err
}
