package supervisor

import (
	"context"
	"io"
	"sync/atomic"
)

// Log never waits on a sink. One bounded sink goroutine may be blocked until
// process exit; its 64 bulk records and 64 critical records cannot hold
// supervision or terminal handling, and critical supervision milestones drain
// ahead of bulk child output.
type Log struct {
	queue      chan []byte
	critical   chan []byte
	notify     chan struct{}
	inflight   atomic.Int64
	sinkFailed atomic.Bool
	Dropped    atomic.Uint64
}

func NewLog(sink io.Writer) *Log {
	l := &Log{
		queue:    make(chan []byte, 64),
		critical: make(chan []byte, 64),
		notify:   make(chan struct{}, 1),
	}
	go func() {
		for {
			var b []byte
			select {
			case b = <-l.critical:
			default:
				select {
				case b = <-l.critical:
				case b = <-l.queue:
				}
			}
			err := Write(sink, b)
			if err != nil {
				l.sinkFailed.Store(true)
			}
			if l.inflight.Add(-1) == 0 || err != nil {
				l.signalIdle()
			}
			if err != nil {
				return
			}
		}
	}()
	return l
}

func (l *Log) signalIdle() {
	select {
	case l.notify <- struct{}{}:
	default:
	}
}

func (l *Log) enqueue(ch chan []byte, b []byte) (int, error) {
	n := len(b)
	if len(b) > 4096 {
		b = b[:4096]
	}
	if l.sinkFailed.Load() {
		l.Dropped.Add(1)
		return n, nil
	}
	cp := append([]byte(nil), b...)
	l.inflight.Add(1)
	select {
	case ch <- cp:
	default:
		if l.inflight.Add(-1) == 0 {
			l.signalIdle()
		}
		l.Dropped.Add(1)
	}
	return n, nil
}

func (l *Log) Write(b []byte) (int, error) {
	return l.enqueue(l.queue, b)
}

// WriteCritical queues a host supervision record in a dedicated bounded lane
// that drains ahead of ordinary bulk Write chunks and never blocks the caller.
func (l *Log) WriteCritical(b []byte) (int, error) {
	return l.enqueue(l.critical, b)
}

// Flush waits until queued records have been written to sink or ctx expires.
func (l *Log) Flush(ctx context.Context) bool {
	for {
		if l.inflight.Load() == 0 || l.sinkFailed.Load() {
			l.signalIdle()
			return !l.sinkFailed.Load()
		}
		select {
		case <-l.notify:
		case <-ctx.Done():
			return l.inflight.Load() == 0 && !l.sinkFailed.Load()
		}
	}
}
