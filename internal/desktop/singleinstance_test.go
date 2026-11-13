package desktop

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func TestSingleInstanceActivationAndShutdown(t *testing.T) {
	scope := fmt.Sprintf("test-%d", time.Now().UnixNano())
	var woken atomic.Int32
	wakeCh := make(chan struct{}, 2)

	first, err := AcquireSingleInstance(context.Background(), scope, false, func() {
		woken.Add(1)
		select {
		case wakeCh <- struct{}{}:
		default:
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if first.AlreadyRunning {
		t.Fatal("first lock reported AlreadyRunning")
	}

	second, err := AcquireSingleInstance(context.Background(), scope, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if !second.AlreadyRunning {
		t.Fatal("second lock did not detect existing instance")
	}

	select {
	case <-wakeCh:
	case <-time.After(3 * time.Second):
		t.Fatal("existing instance was not woken by second --show")
	}
	if woken.Load() != 1 {
		t.Fatalf("unexpected wake count: %d", woken.Load())
	}

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := AcquireSingleInstance(context.Background(), scope, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	if third.AlreadyRunning {
		t.Fatal("instance lock was not released on Close")
	}
}
