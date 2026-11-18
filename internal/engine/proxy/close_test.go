package proxy

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/kekawia/net-switch/internal/engine/platform"
)

type closeOnlyTCP struct{ platform.TCPConn }

func (closeOnlyTCP) Close() error { return nil }

func TestUDPAssociationCompletionFollowsResourceRelease(t *testing.T) {
	entered := make(chan struct{})
	proceed := make(chan struct{})
	finished := make(chan struct{})
	var released atomic.Bool
	var unblock sync.Once
	c := &socks5UDPConn{
		tcp: closeOnlyTCP{}, udp: mtuStubUDP{}, done: make(chan struct{}),
		release: func() {
			close(entered)
			<-proceed
			released.Store(true)
		},
	}
	t.Cleanup(func() {
		unblock.Do(func() { close(proceed) })
		<-finished
	})
	go func() { defer close(finished); _ = c.Close() }()
	<-entered
	if !c.closed.Load() {
		t.Fatal("new operations remain admitted while closing")
	}
	select {
	case <-c.done:
		t.Fatal("cleanup completion was published before releasing the association slot")
	default:
	}
	unblock.Do(func() { close(proceed) })
	<-c.done
	if !released.Load() {
		t.Fatal("completion did not publish resource release")
	}
}
