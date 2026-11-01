package lifecycle

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/service"
)

func TestReservedConnectionsRemainAvailableDuringAttack(t *testing.T) {
	l := &connectionLimits{owner: "owner", users: map[string]int{}}
	for i := range 8 {
		user := string(rune('a' + i))
		if !l.take(user) || !l.take(user) || l.take(user) {
			t.Fatal("per-user cap", user)
		}
	}
	if l.take("another-attacker") {
		t.Fatal("public capacity not bounded")
	}
	for _, user := range []string{"owner", "0", "S-1-5-18"} {
		if !l.take(user) {
			t.Fatal("attacker held the reserved slot", user)
		}
	}
}

func TestOwnerLogoffAndHybridResumeWaitForSignIn(t *testing.T) {
	for _, test := range []struct {
		event   service.Event
		present bool
	}{
		{service.Event{Logoff: true, Session: 7}, false},
		{service.Event{Resume: true}, false},
		{service.Event{Resume: true}, true},
	} {
		ctx, cancel := context.WithCancel(context.Background())
		events := service.NewEventQueue()
		ready, done, stopped := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var queries, stops atomic.Int32
		r := NewRemote(ctx, func(string) {})
		query := func(owner string, excluded uint32) (bool, error) {
			if owner != "owner" || excluded != ^uint32(0) {
				t.Error("callback session ID was used as authority")
			}
			if queries.Add(1) == 1 {
				close(ready)
			}
			return test.present, nil
		}
		go func() {
			defer close(done)
			runSessionEvents(ctx, events, "owner", r, func(bool) {}, func() error {
				if stops.Add(1) == 1 {
					close(stopped)
				}
				return nil
			}, func(string) {}, query)
		}()
		<-ready
		events.Publish(test.event)
		if test.present {
			deadline := time.Now().Add(3 * time.Second)
			for queries.Load() < 2 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
		} else {
			select {
			case <-stopped:
			case <-time.After(3 * time.Second):
				cancel()
				<-done
				t.Fatal("production session loop did not stop routing")
			}
		}
		cancel()
		<-done
		if queries.Load() < 2 || test.present && stops.Load() != 0 || !test.present && stops.Load() != 1 {
			t.Fatal("wrong session transition", queries.Load(), stops.Load())
		}
		if test.event.Resume {
			r.mu.Lock()
			grace := r.wakeGrace
			r.mu.Unlock()
			if !grace.After(time.Now()) {
				t.Fatal("Control resume did not reach Remote.Wake")
			}
		}
	}
}

func TestSeveralOwnerDesktopSessions(t *testing.T) {
	d := &DesktopBridge{}
	d.Connect("console", 1)
	d.Connect("rdp", 2)
	d.Disconnect("rdp")
	if d.PID() != 1 {
		t.Fatal("closing RDP evicted the console desktop")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := d.Call(ctx, "installed-apps", nil); done <- err }()
	var batch []DesktopWork
	for len(batch) == 0 && ctx.Err() == nil {
		batch = d.Poll("console")
		time.Sleep(time.Millisecond)
	}
	if len(batch) != 1 {
		t.Fatal("remaining owner session received no work")
	}
	d.Complete("rdp", batch[0].ID, nil, "")
	select {
	case <-done:
		t.Fatal("other session supplied the result")
	default:
	}
	d.Complete("console", batch[0].ID, []any{}, "")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
