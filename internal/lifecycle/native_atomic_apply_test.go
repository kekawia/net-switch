package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/apps"
	ce "github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
)

type replayApplyStore struct {
	mu      sync.Mutex
	entered chan policy.Applied
	release chan struct{}
	refuse  bool
	saved   []policy.Applied
}

func (s *replayApplyStore) SaveApplied(a policy.Applied) error {
	s.mu.Lock()
	entered, release, refuse := s.entered, s.release, s.refuse
	s.mu.Unlock()
	if a.N == 2 {
		entered <- a
		<-release
	}
	if refuse {
		return errors.New("injected durable revision refusal")
	}
	s.mu.Lock()
	s.saved = append(s.saved, a)
	s.mu.Unlock()
	return nil
}

// A real protocol request changes two lane targets. Persistence is held before
// publication, then refused; both old targets and held records must survive.
// Retrying the same complete revision commits both targets together.
func TestNativeRejectedApplyAndAtomicLaneCommit(t *testing.T) {
	f := newNativeFixture(t, nativeProber{})
	store := &replayApplyStore{}
	table := flows.New(flows.Defaults(), store)
	defer table.CloseAll()
	f.dialMu.Lock()
	f.runtime.table = table
	f.server = protocol.New(f.runtime, table, nativeProber{})
	f.dialMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first := testRevision(1)
	first.Policy.Combine = false
	first.Policy.AppLines = apps.Pins{{Path: "first-app", LineID: "a1"}, {Path: "second-app", LineID: "b2"}}
	f.remote.Restore(&first)
	if err := f.remote.Start(ctx, first.Policy); err != nil {
		t.Fatal(err)
	}
	admit := func(index int, app string) {
		ticket, err := table.Begin("tcp", platform.Tuple{Source: netip.MustParseAddrPort(fmt.Sprintf("198.18.0.2:%d", 40000+index)), Destination: netip.MustParseAddrPort("203.0.113.7:443")})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ticket.Resolve(platform.Owner{AppID: app, Path: app}); err != nil {
			ticket.Close()
			t.Fatal(err)
		}
		ticket.Established(netip.MustParseAddr("192.0.2.1"))
		ticket.Add(7, 9)
		ticket.SetCancel(ticket.Close)
	}
	admit(0, "first-app")
	admit(1, "second-app")
	held, err := table.Page("")
	if err != nil || len(held.Flows) != 2 || held.Flows[0].Line != "a1" || held.Flows[1].Line != "b2" || held.Flows[0].Closing || held.Flows[1].Closing {
		t.Fatal("held-flow starting condition", held, err)
	}
	before := *table.Applied()
	snapshot := f.remote.Snapshot()
	if before.N != 1 || before.Point == 0 || snapshot.Status != "on" {
		t.Fatal("applied starting condition")
	}
	checkTargets := func(first, second string) {
		for i, app := range []string{"first-app", "second-app"} {
			p, err := table.Predict(app)
			if err != nil || p.Line != []string{first, second}[i] || p.Blocked || len(p.Distribution) != 0 {
				t.Fatal("partial lane publication", app, p, err)
			}
		}
	}
	checkTargets("a1", "b2")
	next := first
	next.Number = 2
	next.Hash = "control-hash-2"
	next.Policy.Lanes = map[string]string{"a1": "b2", "b2": "a1", "c3": "a1"}
	for _, refuse := range []bool{true, false} {
		entered := make(chan policy.Applied, 1)
		gate := make(chan struct{})
		release := sync.OnceFunc(func() { close(gate) })
		defer release()
		store.mu.Lock()
		store.entered, store.release, store.refuse = entered, gate, refuse
		store.mu.Unlock()
		type result struct {
			ack ce.Acknowledgement
			err error
		}
		done := make(chan result, 1)
		go func() { a, err := f.remote.Apply(ctx, next); done <- result{a, err} }()
		select {
		case a := <-entered:
			if a.N != 2 {
				t.Fatal("wrong persisted revision", a)
			}
		case <-ctx.Done():
			t.Fatal("native apply never reached persistence")
		}
		checkTargets("a1", "b2")
		if !reflect.DeepEqual(*table.Applied(), before) {
			t.Fatal("revision published before durable commit")
		}
		release()
		var resultValue result
		select {
		case resultValue = <-done:
		case <-ctx.Done():
			t.Fatal("native apply did not return")
		}
		remaining, err := table.Page("")
		if err != nil || !reflect.DeepEqual(remaining.Flows, held.Flows) {
			t.Fatal("apply closed or changed held flows", remaining, err)
		}
		if refuse {
			if resultValue.err == nil || !strings.Contains(resultValue.err.Error(), "injected durable revision refusal") {
				t.Fatal("expected real persistence refusal", resultValue.err)
			}
			if !reflect.DeepEqual(*table.Applied(), before) || !reflect.DeepEqual(f.remote.Snapshot(), snapshot) {
				t.Fatal("refused apply changed revision or client snapshot")
			}
			checkTargets("a1", "b2")
			store.mu.Lock()
			count := len(store.saved)
			store.mu.Unlock()
			if count != 1 {
				t.Fatal("refused revision persisted", count)
			}
		} else {
			if resultValue.err != nil || resultValue.ack.Number != 2 || resultValue.ack.Point <= before.Point {
				t.Fatal("complete retry acknowledgement", resultValue)
			}
			checkTargets("b2", "a1")
			if got := f.remote.Snapshot(); got.AppliedRevision != 2 || !reflect.DeepEqual(got.Policy.Lanes, next.Policy.Lanes) {
				t.Fatal("incomplete acknowledged lane policy", got)
			}
		}
	}
	admit(2, "first-app")
	admit(3, "second-app")
	after, err := table.Page("")
	if err != nil || len(after.Flows) != 4 || !reflect.DeepEqual(after.Flows[:2], held.Flows) || after.Flows[2].Line != "b2" || after.Flows[3].Line != "a1" || after.Flows[2].Revision != 2 || after.Flows[3].Revision != 2 {
		t.Fatal("new flows did not see complete lane commit", after, err)
	}
}
