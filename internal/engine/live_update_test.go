package engine

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
)

// Real engine Apply and flow table, with an in-memory TUN and route boundary.
// No OS adapter, route, service or network socket is created.
func TestLiveApplyPreservesFlowsAndDisablesOnlyIPv6(t *testing.T) {
	routes := &preparedRoutes{}
	e := New(context.Background(), Dependencies{OpenTun: func(context.Context) (platform.TunDevice, error) { return testfake.NewTun(), nil }, Routes: routes, Dialer: testfake.Dialer{}, Owners: &testfake.Owners{}}, flows.Defaults(), nil)
	t.Cleanup(func() { e.Stop(context.Background()) })
	c := policy.Config{Lines: []platform.Line{{ID: "A", Interface: "Ethernet"}, {ID: "B", Interface: "Wi-Fi"}}, AppLines: map[string]string{"other": "B"}, IPv6: true}
	if _, err := e.Start(context.Background(), policy.Revision{N: 1, Hash: policy.Hash(c), Config: c}); err != nil {
		t.Fatal(err)
	}
	var closed [3]atomic.Bool
	for i, spec := range []struct{ app, source, destination, line string }{
		{"main", "192.0.2.1:1234", "198.51.100.1:443", "A"},
		{"other", "192.0.2.2:1235", "198.51.100.2:443", "B"},
		{"other", "[2001:db8::1]:1236", "[2001:db8::2]:443", "B"},
	} {
		flow, err := e.Table.Begin("tcp", platform.Tuple{Source: netip.MustParseAddrPort(spec.source), Destination: netip.MustParseAddrPort(spec.destination)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(flow.Close)
		decision, err := flow.Resolve(platform.Owner{AppID: spec.app})
		if err != nil || decision.Line != spec.line || decision.Revision != 1 {
			t.Fatal(decision, err)
		}
		flow.SetCancel(func() { closed[i].Store(true) })
	}
	page, err := e.Table.Page("")
	if err != nil || len(page.Flows) != 3 {
		t.Fatal("held-flow starting condition", page, err)
	}
	c.Lines[1].Interface = "Renamed Wi-Fi"
	c.Lanes = map[string]string{"A": "B", "B": "A"}
	if _, err := e.Apply(context.Background(), policy.Revision{N: 2, Hash: policy.Hash(c), Config: c}); err != nil {
		t.Fatal(err)
	}
	for i := range closed {
		if closed[i].Load() {
			t.Fatal("alias/lane update closed held flow", i)
		}
	}
	if routes.lines[1].ID != "B" || routes.lines[1].Interface != "Renamed Wi-Fi" {
		t.Fatal("new alias was not prepared")
	}
	c.IPv6 = false
	if _, err := e.Apply(context.Background(), policy.Revision{N: 3, Hash: policy.Hash(c), Config: c}); err != nil {
		t.Fatal(err)
	}
	if closed[0].Load() || closed[1].Load() || !closed[2].Load() {
		t.Fatal("IPv6 disable did not preserve both IPv4 flows")
	}
	if state, _ := e.LiveState(); state != "on" {
		t.Fatal("apply stopped capture", state)
	}
}
