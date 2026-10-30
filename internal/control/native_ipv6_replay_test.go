package control

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/apppath"
	"github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
)

// Companion selector witness for the trace's actual enabled/disabled policies.
// The trace has empty connection observations. These four synthetic held flows
// establish the stronger selector precondition on both physical lines. The
// existing engine TestLiveApplyPreservesFlowsAndDisablesOnlyIPv6 separately
// verifies that Engine.Apply invokes this production selector automatically.
func checkNativeIPv6Closure(t *testing.T, enabled, disabled engine.Policy) {
	t.Helper()
	if !enabled.IPv6 || disabled.IPv6 {
		t.Fatal("IPv6 closure policy preconditions")
	}
	a, err := engine.NativeRevision(engine.Revision{Number: 1, Policy: enabled}, apppath.Windows)
	if err != nil {
		t.Fatal(err)
	}
	b, err := engine.NativeRevision(engine.Revision{Number: 2, Policy: disabled}, apppath.Windows)
	if err != nil {
		t.Fatal(err)
	}
	table := flows.New(flows.Defaults(), nil)
	defer table.CloseAll()
	// Only the companion's admission pins are synthetic. The final policy and
	// the decision whether IPv6 is allowed come from the running Control.
	a.Config.AppLines = map[string]string{"held-a1": "a1", "held-b2": "b2"}
	a.Hash = policy.Hash(a.Config)
	if _, err := table.Apply(a); err != nil {
		t.Fatal(err)
	}
	for i, line := range []string{"a1", "b2"} {
		for j, v6 := range []bool{false, true} {
			source, destination := fmt.Sprintf("198.18.0.2:%d", 40000+i*2+j), "203.0.113.9:443"
			if v6 {
				source = fmt.Sprintf("[fd00::2]:%d", 40000+i*2+j)
				destination = "[2001:db8::9]:443"
			}
			ticket, err := table.Begin("tcp", platform.Tuple{Source: netip.MustParseAddrPort(source), Destination: netip.MustParseAddrPort(destination)})
			if err != nil {
				t.Fatal(err)
			}
			decision, err := ticket.Resolve(platform.Owner{AppID: "held-" + line})
			if err != nil || decision.Line != line {
				ticket.Close()
				t.Fatal("held physical line", decision, err)
			}
			ticket.SetCancel(ticket.Close)
		}
	}
	before, err := table.Page("")
	if err != nil || len(before.Flows) != 4 {
		t.Fatal("four held family/line records", before, err)
	}
	point, err := table.Apply(b)
	if err != nil {
		t.Fatal(err)
	}
	closed, err := table.CloseFlows(flows.Selector{IPv6: !disabled.IPv6}, point.Point)
	if err != nil || closed.Closed != 2 || closed.Gone != 0 || closed.Failed != 0 {
		t.Fatal("selective IPv6 closure", closed, err)
	}
	after, err := table.Page("")
	if err != nil || len(after.Flows) != 2 {
		t.Fatal("IPv4 survivors", after, err)
	}
	for i, flow := range after.Flows {
		if !reflect.DeepEqual(flow, before.Flows[i*2]) || flow.Line != []string{"a1", "b2"}[i] || flow.Revision != 1 {
			t.Fatal("unrelated held IPv4 changed", flow)
		}
	}
}
