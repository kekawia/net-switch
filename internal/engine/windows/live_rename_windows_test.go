package winengine

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

func TestAliasRenameBeforeControlRevisionKeepsPhysicalBinding(t *testing.T) {
	configured := []platform.Line{{ID: "a", Interface: "Before"}}
	addr := netip.MustParseAddr("192.0.2.2")
	old := bindingTable{"a": {ID: "stable-guid", Alias: "Before", LUID: 7, Up: true, Valid: []netip.Addr{addr}}}
	renamed := old["a"]
	renamed.Alias = "After"
	for range 3 { // several platform rounds before Control's network reader runs
		next := resolveBindings(configured, []Adapter{renamed}, configured, &old)
		var closed recordedClosures
		closeLost(&closed, old, next)
		if next["a"].LUID != 7 || len(closed.lines) != 0 || len(closed.sources) != 0 {
			t.Fatal("alias-only change lost the live physical line", next, closed)
		}
		old = next
	}
	// Control's eventual revision must still resolve the same physical adapter.
	next := resolveBindings([]platform.Line{{ID: "a", Interface: "After"}}, []Adapter{renamed}, configured, &old)
	if next["a"].LUID != 7 {
		t.Fatal("new alias did not reconcile", next)
	}
}

func TestAliasRetentionStillObservesPhysicalChanges(t *testing.T) {
	addr := netip.MustParseAddr("192.0.2.2")
	configured := []platform.Line{{ID: "a", Interface: "Before"}}
	old := bindingTable{"a": {ID: "stable-guid", Alias: "Before", LUID: 7, Up: true, Valid: []netip.Addr{addr}}}
	for _, tc := range []struct {
		name, selector string
		adapters       []Adapter
		luid           uint64
		lines, sources []string
	}{
		{"gone", "Before", nil, 0, []string{"a"}, nil},
		{"down", "Before", []Adapter{{ID: "stable-guid", Alias: "After", LUID: 7}}, 7, []string{"a"}, nil},
		{"address-lost", "Before", []Adapter{{ID: "stable-guid", Alias: "After", LUID: 7, Up: true}}, 7, nil, []string{"a 192.0.2.2"}},
		{"alias-reused", "Before", []Adapter{{ID: "different", Alias: "Before", LUID: 8, Up: true}, {ID: "stable-guid", Alias: "After", LUID: 7, Up: true, Valid: []netip.Addr{addr}}}, 7, nil, nil},
		{"explicit-rebind", "Other", []Adapter{{ID: "stable-guid", Alias: "After", LUID: 7, Up: true}, {ID: "different", Alias: "Other", LUID: 8, Up: true}}, 8, []string{"a"}, nil},
		{"replacement", "Before", []Adapter{{ID: "different", Alias: "Before", LUID: 8, Up: true}}, 8, []string{"a"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := resolveBindings([]platform.Line{{ID: "a", Interface: tc.selector}}, tc.adapters, configured, &old)
			var closed recordedClosures
			closeLost(&closed, old, next)
			if next["a"].LUID != tc.luid || !reflect.DeepEqual(closed.lines, tc.lines) || !reflect.DeepEqual(closed.sources, tc.sources) {
				t.Fatal("incorrect physical reconciliation", next, closed)
			}
		})
	}
}
