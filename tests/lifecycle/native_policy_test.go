package lifecycle_test

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/apps"
	ce "github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/lifecycle"
	"github.com/AyoubAchour/net-switch/internal/lines"
)

// Run in both product and fault builds, on the installed host's authenticated
// transport. Prediction proves the installed policy, not OS app attribution.
// The fresh and held echoes separately prove capture still carries traffic.
func nativePolicyEvidence(t *testing.T, c *nativeClient, fixture tunFixture, rev *policy.Revision, held net.Conn) {
	if !t.Run("compiled-policy-main-exception-and-blocked-pin", func(t *testing.T) {
		original := rev.Config
		p := ce.Policy{
			Lines:    []lines.Line{{ID: "a1", Alias: fixture.line}, {ID: "unplugged", Alias: "ns-missing"}},
			AppLines: apps.Pins{{Path: "flatpak:org.netswitch.PolicyEvidence", LineID: "unplugged"}},
			Combine:  true,
			Lanes:    map[string]string{"unplugged": "unplugged", "a1": "a1"},
		}
		for _, blocked := range []bool{false, true} {
			if blocked {
				p.Blocked = []string{"unplugged"}
			}
			next, err := lifecycle.NativeRevision(ce.Revision{Number: rev.N + 1, Policy: p})
			if err != nil {
				t.Fatal(err)
			}
			var applied policy.Applied
			nativeMust(t, c, "apply", map[string]any{"revision": next}, &applied)
			if applied.N != next.N || applied.Hash != next.Hash || applied.Point == 0 {
				t.Fatal("installed policy acknowledgement mismatch", applied, next)
			}
			*rev = next
			for _, app := range []string{"flatpak:org.netswitch.PolicyEvidence", "unselected", ""} {
				var got policy.Prediction
				nativeMust(t, c, "predict", map[string]any{"app": app}, &got)
				wantBlocked := blocked && app == "flatpak:org.netswitch.PolicyEvidence"
				wantLine := "a1"
				if app == "flatpak:org.netswitch.PolicyEvidence" {
					wantLine = "unplugged"
				}
				if got.Line != wantLine || got.Blocked != wantBlocked || len(got.Distribution) != 0 {
					t.Fatalf("installed prediction app=%q blocked=%t: %+v", app, blocked, got)
				}
			}
			nativeEcho(t, held, "held-through-policy-change")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			fresh, err := fixture.dial(ctx, "tcp4", fixture.target)
			cancel()
			if err != nil {
				t.Fatal("main exception did not admit a fresh flow", err)
			}
			func() {
				defer fresh.Close()
				nativeEcho(t, fresh, "fresh-main-exception")
				assertNativePolicyFlow(t, c, fixture, fresh, next.N)
			}()
		}
		// Restore the prior policy with a new revision, leaving later proofs on
		// their original fixture. No revision number or apply point is reused.
		rev.N++
		rev.Config = original
		rev.Hash = policy.Hash(original)
		nativeMust(t, c, "apply", map[string]any{"revision": *rev}, nil)
	}) {
		t.FailNow()
	}
}

func assertNativePolicyFlow(t *testing.T, c *nativeClient, fixture tunFixture, conn net.Conn, revision uint64) {
	t.Helper()
	_, source := fixture.origin(t, conn)
	destination := netip.MustParseAddrPort(fixture.target)
	same := func(a, b netip.AddrPort) bool { return a.Addr().Unmap() == b.Addr().Unmap() && a.Port() == b.Port() }
	cursor := ""
	seen := map[string]bool{}
	for {
		var page flows.Page
		nativeMust(t, c, "flows", map[string]any{"cursor": cursor}, &page)
		for _, flow := range page.Flows {
			if flow.Protocol == "tcp" && same(flow.Source, source) && same(flow.Destination, destination) {
				if flow.Revision != revision || flow.Line != "a1" || flow.Lane != "a1" {
					t.Fatal("fresh echo did not use the installed revision's main lane", flow)
				}
				t.Logf("NATIVE_POLICY_FLOW revision=%d lane=%s line=%s source=%s destination=%s", flow.Revision, flow.Lane, flow.Line, flow.Source, flow.Destination)
				return
			}
		}
		if page.Cursor == "" {
			t.Fatal("fresh echo missing from installed engine flow listing", source, destination)
		}
		if seen[page.Cursor] {
			t.Fatal("flow cursor made no progress", page.Cursor)
		}
		seen[page.Cursor] = true
		cursor = page.Cursor
	}
}
