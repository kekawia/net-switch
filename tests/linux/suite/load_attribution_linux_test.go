//go:build linux

package suite

import (
	"context"
	"io"
	"net/netip"
	"strings"
	"testing"

	"github.com/AyoubAchour/net-switch/tests/linux/engine"
	"github.com/AyoubAchour/net-switch/tests/linux/harness"
	"github.com/AyoubAchour/net-switch/tests/linux/topo"
)

// runBurstJudgement runs judgeBurstSession on one sample as the real case
// would: unblocked in the 1.0 catalogue, through the harness, under kind.
func runBurstJudgement(t *testing.T, kind harness.EngineKind, exact bool, f engine.Flow, sessions int, seen map[string]int) (*harness.Report, *harness.Case) {
	const id = "udp.fifty-destinations-one-session"
	c := &harness.Case{ID: id, Title: "burst", Label: harness.Parity}
	c.Run = func(test *harness.T) {
		e := &Env{T: test}
		e.judgeBurstSession(exact, f, sessions, 4242, seen)
	}
	return harness.Run(context.Background(), []*harness.Case{c}, harness.NewReport(), harness.Options{Kind: kind, OutDir: t.TempDir(), Console: io.Discard}), c
}

func publicEndpoint(line engine.LineID, port uint16) string {
	return netip.AddrPortFrom(topo.Line(line).Public4, port).String()
}

// The sample from PR #85's CI job 120593704124: one endpoint, on main line a
// from an unknown session. The four consistency checks still pass so the failure
// is never misdiagnosed as a port change, while the missing charlie identity
// fails 1.0 hard.
func TestFiftyDestinationsUnknownOwnerOnMainFailsHard(t *testing.T) {
	unknown := engine.Flow{Protocol: "udp", Lane: "a", Line: "a"}
	report, c := runBurstJudgement(t, harness.V1, true, unknown, 1, map[string]int{publicEndpoint("a", 40000): 50})
	if !report.JobFailed || len(report.Cases) != 1 || report.Cases[0].Outcome != harness.Fail {
		t.Fatalf("an unknown session on main did not fail 1.0 hard: %+v", report)
	}
	checks := report.Cases[0].Checks
	if len(checks) != 5 {
		t.Fatalf("expected 5 mandatory checks, got %d: %+v", len(checks), checks)
	}
	for i, check := range checks {
		if check.ReleaseBlocker {
			t.Fatalf("unexpected release-blocker check at %d: %+v", i, check)
		}
		if i < 4 && !check.OK {
			t.Errorf("consistency check %d failed on explicit unknown sample: %s", i, check.Message)
		}
		if i == 4 && (check.OK || !strings.Contains(check.Message, "charlie's session owner is identified") || !strings.Contains(check.Message, "would pass: false")) {
			t.Errorf("owner check did not fail hard with diagnostic verdict: %+v", check)
		}
	}
	if err := harness.CheckRelease([]*harness.Case{c}); err != nil {
		t.Fatalf("release gate rejected unblocked burst case: %v", err)
	}
}

// Every wrong identity, wrong line, server mismatch, multiple endpoint or
// multiple session sample fails hard, while the identified line-c sample passes.
func TestFiftyDestinationsWrongOwnerLineOrEndpointsStayHard(t *testing.T) {
	charlie, alpha := AppPath("charlie"), AppPath("alpha")
	onC := engine.Flow{Protocol: "udp", App: charlie, AppID: charlie, PID: 4242, Lane: "c", Line: "c"}
	unknown := engine.Flow{Protocol: "udp", Lane: "a", Line: "a"}
	a, c, c2 := publicEndpoint("a", 40000), publicEndpoint("c", 40000), publicEndpoint("c", 40001)
	for _, test := range []struct {
		name     string
		flow     engine.Flow
		sessions int
		seen     map[string]int
	}{
		{"charlie identified but on main", engine.Flow{Protocol: "udp", App: charlie, AppID: charlie, PID: 4242, Lane: "a", Line: "a"}, 1, map[string]int{a: 50}},
		{"charlie identified on c but servers saw main", onC, 1, map[string]int{a: 50}},
		{"unknown on main but servers saw line c", unknown, 1, map[string]int{c: 50}},
		{"unknown routed to line c", engine.Flow{Protocol: "udp", Lane: "c", Line: "c"}, 1, map[string]int{c: 50}},
		{"two public endpoints", onC, 1, map[string]int{c: 30, c2: 20}},
		{"endpoints on two lines", onC, 1, map[string]int{c: 49, a: 1}},
		{"another app's identity", engine.Flow{Protocol: "udp", App: alpha, AppID: alpha, PID: 4242, Lane: "c", Line: "c"}, 1, map[string]int{c: 50}},
		{"another process of charlie", engine.Flow{Protocol: "udp", App: charlie, AppID: charlie, PID: 4243, Lane: "c", Line: "c"}, 1, map[string]int{c: 50}},
		{"partial identity", engine.Flow{Protocol: "udp", AppID: charlie, Lane: "a", Line: "a"}, 1, map[string]int{a: 50}},
		{"no session listed", engine.Flow{}, 0, map[string]int{c: 50}},
		{"two sessions", onC, 2, map[string]int{c: 50}},
	} {
		t.Run(test.name, func(t *testing.T) {
			report, _ := runBurstJudgement(t, harness.V1, true, test.flow, test.sessions, test.seen)
			if !report.JobFailed || report.Cases[0].Outcome != harness.Fail {
				t.Fatalf("hard failure did not fail the job: %+v", report.Cases[0])
			}
			if strings.Contains(report.Cases[0].Detail(), "threshold") {
				t.Fatalf("unexpected release-blocker threshold wording: %s", report.Cases[0].Detail())
			}
		})
	}
	report, _ := runBurstJudgement(t, harness.V1, true, onC, 1, map[string]int{c: 50})
	if report.JobFailed || report.Cases[0].Outcome != harness.Pass {
		t.Fatalf("the identified line-c sample did not pass cleanly: %+v", report.Cases[0])
	}
	for i, check := range report.Cases[0].Checks {
		if !check.OK || check.ReleaseBlocker || (i == 4 && !strings.Contains(check.Message, "would pass: true")) {
			t.Fatalf("the identified sample failed a check or lost its diagnostic verdict: %+v", check)
		}
	}
}

// The baseline reports no identity or PID per session, so there the servers'
// line is the whole verdict and it stays hard; no release check is made.
func TestFiftyDestinationsBaselineKeepsLineCHard(t *testing.T) {
	report, _ := runBurstJudgement(t, harness.Baseline, false, engine.Flow{Protocol: "udp"}, 1, map[string]int{publicEndpoint("c", 40000): 50})
	if report.JobFailed || report.Cases[0].Outcome != harness.Pass || len(report.Cases[0].Checks) != 3 {
		t.Fatalf("the baseline sample on line c didn't pass cleanly: %+v", report.Cases[0])
	}
	report, _ = runBurstJudgement(t, harness.Baseline, false, engine.Flow{Protocol: "udp"}, 1, map[string]int{publicEndpoint("a", 40000): 50})
	if !report.JobFailed || report.Cases[0].Outcome != harness.Fail {
		t.Fatalf("the baseline sample on main wasn't a hard failure: %+v", report.Cases[0])
	}
}

func TestUnderLoadAttributionFailsHard(t *testing.T) {
	c := &harness.Case{ID: "overload.unknown-owner-limits", Title: "recovery", Label: harness.Requires10}
	c.Run = func(test *harness.T) {
		e := &Env{T: test, inspectLoad: true}
		e.checkLoadIdentity(false, "under-load or post-fault owner is unknown")
	}
	report := harness.Run(context.Background(), []*harness.Case{c}, harness.NewReport(), harness.Options{Kind: harness.V1, OutDir: t.TempDir(), Console: io.Discard})
	if !report.JobFailed || len(report.Cases) != 1 || report.Cases[0].Outcome != harness.Fail {
		t.Fatalf("unknown owner under load passed 1.0 CI: %+v", report)
	}
	checks := report.Cases[0].Checks
	if len(checks) != 1 || checks[0].OK || checks[0].ReleaseBlocker {
		t.Fatalf("expected one failed mandatory check, got: %+v", checks)
	}
}

func TestLoadAttributionNeverWaivesIdentityOrRoutingErrors(t *testing.T) {
	path := AppPath("bravo")
	known := engine.Flow{App: path, AppID: path, PID: 42, Lane: "b", Line: "b"}
	unknown := engine.Flow{Lane: "a", Line: "a"}
	for _, test := range []struct {
		name         string
		flow         engine.Flow
		line         engine.LineID
		known, valid bool
	}{
		{"identified on pinned line", known, "b", true, true},
		{"explicit unknown on main", unknown, "a", false, true},
		{"identified on main is still wrong", engine.Flow{App: path, AppID: path, PID: 42, Lane: "a", Line: "a"}, "b", true, false},
		{"unknown on pinned line is still wrong", engine.Flow{Lane: "b", Line: "b"}, "a", false, false},
		{"wrong app", engine.Flow{App: AppPath("alpha"), AppID: AppPath("alpha"), PID: 42, Lane: "b", Line: "b"}, "b", true, false},
		{"wrong pid", engine.Flow{App: path, AppID: path, PID: 43, Lane: "b", Line: "b"}, "b", true, false},
		{"partial unknown", engine.Flow{AppID: path, Lane: "a", Line: "a"}, "a", false, false},
		{"wrong selector", engine.Flow{App: path, AppID: path, PID: 42, Lane: "c", Line: "b"}, "b", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			line, identified, err := loadFlowLine(test.flow, path, 42, "b")
			if line != test.line || identified != test.known || (err == nil) != test.valid {
				t.Fatalf("line=%s identified=%t error=%v", line, identified, err)
			}
		})
	}
}
