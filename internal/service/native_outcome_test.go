package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kekawia/net-switch/internal/engine/host"
)

func TestNativeStatusRequiresMatchingSuccessfulRecovery(t *testing.T) {
	dir := t.TempDir()
	instance := strings.Repeat("a", 32)
	write := func(path string, v any) {
		t.Helper()
		b, _ := json.Marshal(v)
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dir, "engine-state.json"), host.Record{Schema: 1, Instance: instance})
	path, err := host.OutcomePath(dir, instance)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		state   string
		main    uint32
		manager string
		known   bool
		code    uint32
	}{
		{"pending", 3, "", false, 3}, {"failed", 3, "", true, 1}, {"complete", 3, "exit-code", true, 3},
		{"complete", 0, "success", true, 0}, {"complete", 0, "exit-code", true, 1},
	} {
		outcome := host.Outcome{Instance: instance, State: tc.state}
		if tc.state == "failed" {
			outcome.Error = "cleanup evidence"
		}
		write(path, outcome)
		got := readNativeOutcome(dir, Status{Stopped: true, ExitKnown: true, ExitCode: tc.main, ManagerResult: tc.manager}, nil)
		if got.ExitKnown != tc.known || got.ExitCode != tc.code || got.MainExitCode != tc.main {
			t.Fatal(tc, got)
		}
	}
	write(path, host.Outcome{Instance: strings.Repeat("b", 32), State: "complete"})
	if got := readNativeOutcome(dir, Status{Stopped: true, ExitKnown: true, ExitCode: 3}, nil); got.ExitKnown {
		t.Fatal("foreign outcome proved a clean loss", got)
	}
}

// Setup re-registers the services, so Windows keeps no exit for the engine
// (ERROR_SERVICE_NEVER_STARTED) and every install and update counted as an
// engine failure (2026-11-23). Only the host's own clean record from this boot
// stands in; anything less stays unknown.
func TestNativeStatusAfterTheServiceIsReRegistered(t *testing.T) {
	boot, err := host.CurrentBootID()
	if err != nil || boot == "" {
		t.Skip("no boot identity on this platform", err)
	}
	dir := t.TempDir()
	instance := strings.Repeat("a", 32)
	write := func(path string, v any) {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dir, "engine-state.json"), host.Record{Schema: 1, Instance: instance})
	path, err := host.OutcomePath(dir, instance)
	if err != nil {
		t.Fatal(err)
	}
	clean := func(code uint32, change func(*host.Outcome)) host.Outcome {
		out := host.Outcome{Instance: instance, State: "complete", Reason: "stop", BootID: boot, Child: &host.ChildOutcome{PID: 7, Code: code, Completed: true}}
		if change != nil {
			change(&out)
		}
		return out
	}
	neverRan := Status{Stopped: true, ManagerNeverRan: true}
	for _, tc := range []struct {
		name  string
		out   host.Outcome
		known bool
		code  uint32
	}{
		{"clean stop", clean(0, nil), true, 0},
		{"clean adapter loss", clean(3, func(o *host.Outcome) { o.Reason = "adapter lost" }), true, 3},
		{"child failed", clean(0, func(o *host.Outcome) { o.Reason, o.Child.Error = "failure", "native child failed code=1" }), false, 0},
		{"child forced", clean(0, func(o *host.Outcome) { o.Child.Forced = true }), false, 0},
		{"child without completion", clean(0, func(o *host.Outcome) { o.Child.Completed = false }), false, 0},
		{"host gone before recording the child", clean(0, func(o *host.Outcome) { o.Child = nil }), false, 0},
		{"other child code", clean(1, nil), false, 0},
		{"cleanup failed", clean(0, func(o *host.Outcome) { o.State, o.Error = "failed", "route cleanup" }), true, 1},
		{"cleanup still running", clean(0, func(o *host.Outcome) { o.State = "running" }), false, 0},
		{"earlier boot", clean(0, func(o *host.Outcome) { o.BootID = strings.Repeat("e", 32) }), false, 0},
		{"no boot recorded (older engine)", clean(0, func(o *host.Outcome) { o.BootID = "" }), false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			write(path, tc.out)
			got := readNativeOutcome(dir, neverRan, nil)
			if got.ExitKnown != tc.known || (got.ExitKnown && got.ExitCode != tc.code) {
				t.Fatalf("unexpected final status: %+v", got)
			}
			if !tc.known && got.LastError == "" {
				t.Fatal("unknown exit has no diagnostic", got)
			}
			if tc.known && tc.code != 1 && got.MainExitSource != "host-outcome" {
				t.Fatal("host record used without saying so", got)
			}
		})
	}
	// Only a manager that ran nothing since registration or boot defers to the
	// host's record; any other missing exit (a crash code) stays unknown.
	write(path, clean(0, nil))
	if got := readNativeOutcome(dir, Status{Stopped: true}, nil); got.ExitKnown || got.LastError == "" {
		t.Fatal("host record replaced a manager exit that was merely unknown", got)
	}
	if got := readNativeOutcome(dir, Status{Stopped: true, ExitKnown: true, ExitCode: 3, ManagerNeverRan: true}, nil); !got.ExitKnown || got.ExitCode != 1 || got.MainExitSource == "host-outcome" {
		t.Fatal("host record replaced a live manager exit", got)
	}
}

func TestNativeStatusSurvivesSystemdUnitCollection(t *testing.T) {
	dir := t.TempDir()
	instance, invocation := strings.Repeat("a", 32), strings.Repeat("b", 32)
	write := func(path string, v any) {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dir, "engine-state.json"), host.Record{Schema: 1, Instance: instance})
	path, err := host.OutcomePath(dir, instance)
	if err != nil {
		t.Fatal(err)
	}
	boot := strings.Repeat("d", 32)
	collected := Status{Stopped: true, ManagerCode: "0", ManagerStatus: "0", ManagerResult: "success", ManagerBootID: boot}
	for _, tc := range []struct {
		name, cleanup string
		exit          *host.SystemdExit
		known         bool
		code          uint32
	}{
		{"clean", "complete", &host.SystemdExit{Code: "exited", Status: "0", Result: "success"}, true, 0},
		{"loss", "complete", &host.SystemdExit{Code: "exited", Status: "3", Result: "exit-code"}, true, 3},
		{"crash", "complete", &host.SystemdExit{Code: "killed", Status: "KILL", Result: "signal"}, false, 0},
		{"signal-success-is-not-exit-zero", "complete", &host.SystemdExit{Code: "killed", Status: "TERM", Result: "success"}, false, 0},
		{"missing-main", "complete", nil, false, 0},
		{"missing-status", "complete", &host.SystemdExit{Code: "exited", Result: "success"}, false, 0},
		{"cleanup-pending", "pending", &host.SystemdExit{Code: "exited", Status: "0", Result: "success"}, false, 0},
		{"cleanup-failed", "failed", &host.SystemdExit{Code: "exited", Status: "3", Result: "exit-code"}, true, 1},
		{"manager-failed", "complete", &host.SystemdExit{Code: "exited", Status: "0", Result: "timeout"}, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			write(path, host.Outcome{Instance: instance, State: tc.cleanup, InvocationID: invocation, BootID: boot, Systemd: tc.exit})
			got := readNativeOutcome(dir, collected, nil)
			if got.ExitKnown != tc.known || (got.ExitKnown && got.ExitCode != tc.code) {
				t.Fatalf("unexpected final status: %+v", got)
			}
			if !tc.known && got.LastError == "" {
				t.Fatal("unknown exit has no diagnostic", got)
			}
		})
	}
	write(path, host.Outcome{Instance: instance, State: "complete", InvocationID: invocation, BootID: boot, Systemd: &host.SystemdExit{Code: "exited", Status: "0", Result: "success"}})
	for _, currentBoot := range []string{"", strings.Repeat("e", 32)} {
		state := collected
		state.ManagerBootID = currentBoot
		if got := readNativeOutcome(dir, state, nil); got.ExitKnown || got.LastError == "" {
			t.Fatal("previous boot's clean exit survived reboot/unknown boot", got)
		}
	}
	for _, current := range []Status{
		{Stopped: true, ManagerCode: "2", ManagerStatus: "9", ManagerResult: "signal"},
		{Stopped: true, ManagerCode: "0", ManagerStatus: "0", ManagerResult: "success", ManagerInvocation: strings.Repeat("c", 32)},
		{Stopped: true, ManagerCode: "1", ManagerStatus: "3", ManagerResult: "exit-code", ExitKnown: true, ExitCode: 3},
	} {
		got := readNativeOutcome(dir, current, nil)
		if got.ExitKnown != current.ExitKnown || (got.ExitKnown && got.ExitCode != current.ExitCode) || got.MainExitSource == "systemd-stop-post" {
			t.Fatalf("stored result replaced live manager evidence: %+v -> %+v", current, got)
		}
	}
	foreign := Status{Stopped: true, ExitKnown: true, ManagerCode: "1", ManagerStatus: "0", ManagerResult: "success", ManagerInvocation: strings.Repeat("c", 32)}
	if got := readNativeOutcome(dir, foreign, nil); got.ExitKnown || got.Cleanup != "unknown" || got.LastError == "" {
		t.Fatal("new main exit combined with old invocation cleanup", got)
	}
	write(path, host.Outcome{Instance: instance, State: "complete", Systemd: &host.SystemdExit{Code: "exited", Status: "0", Result: "success"}})
	if got := readNativeOutcome(dir, collected, nil); got.ExitKnown || got.LastError == "" {
		t.Fatal("unbound result accepted", got)
	}
}
