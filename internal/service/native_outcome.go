package service

import (
	"fmt"
	"path/filepath"

	"github.com/kekawia/net-switch/internal/engine/host"
)

func nativeOutcome(name string, state Status) Status {
	if name != Engine || !state.Stopped {
		return state
	}
	data, err := nativeStateDirectory()
	if data == "" && err == nil {
		return state
	} // M2 stand-in or never installed
	return readNativeOutcome(data, state, err)
}

func readNativeOutcome(data string, state Status, err error) Status {
	state.MainExitCode, state.MainExitKnown = state.ExitCode, state.ExitKnown
	if state.MainExitKnown {
		state.MainExitSource = "manager"
	}
	state.ExitKnown = false
	state.Cleanup = "pending"
	if err != nil {
		state.LastError = err.Error()
		return state
	}
	record, err := host.ReadRecord(filepath.Join(data, "engine-state.json"))
	if err != nil {
		state.LastError = "native exit state: " + err.Error()
		return state
	}
	outcome, err := host.ReadOutcome(data, record.Instance)
	if err != nil {
		state.LastError = "native cleanup result: " + err.Error()
		return state
	}
	state.Cleanup, state.LastError = outcome.State, outcome.Error
	if state.LastError == "" && outcome.Child != nil {
		state.LastError = outcome.Child.Error
	}
	if state.ManagerBootID != "" && state.ManagerBootID != outcome.BootID {
		state.Cleanup = "unknown"
		state.LastError = "native cleanup belongs to another or unknown boot"
		return state
	}
	if state.ManagerInvocation != "" && state.ManagerInvocation != outcome.InvocationID {
		state.Cleanup = "unknown"
		state.LastError = "native cleanup belongs to another service invocation"
		return state
	}
	// A newly loaded, never-run unit has code 0 and no invocation. Only then
	// use the manager result retained by this native instance's ExecStopPost.
	// Never replace a signal, another invocation, or a live manager result.
	if !state.MainExitKnown && state.ManagerCode == "0" && state.ManagerStatus == "0" && state.ManagerInvocation == "" && state.ManagerResult == "success" && outcome.Systemd != nil {
		if state.ManagerBootID == "" || outcome.BootID == "" {
			state.LastError = "retained native exit has no matching boot identity"
			return state
		}
		state.MainExitCode, state.MainExitKnown = outcome.Systemd.ExitCode()
		state.MainExitSource = "systemd-stop-post"
		state.ManagerResult = outcome.Systemd.Result
		if !state.MainExitKnown && state.LastError == "" {
			state.LastError = fmt.Sprintf("retained main result has no exit code: code=%q status=%q result=%q", outcome.Systemd.Code, outcome.Systemd.Status, outcome.Systemd.Result)
		}
	}
	// Windows keeps no exit for a service Setup has just re-registered, so
	// every install and update looked like an engine failure (2026-11-23).
	// Only then, and only for an outcome written in this boot, the host's own
	// record stands in: the host exits with its child's 0 or 3 exactly when it
	// recorded a completed, unforced child with no error and finished cleanup.
	if !state.MainExitKnown && state.ManagerNeverRan && hostExitClean(outcome) && outcomeFromThisBoot(outcome) {
		state.MainExitCode, state.MainExitKnown = outcome.Child.Code, true
		state.MainExitSource = "host-outcome"
	}
	incomplete := outcome.Child != nil && (!outcome.Child.Completed || outcome.Child.Forced || state.MainExitKnown && outcome.Child.Code != state.MainExitCode)
	if outcome.State == "failed" || state.MainExitKnown && incomplete && (state.MainExitCode == 0 || state.MainExitCode == 3) || (state.MainExitKnown && state.MainExitCode == 0 && state.ManagerResult != "" && state.ManagerResult != "success") {
		state.ExitKnown, state.ExitCode = true, 1
		if state.LastError == "" {
			if incomplete {
				state.LastError = "native child has no completed, unforced outcome"
			} else {
				state.LastError = "service cleanup failed: " + state.ManagerResult
			}
		}
		return state
	}
	if outcome.State == "complete" {
		state.ExitKnown, state.ExitCode = state.MainExitKnown, state.MainExitCode
	}
	if state.LastError == "" && outcome.State != "complete" {
		state.LastError = fmt.Sprintf("native cleanup is %s for %s", outcome.State, record.Instance)
	}
	if state.LastError == "" && !state.MainExitKnown {
		state.LastError = fmt.Sprintf("main exit code unavailable: manager code=%q status=%q invocation=%q", state.ManagerCode, state.ManagerStatus, state.ManagerInvocation)
	}
	return state
}

// hostExitClean mirrors the host's last word before a 0 or 3 exit: any
// failure on the way writes Child.Error, and failed cleanup sets State.
func hostExitClean(o host.Outcome) bool {
	c := o.Child
	return c != nil && c.Completed && !c.Forced && c.Error == "" && (c.Code == 0 || c.Code == 3) && o.State == "complete" && o.Error == ""
}

// outcomeFromThisBoot refuses an outcome without a boot or from an earlier
// boot, as the systemd path does: a previous boot's record proves nothing
// about this registration.
func outcomeFromThisBoot(o host.Outcome) bool {
	boot, err := host.CurrentBootID()
	return err == nil && boot != "" && o.BootID == boot
}
