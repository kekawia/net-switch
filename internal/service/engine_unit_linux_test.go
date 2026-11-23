package service

import (
	"strings"
	"testing"
)

// The host never respawns the native child and the service manager never
// respawns the host: Control owns every engine restart (spec §3.4). Only
// Control's own unit restarts on failure.
func TestEngineUnitNeverRestartsItself(t *testing.T) {
	files := unitFiles(Config{Directory: "/opt/netswitch", Data: "/var/lib/netswitch", Native: true})
	engine := files["netswitch-engine.service"]
	if !strings.Contains(engine, "\nRestart=no\n") || !strings.Contains(engine, "ExecStopPost=") {
		t.Fatal("engine unit must only clean up after a failure, never restart", engine)
	}
	if !strings.Contains(files["netswitch.service"], "\nRestart=on-failure\n") {
		t.Fatal("Control's unit must restart on failure", files["netswitch.service"])
	}
}

// Routing and the lease that keeps it on must get CPU while the apps they
// serve are busy; systemd applies Nice before exec, so the supervised engine
// and Control both start raised (the engine's own nice only covered `run`).
func TestServiceUnitsRunAboveNormalPriority(t *testing.T) {
	files := unitFiles(Config{Directory: "/opt/netswitch", Data: "/var/lib/netswitch", Native: true})
	for _, name := range []string{"netswitch.service", "netswitch-engine.service"} {
		if strings.Count(files[name], "\nNice=-5\n") != 1 {
			t.Fatalf("%s must set Nice=-5 once:\n%s", name, files[name])
		}
	}
}

func TestEngineUnitBPFCapabilitiesStayOutOfControl(t *testing.T) {
	files := unitFiles(Config{Directory: "/opt/netswitch", Data: "/var/lib/netswitch", Native: true})
	engine := files["netswitch-engine.service"]
	control := files["netswitch.service"]
	for _, want := range []string{"CAP_BPF", "CAP_PERFMON", "\nLimitMEMLOCK=infinity\n", "\nProtectControlGroups=yes\n"} {
		if !strings.Contains(engine, want) {
			t.Fatalf("engine unit missing %q:\n%s", want, engine)
		}
	}
	if strings.Contains(engine, "CAP_SYS_ADMIN") {
		t.Fatalf("engine unit must not request CAP_SYS_ADMIN:\n%s", engine)
	}
	for _, forbidden := range []string{"CAP_BPF", "CAP_PERFMON", "CAP_SYS_ADMIN", "LimitMEMLOCK=infinity"} {
		if strings.Contains(control, forbidden) {
			t.Fatalf("Control unit must not carry engine BPF privileges (%q):\n%s", forbidden, control)
		}
	}
}
