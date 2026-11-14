package engine

import (
	"context"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
)

type blockedFirewallRoutes struct {
	healthRoutes
	captured bool
	cleaned  bool
}

func (r *blockedFirewallRoutes) Capture(context.Context) error {
	r.captured = true
	return nil
}

func (r *blockedFirewallRoutes) Cleanup(context.Context) error {
	r.cleaned = true
	return nil
}

func (r *blockedFirewallRoutes) CheckVPNFirewall(context.Context, int, uint16, []byte) (*platform.VPNFirewall, error) {
	return &platform.VPNFirewall{
		Blocked:    true,
		SteppedOut: true,
		Blocker:    "WireGuard",
		Reason:     "WireGuard's kill switch blocks Net Switch. Routing is paused so your VPN keeps working.",
	}, nil
}

func TestEngineStartStepsAsideBeforeCaptureOnVPNFirewall(t *testing.T) {
	tun := testfake.NewTun()
	routes := &blockedFirewallRoutes{}
	key := make([]byte, 32)
	e := New(context.Background(), Dependencies{
		OpenTun:   func(context.Context) (platform.TunDevice, error) { return tun, nil },
		Routes:    routes,
		Dialer:    testfake.Dialer{},
		Owners:    &testfake.Owners{},
		HealthKey: key,
	}, flows.Defaults(), nil)

	cfg := policy.Config{Lines: []platform.Line{{ID: "a", Interface: "eth0"}}}
	rev := policy.Revision{N: 1, Hash: policy.Hash(cfg), Config: cfg}
	_, err := e.Start(context.Background(), rev)
	if err == nil {
		t.Fatal("expected Start to return error when VPN firewall blocks TUN")
	}
	if routes.captured {
		t.Fatal("Capture must not run when CheckVPNFirewall detects a blocking VPN kill switch")
	}
	if !routes.cleaned {
		t.Fatal("expected Cleanup to run on step-aside")
	}
	state, _ := e.LiveState()
	if state != "error" {
		t.Fatalf("expected engine state 'error', got %q", state)
	}
	fw := e.VPNFirewall()
	if fw == nil || !fw.Blocked || !fw.SteppedOut || fw.Blocker != "WireGuard" {
		t.Fatalf("unexpected VPNFirewall status: %+v", fw)
	}
}
