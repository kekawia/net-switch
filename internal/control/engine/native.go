// Package engine owns the translation from Control's durable policy to the native engine.
package engine

import (
	"errors"
	"fmt"
	"math"

	"github.com/AyoubAchour/net-switch/internal/apppath"
	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
)

// pinIdentity is the engine identity a pin binds (design decision recorded in
// the spec): the exact identity the user selected, never inferred from a path
// other apps may share. A Windows path pin is the normalised path, which is
// also the Windows engine's identity, so existing pins stay valid. On Linux a
// path pin inside a sandbox location cannot name the app the person meant (the
// engine reports it by sandbox identity), so it compiles to nothing and is
// shown as needing reselection rather than routed by guess.
func pinIdentity(value string, rules apppath.Rules) (string, bool) {
	if apps.SandboxIdentity(value) {
		return value, true
	}
	if rules.Separator == "/" && apps.PinNeedsReselection(apps.Pin{Path: value}, "") {
		return "", false
	}
	return apppath.Normalize(value, rules), true
}

// NativeRevision compiles a durable Control revision using explicit OS identity rules.
// It performs no I/O and is shared by the IPC client and policy decision evidence.
func NativeRevision(r Revision, rules apppath.Rules) (policy.Revision, error) {
	p := r.Policy
	config := policy.Config{Combine: p.Combine, IPv6: p.IPv6, AppLines: map[string]string{}, Shares: map[string]uint64{}, Lanes: map[string]string{}, Blocked: []string{}}
	known := map[string]bool{}
	for _, line := range p.Lines {
		if line.ID == "" || line.Alias == "" {
			return policy.Revision{}, fmt.Errorf("line %q has no interface alias", line.ID)
		}
		known[line.ID] = true
		config.Lines = append(config.Lines, platform.Line{ID: line.ID, Interface: line.Alias})
	}
	for _, pin := range p.AppLines {
		if !known[pin.LineID] || pin.Path == "" {
			continue
		}
		if id, ok := pinIdentity(pin.Path, rules); ok {
			config.AppLines[id] = pin.LineID
		}
	}
	blocked := map[string]bool{}
	for _, id := range p.Blocked {
		if known[id] && !blocked[id] {
			blocked[id] = true
			config.Blocked = append(config.Blocked, id)
		}
	}
	// Control shares only open lines (spec §4.6), so a blocked line never has
	// a share; the engine refuses one, so the translation drops it as well.
	for _, share := range p.Shares {
		if known[share.ID] && !blocked[share.ID] && share.Value > 0 && !math.IsNaN(share.Value) && !math.IsInf(share.Value, 0) {
			config.Shares[share.ID] = uint64(math.Round(share.Value * 1_000_000))
		}
	}
	for id, target := range p.Lanes {
		if known[id] && known[target] {
			config.Lanes[id] = target
		}
	}
	if r.Number == 0 {
		return policy.Revision{}, errors.New("revision number is required")
	}
	return policy.Revision{N: r.Number, Hash: policy.Hash(config), Config: config}, nil
}
