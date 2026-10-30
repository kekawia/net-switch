package engine

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
)

func TestNativeInvalidStartHasNoPlatformEffects(t *testing.T) {
	for _, name := range []string{"zero-revision", "bad-hash", "no-lines", "duplicate-line", "unknown-lane", "blocked-main"} {
		t.Run(name, func(t *testing.T) {
			config := policy.Config{Lines: []platform.Line{{ID: "a1"}}}
			r := policy.Revision{N: 1, Config: config}
			switch name {
			case "zero-revision":
				r.N = 0
			case "no-lines":
				r.Config.Lines = nil
			case "duplicate-line":
				r.Config.Lines = append(r.Config.Lines, r.Config.Lines[0])
			case "unknown-lane":
				r.Config.Lanes = map[string]string{"a1": "missing"}
			case "blocked-main":
				r.Config.Blocked = []string{"a1"}
			}
			r.Hash = policy.Hash(r.Config)
			if name == "bad-hash" {
				r.Hash = "bad"
			}
			opens := 0
			routes := &testfake.Routes{}
			owners := &testfake.Owners{}
			var sockets atomic.Uint64
			dialer := testfake.Dialer{
				TCPFunc: func(context.Context, string, netip.AddrPort) (platform.TCPConn, error) {
					sockets.Add(1)
					return nil, errors.New("unexpected TCP socket")
				},
				UDPFunc: func(context.Context, string, bool) (platform.UDPConn, error) {
					sockets.Add(1)
					return nil, errors.New("unexpected UDP socket")
				},
			}
			e := New(context.Background(), Dependencies{OpenTun: func(context.Context) (platform.TunDevice, error) { opens++; return nil, errors.New("unexpected open") }, Routes: routes, Dialer: dialer, Owners: owners}, flows.Defaults(), nil)
			state, started := e.LiveState()
			if state != "off" || !started.IsZero() || owners.Calls.Load() != 0 || sockets.Load() != 0 {
				t.Fatal("invalid-start platform precondition")
			}
			if e.Table.Applied() != nil || e.stack != nil {
				t.Fatal("invalid-start precondition")
			}
			if _, err := e.Start(context.Background(), r); err == nil {
				t.Fatal("invalid native start accepted")
			}
			state, started = e.LiveState()
			if state != "off" || !started.IsZero() || opens != 0 || sockets.Load() != 0 || owners.Calls.Load() != 0 || len(routes.Calls) != 0 || e.Table.Applied() != nil || e.stack != nil {
				t.Fatal("invalid native start reached platform", state, opens, sockets.Load(), owners.Calls.Load(), routes.Calls)
			}
		})
	}
}
