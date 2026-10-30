package engine

import (
	"context"
	"errors"
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
			e := New(context.Background(), Dependencies{OpenTun: func(context.Context) (platform.TunDevice, error) { opens++; return nil, errors.New("unexpected open") }, Routes: routes, Dialer: testfake.Dialer{}, Owners: &testfake.Owners{}}, flows.Defaults(), nil)
			if e.Table.Applied() != nil || e.stack != nil {
				t.Fatal("invalid-start precondition")
			}
			if _, err := e.Start(context.Background(), r); err == nil {
				t.Fatal("invalid native start accepted")
			}
			if opens != 0 || len(routes.Calls) != 0 || e.Table.Applied() != nil || e.stack != nil {
				t.Fatal("invalid native start reached platform", opens, routes.Calls)
			}
		})
	}
}
