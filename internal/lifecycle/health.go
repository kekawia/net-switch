package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// The native engine can implement this boundary using an internal forwarding
// health check when it replaces the adapter. A successful response resets the
// whole window; snapshot latency is deliberately not an input.
type engineHealth interface {
	Health(context.Context) error
}

// starvedTickLateness: when the watch's own one-second tick fires this late,
// the whole PC is starved (a compiler farm, paging), not just the child. A
// failed probe in such a tick is not counted: killing the forwarding child
// then only adds a crash and a cold restart to the load (2026-11-23). A child
// that is really stuck is still killed once the PC lets the watch run on time.
const starvedTickLateness = 2 * time.Second

type healthWatch struct {
	failedFor time.Duration
	limit     time.Duration
	// starved counts failed probes left out of the window because the watch
	// tick that ran them fired starvedTickLateness or more late.
	starved int
}

func (w *healthWatch) check(ctx context.Context, engine engineHealth, now func() time.Time, late time.Duration) error {
	started := now()
	probe, cancel := context.WithTimeout(ctx, 3*time.Second)
	err := engine.Health(probe)
	cancel()
	if err == nil {
		w.failedFor = 0
		return nil
	}
	var terminal *nativeTransitionTimeout
	if errors.As(err, &terminal) {
		return err
	}
	if late >= starvedTickLateness {
		w.starved++
		return nil
	}
	// A single request that spans standby must not turn eight sleeping hours
	// into a full failure window before queued resume notifications run. Count
	// at most its three-second probe budget (at least one host watch tick).
	w.failedFor += min(max(now().Sub(started), time.Second), 3*time.Second)
	limit := w.limit
	if limit == 0 {
		limit = 20 * time.Second
	}
	if w.failedFor >= limit {
		return fmt.Errorf("routing engine health check failed continuously for %s (%s): %w", limit, systemLoad(), err)
	}
	return nil
}
