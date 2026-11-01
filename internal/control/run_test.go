package control

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/platform"
)

type panicEngine struct {
	engine.Engine
	where string
}

func (e panicEngine) Snapshot() engine.Snapshot {
	if e.where == "supervisor" {
		panic("supervisor fault")
	}
	return e.Engine.Snapshot()
}
func (e panicEngine) Connections(ctx context.Context) ([]engine.Connection, error) {
	if e.where == "poll" {
		panic("poll fault")
	}
	return e.Engine.Connections(ctx)
}
func (e panicEngine) Probe(ctx context.Context, r engine.ProbeRequest) engine.ProbeResult {
	if e.where == "probe" {
		panic("probe fault")
	}
	return e.Engine.Probe(ctx, r)
}

type panicStream struct{ platform.System }

func (panicStream) Stream(context.Context, string, func([]byte), func(error)) {
	panic("stream callback fault")
}

func TestCrashNetStopsEngineAfterBackgroundPanic(t *testing.T) {
	for _, where := range []string{"poll", "supervisor", "probe", "stream"} {
		t.Run(where, func(t *testing.T) {
			c, e, _, files := testCore(t, map[string]any{"lines": testLines()})
			c.sampleLinesLocked(e.Snapshot())
			if err := c.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			c.op.Engine = panicEngine{e, where}
			for _, l := range c.lanes {
				l.probeAt = nil
			}
			if where == "stream" {
				c.op.Platform = panicStream{c.op.Platform}
			}
			var jobs sync.WaitGroup
			c.op.Background = func(f func()) {
				jobs.Add(1)
				go func() { defer jobs.Done(); defer c.op.Crash.Recover("Run background task"); f() }()
			}
			c.Run()
			select {
			case err := <-c.op.Crash.Failures():
				if !strings.Contains(err.Error(), where) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("panic cleanup did not finish")
			}
			if e.Snapshot().Status != "off" {
				t.Fatal("engine survived panic")
			}
			jobs.Wait()
			files.mu.Lock()
			log := strings.Join(files.logs, "\n")
			files.mu.Unlock()
			if !strings.Contains(log, fmt.Sprintf("%s fault", where)) && !strings.Contains(log, "stream callback fault") {
				t.Fatal("panic was not logged")
			}
		})
	}
}
