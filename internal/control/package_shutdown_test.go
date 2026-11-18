package control

import (
	"context"
	"testing"
	"time"
)

func TestPackageShutdownRetainsTheLatestDurableChoice(t *testing.T) {
	for _, stopped := range []bool{false, true} {
		t.Run(map[bool]string{false: "routing-on", true: "owner-stopped"}[stopped], func(t *testing.T) {
			c, e, clock, files := testCore(t, map[string]any{"lines": testLines()})
			c.op.ServiceMode, c.op.BootID = true, "package-boot"
			ctx := context.Background()
			if err := c.Routing(ctx, true); err != nil {
				t.Fatal(err)
			}
			if stopped {
				if err := c.Routing(ctx, false); err != nil {
					t.Fatal(err)
				}
			}
			c.failureTimes = []int64{c.now() - 1}
			if err := c.ShutdownForPackageUpgrade(ctx); err != nil {
				t.Fatal(err)
			}
			if e.Snapshot().Status == "on" || c.op.Journal.Values()["wanted"] != !stopped {
				t.Fatal("package shutdown did not stop traffic while preserving owner intent")
			}
			reloaded, restartedEngine, _, _ := testCoreWithFilesBoot(t, files, clock, true, time.UTC, "package-boot")
			if reloaded.WantsRouting() != !stopped || len(reloaded.failureTimes) != 1 {
				t.Fatal("a real journal reload changed the owner choice or failure budget")
			}
			if err := reloaded.ResumeRouting(ctx); err != nil {
				t.Fatal(err)
			}
			if (restartedEngine.Snapshot().Status == "on") != !stopped {
				t.Fatal("package replacement resumed the wrong routing choice")
			}
			cold, _, _, _ := testCoreWithFilesBoot(t, files, clock, true, time.UTC, "different-boot")
			if cold.WantsRouting() {
				t.Fatal("an upgrade's old-boot choice bypassed the sign-in gate")
			}
		})
	}
}

func TestPackageShutdownRefusesAnUncommittedStop(t *testing.T) {
	c, e, _, files := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode, c.op.BootID = true, "package-boot"
	if err := c.Routing(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	files.fail = true
	if err := c.ShutdownForPackageUpgrade(context.Background()); err == nil {
		t.Fatal("package shutdown ignored a refused journal write")
	}
	if !c.WantsRouting() || c.quitting || e.Snapshot().Status != "on" {
		t.Fatal("an uncommitted package stop changed live routing")
	}
	files.fail = false
	if err := c.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.op.Journal.Values()["wanted"] != false {
		t.Fatal("an owner's Quit did not persist an explicit stop")
	}
}
