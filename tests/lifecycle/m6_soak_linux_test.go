package lifecycle_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/kekawia/net-switch/internal/lifecycle"
	"github.com/kekawia/net-switch/internal/lines"
	"github.com/kekawia/net-switch/internal/service"
)

func TestInstalledLinuxTwoHourSoak(t *testing.T) {
	if !hosted() || os.Getenv("NETSWITCH_M6_SOAK") != "1" {
		t.Skip("dedicated hosted M6 job")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 125*time.Minute)
	defer cancel()
	data := lifecycle.DefaultData()
	dir := "/usr/lib/netswitch"
	result := os.Getenv("M6_RESULT")
	if os.Geteuid() != 0 || !filepath.IsAbs(result) {
		t.Fatal("missing disposable M6 setup")
	}
	digests := map[string]string{}
	for _, name := range []string{"netswitch", "netswitch-engine", "netswitchctl", "netswitch-desktop"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		d := sha256.Sum256(b)
		digests[name] = hex.EncodeToString(d[:])
	}
	owner := newActor(t, "NSNativeControlOwner")
	fixture := prepareTUN(t, dir, data)
	if err := lifecycle.Save(filepath.Join(data, "settings.json"), map[string]any{"lines": []lines.Line{{ID: "a1", Alias: fixture.line, Label: "Main", Weight: 1}}, "ipv6": "off", "checkForUpdates": false}); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.CommandContext(ctx, filepath.Join(dir, "netswitchctl"), "enroll", "--owner", owner.id()).CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
	if err := service.Start(ctx, service.Control); err != nil {
		t.Fatal(err)
	}
	c := openClient(t, owner, false)
	c.must(t, "routing", map[string]any{"on": true}, nil)
	initial := waitRouting(t, c, "initial installed routing", 30*time.Second, func(s status) bool { return s.Routing == "on" && s.Instance != "" })
	held := routedStream(t, ctx, fixture)
	defer held.Close()
	fixture.exchange(t, held)
	assertTUNCaptured(t, held, fixture)
	start, last := time.Now(), time.Now()
	n := 0
	save := func(complete bool) {
		b, err := json.Marshal(map[string]any{"complete": complete, "start": start.UTC(), "seconds": time.Since(start).Seconds(), "checks": n, "images": digests, "commit": os.Getenv("GITHUB_SHA"), "instance": initial.Instance})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(result+".tmp", b, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(result+".tmp", result); err != nil {
			t.Fatal(err)
		}
	}
	save(false)
	for time.Since(start) < 2*time.Hour {
		if time.Since(last) > 10*time.Second {
			t.Fatal("traffic observation gap", time.Since(last))
		}
		last = time.Now()
		fixture.exchange(t, held)
		echoExact(t, ctx, fixture, 1024)
		n++
		if n%30 == 0 {
			func() {
				fresh := routedStream(t, ctx, fixture)
				defer fresh.Close()
				fixture.exchange(t, fresh)
				assertTUNCaptured(t, fresh, fixture)
			}()
			s := getStatus(t, c)
			if s.Instance != initial.Instance || s.ControlPID != initial.ControlPID || s.Routing != "on" {
				t.Fatal("installed lifetime changed", s)
			}
			save(false)
			fmt.Printf("M6_LINUX_SOAK checks=%d elapsed=%v\n", n, time.Since(start))
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Second):
		}
	}
	fixture.exchange(t, held)
	assertTUNCaptured(t, held, fixture)
	echoExact(t, ctx, fixture, 4096)
	assertNativeCapture(t, initial.Instance, fixture)
	save(true)
	t.Log("M6_LINUX_SOAK_COMPLETE")
}
