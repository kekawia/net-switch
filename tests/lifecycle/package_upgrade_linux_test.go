package lifecycle_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/kekawia/net-switch/internal/lifecycle"
	"github.com/kekawia/net-switch/internal/lines"
	"github.com/kekawia/net-switch/internal/service"
)

// The package smoke job installs the first real .deb, then starts this
// executable as root. Only the installed services enter the DUT namespace.
func TestInstalledDebUpgradeWithLiveRouting(t *testing.T) {
	if !hosted() || os.Getenv("NETSWITCH_PACKAGE_SMOKE") != "disposable" {
		t.Skip("requires the hosted package smoke runner")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	data := lifecycle.DefaultData()
	dir := "/usr/lib/netswitch"
	deb := os.Getenv("NETSWITCH_TEST_DEB")
	if !filepath.IsAbs(deb) || os.Geteuid() != 0 {
		t.Fatal("missing hosted upgrade fixture")
	}
	owner := newActor(t, "NSNativeControlOwner")
	fixture := prepareTUN(t, dir, data)
	if err := lifecycle.Save(filepath.Join(data, "settings.json"), map[string]any{
		"lines": []lines.Line{{ID: "a1", Alias: fixture.line, Label: "Package test line", Weight: 1}},
		"ipv6":  "off", "checkForUpdates": false,
	}); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, filepath.Join(dir, "netswitchctl"), "enroll", "--owner", owner.id())
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatal(err, string(b))
	}
	if err := service.Start(ctx, service.Control); err != nil {
		t.Fatal(err)
	}
	c := openClient(t, owner, false)
	c.must(t, "routing", map[string]any{"on": true}, nil)
	before := waitRouting(t, c, "original package active", 30*time.Second, func(s status) bool { return s.Routing == "on" && s.Instance != "" })
	echoExact(t, ctx, fixture, 4096)
	if b, err := exec.CommandContext(ctx, "apt-get", "-y", "install", deb).CombinedOutput(); err != nil {
		t.Fatal(err, string(b))
	}
	after := openClient(t, owner, false)
	s := waitRouting(t, after, "replacement resumed routing", 30*time.Second, func(s status) bool {
		return s.Routing == "on" && s.Instance != "" && s.Instance != before.Instance && s.ControlPID != before.ControlPID
	})
	assertNativeCapture(t, s.Instance, fixture)
	echoExact(t, ctx, fixture, 4096)
	persisted, err := lifecycle.LoadOwner(data)
	if err != nil || persisted.User != owner.id() {
		t.Fatal("owner after upgrade", persisted, err)
	}
	t.Log("PACKAGE_TRAFFIC previous_and_replacement_echo=true distinct_engine=true distinct_control=true owner_retained=true")
}
