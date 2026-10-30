package lifecycle_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/lifecycle"
	"github.com/AyoubAchour/net-switch/internal/service"
)

// Invoked by the parent with its real unelevated owner token. No synthetic
// descriptor or mocked identity can satisfy this installed-store proof.
func TestInstalledStoreDeniesOwner(t *testing.T) {
	data := os.Getenv("NETSWITCH_INSTALLED_STORE")
	if !hosted() || data == "" {
		t.Skip("launched only by installed owner-access proof")
	}
	if lifecycle.Administrator() {
		t.Fatal("store denial probe is elevated")
	}
	file := filepath.Join(data, "owner.json")
	if _, err := os.ReadFile(file); !errors.Is(err, os.ErrPermission) {
		t.Fatal("owner could read enrollment or denial had wrong cause", err)
	}
	f, err := os.OpenFile(file, os.O_WRONLY, 0)
	if err == nil {
		f.Close()
		t.Fatal("owner could open enrollment for writing")
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Fatal("write denial had wrong cause", err)
	}
}

// Startup assertions formerly exercised the compatibility launcher's desktop
// lifetime. Here the installer prepares the store and SCM owns Control. Worker
// Win32 parity remains a separate comparison with the frozen implementation.
func TestInstalledNativeStartup(t *testing.T) {
	requireInstalledHarness(t)
	root := installedRoot(t)
	target := filepath.Join(root, "outside-target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(target, "record")
	const contents = "outside startup recovery"
	if err := os.WriteFile(sentinel, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	acl := func() string {
		cmd := exec.Command("pwsh.exe", "-NoProfile", "-NonInteractive", "-Command", `@((Get-Acl -LiteralPath $env:NS_TARGET).Sddl,(Get-Acl -LiteralPath (Join-Path $env:NS_TARGET 'record')).Sddl) | ConvertTo-Json -Compress`)
		cmd.Env = append(os.Environ(), "NS_TARGET="+target)
		b, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatal("outside ACL", err, string(b))
		}
		return strings.TrimSpace(string(b))
	}
	before := acl()
	junction := func(t *testing.T, path string) {
		t.Helper()
		cmd := exec.Command("pwsh.exe", "-NoProfile", "-NonInteractive", "-Command", `New-Item -ItemType Junction -Path $env:NS_LINK -Target $env:NS_TARGET -ErrorAction Stop | Out-Null`)
		cmd.Env = append(os.Environ(), "NS_TARGET="+target, "NS_LINK="+path)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatal("plant junction", err, string(b))
		}
	}
	for _, location := range []string{"root", "stage"} {
		for _, kind := range []string{"junction", "hardlink", "children"} {
			t.Run(location+"-"+kind, func(t *testing.T) {
				data := filepath.Join(root, location+"-"+kind)
				occupant := data
				if location == "stage" {
					occupant += ".migrating"
				}
				switch kind {
				case "junction":
					junction(t, occupant)
				case "hardlink":
					if err := os.Link(sentinel, occupant); err != nil {
						t.Fatal(err)
					}
				case "children":
					if err := os.Mkdir(occupant, 0700); err != nil {
						t.Fatal(err)
					}
					junction(t, filepath.Join(occupant, "junction"))
					if err := os.Link(sentinel, filepath.Join(occupant, "hardlink")); err != nil {
						t.Fatal(err)
					}
				}
				f := newInstalledFixture(t, data)
				f.start(t, map[string]any{"checkForUpdates": false, "ipv6": "off"})
				quarantines, err := filepath.Glob(occupant + ".untrusted-*")
				if err != nil || len(quarantines) != 1 {
					t.Fatal("expected exactly one quarantine", quarantines, err)
				}
				if !strings.Contains(f.installOutput, quarantines[0]) {
					t.Fatal("installer omitted quarantine diagnostic", f.installOutput, quarantines)
				}
				if got := acl(); got != before {
					t.Fatal("outside ACL changed", got, before)
				}
				if b, err := os.ReadFile(sentinel); err != nil || string(b) != contents {
					t.Fatal("outside sentinel changed", string(b), err)
				}
				f.quit(t)
				if err := f.cleanup(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
	t.Run("single-instance-preserves-live-store", func(t *testing.T) {
		f := newInstalledFixture(t, filepath.Join(root, "single-instance"))
		f.start(t, map[string]any{"checkForUpdates": false, "ipv6": "off"})
		file := filepath.Join(f.data, "record")
		if err := os.WriteFile(file, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		before, err := os.Stat(f.data)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := service.Start(ctx, service.Control); err != nil {
			t.Fatal(err)
		}
		after := installedIdentity(t, service.Control, filepath.Join(f.directory, "netswitch.exe"))
		if after.PID != f.control.PID {
			t.Fatal("second activation replaced Control", after, f.control)
		}
		// A second direct entrypoint is not a service launch. It must refuse
		// without touching the real installation's live store.
		b, err := exec.CommandContext(ctx, filepath.Join(f.directory, "netswitch.exe"), "service", "--data", f.data).CombinedOutput()
		if err == nil {
			t.Fatal("out-of-SCM duplicate accepted", string(b))
		}
		stat, err := os.Stat(f.data)
		if err != nil || !os.SameFile(before, stat) {
			t.Fatal("duplicate replaced live store", err)
		}
		if b, err := os.ReadFile(file); err != nil || string(b) != contents {
			t.Fatal("duplicate changed sentinel", string(b), err)
		}
		quarantines, err := filepath.Glob(f.data + ".untrusted-*")
		if err != nil || len(quarantines) != 0 {
			t.Fatal("duplicate quarantined live store", quarantines, err)
		}
		if code, body := f.api(t, "GET", "/api/state", nil); code != 200 {
			t.Fatal("original API lost", code, string(body))
		}
		if got := getStatus(t, f.client); got.ControlPID != f.control.PID {
			t.Fatal("original session replaced", got)
		}
		f.quit(t)
	})
	t.Run("automatic-main-and-worker-restrictions", func(t *testing.T) {
		alias, _ := primaryInterface(t)
		f := newInstalledFixture(t, filepath.Join(root, "automatic-main"))
		f.start(t, map[string]any{"checkForUpdates": false, "ipv6": "off"})
		var state struct {
			Lines []struct {
				Alias string `json:"alias"`
			} `json:"lines"`
		}
		code, body := f.api(t, "GET", "/api/state", nil)
		if err := json.Unmarshal(body, &state); err != nil || code != 200 || len(state.Lines) != 1 || state.Lines[0].Alias != alias {
			t.Fatal("default line is not Windows' uplink", string(body), alias, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, filepath.Join(f.directory, "worker.test.exe"), "-test.v", "-test.timeout=90s", "-test.run=^TestReadWorkerCannotWriteControlHKLMOrTCP$")
		cmd.Env = append(os.Environ(), "NETSWITCH_CONTROL_PID="+strconv.FormatUint(uint64(f.control.PID), 10))
		b, err := cmd.CombinedOutput()
		t.Logf("INSTALLED_WORKER_RESTRICTIONS %s", b)
		if err != nil || !strings.Contains(string(b), "--- PASS: TestReadWorkerCannotWriteControlHKLMOrTCP (") {
			t.Fatal("live Control worker restrictions failed or did not run", err)
		}
		if _, err := os.ReadFile(filepath.Join(f.data, "owner.json")); err != nil {
			t.Fatal("enrollment must actually exist before denial probe", err)
		}
		proof := f.owner.command(filepath.Join(f.directory, "lifecycle.test.exe"), "-test.v", "-test.timeout=30s", "-test.run=^TestInstalledStoreDeniesOwner$")
		proof.Env = append(proof.Env, "NETSWITCH_INSTALLED_STORE="+f.data)
		b, err = proof.CombinedOutput()
		t.Logf("INSTALLED_STORE_DENIAL %s", b)
		if err != nil || !strings.Contains(string(b), "--- PASS: TestInstalledStoreDeniesOwner (") {
			t.Fatal("actual owner store ACL proof failed or did not run", err)
		}
		f.quit(t)
	})
	if got := acl(); !reflect.DeepEqual(got, before) {
		t.Fatal("suite changed outside ACL", got, before)
	}
}
