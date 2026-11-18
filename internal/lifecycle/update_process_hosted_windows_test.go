package lifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kekawia/net-switch/internal/service"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type hostedUpdateProofResult struct {
	Code   int
	Output string
}

// Actions encloses shell steps in a non-breakaway job. Reuse the SCM launch
// pattern from tests/lifecycle: production Control also starts from SCM. Only
// this disposable hosted fixture installs a service; the proof itself still
// uses only temporary processes, handles and an ordinary worker job.
func runHostedUpdateProof(t *testing.T) {
	t.Helper()
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Fatal("hosted update proof is forbidden on this machine")
	}
	root := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	name := "NetSwitchUpdateProof-" + randomID()[:16]
	manager, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Disconnect()
	s, err := manager.CreateService(name, executable, mgr.Config{StartType: mgr.StartManual, ServiceStartName: "LocalSystem"},
		"-test.run=^TestUpdateProcessFixture$", "-test.timeout=100s", "-update-fixture-role=service", "-update-fixture-root="+root, "-update-fixture-service="+name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.Control(svc.Stop)
		until := time.Now().Add(10 * time.Second)
		for time.Now().Before(until) {
			status, err := s.Query()
			if err != nil || status.State == svc.Stopped {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if err := s.Delete(); err != nil {
			t.Error("delete hosted proof service", err)
		}
		if err := s.Close(); err != nil {
			t.Error("close hosted proof service", err)
		}
	})
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+name, registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	err = key.SetStringsValue("Environment", []string{"GITHUB_ACTIONS=true", "RUNNER_ENVIRONMENT=github-hosted", "NETSWITCH_UPDATE_PROCESS_REQUIRED=1", "GOMAXPROCS=2", "GOMEMLIMIT=128MiB"})
	key.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		status, err := s.Query()
		if err != nil {
			t.Fatal(err)
		}
		if status.State == svc.Stopped {
			raw, err := os.ReadFile(filepath.Join(root, "result.json"))
			if err != nil {
				t.Fatal("hosted proof stopped without a result", err)
			}
			var result hostedUpdateProofResult
			if err := json.Unmarshal(raw, &result); err != nil {
				t.Fatal(err)
			}
			if result.Code != 0 || !strings.Contains(result.Output, "UPDATE_PROCESS_PROOF worker_killed=true updater_survived=true inherited_sentinel=false outside_all_jobs=true") {
				t.Fatalf("hosted update proof did not complete: %d: %s", result.Code, result.Output)
			}
			t.Log(result.Output)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("hosted update proof did not exit within 90 seconds")
}

func runUpdateProofService(t *testing.T) {
	t.Helper()
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || !strings.HasPrefix(*updateFixtureService, "NetSwitchUpdateProof-") {
		t.Fatal("invalid hosted proof context")
	}
	err := service.Run(*updateFixtureService, func(ctx context.Context, ready func()) error {
		ready()
		bounded, cancel := context.WithTimeout(ctx, 80*time.Second)
		defer cancel()
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		command := exec.CommandContext(bounded, executable, "-test.v", "-test.run=^TestDetachedUpdaterSurvivesWorkerJobAndParentExit$", "-test.timeout=75s", "-update-proof-from-service=true")
		command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.DETACHED_PROCESS}
		output, runErr := command.CombinedOutput()
		result := hostedUpdateProofResult{Output: string(output)}
		if runErr != nil {
			result.Code = 1
			result.Output += "\n" + runErr.Error()
		}
		raw, err := json.Marshal(result)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(*updateFixtureRoot, "result.json"), raw, 0600); err != nil {
			return err
		}
		if result.Code != 0 {
			return fmt.Errorf("hosted update child failed: %s", runErr)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
