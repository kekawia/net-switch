package lifecycle

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/kekawia/net-switch/internal/platform/winapi"
	"golang.org/x/sys/windows"
)

var updateFixtureRole = flag.String("update-fixture-role", "", "private test subprocess role")
var updateFixtureRoot = flag.String("update-fixture-root", "", "private test directory")
var updateFixtureHandle = flag.Uint64("update-fixture-handle", 0, "test sentinel handle")
var updateFixtureIdentity = flag.String("update-fixture-identity", "", "test sentinel file identity")
var updateFixtureService = flag.String("update-fixture-service", "", "hosted proof service identity")
var updateProofFromService = flag.Bool("update-proof-from-service", false, "proof launched by the hosted SCM fixture")

type updateProcessReport struct {
	PID       uint32 `json:"pid"`
	Created   int64  `json:"created"`
	InJob     bool   `json:"inJob"`
	Inherited bool   `json:"inherited"`
}

func reportUpdateFixture(path string, inherited bool) error {
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &created, &exited, &kernel, &user); err != nil {
		return err
	}
	inside, err := winapi.ProcessInJob(windows.CurrentProcess(), 0)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(updateProcessReport{PID: windows.GetCurrentProcessId(), Created: created.Nanoseconds(), InJob: inside, Inherited: inherited})
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0600)
}

func TestUpdateProcessFixture(t *testing.T) {
	if *updateFixtureRole == "" {
		return
	}
	if !filepath.IsAbs(*updateFixtureRoot) {
		t.Fatal("fixture directory must be absolute")
	}
	if *updateFixtureRole == "service" {
		runUpdateProofService(t)
		return
	}
	if *updateFixtureRole == "parent" {
		inside, membershipErr := winapi.ProcessInJob(windows.CurrentProcess(), 0)
		var parentLimits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
		limitsErr := winapi.QueryJobInformation(0, windows.JobObjectExtendedLimitInformation, &parentLimits)
		t.Logf("fixture parent in_job=%t flags=%#x membership_error=%v limits_error=%v", inside, parentLimits.BasicLimitInformation.LimitFlags, membershipErr, limitsErr)
		job, err := winapi.NewWorkerJob(0)
		if err != nil {
			t.Fatal(err)
		}
		defer windows.CloseHandle(job)
		// If the detached child inherited this handle, killing the parent would
		// leave the job open and its worker alive, making the proof fail.
		if err := windows.SetHandleInformation(job, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
			t.Fatal(err)
		}
		name, _ := windows.UTF16PtrFromString(filepath.Join(*updateFixtureRoot, "sentinel"))
		sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
		handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer windows.CloseHandle(handle)
		var info windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
			t.Fatal(err)
		}
		identity := fmt.Sprintf("%d:%d:%d", info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow)
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		for _, role := range []string{"worker", "updater"} {
			childJob := job
			if role == "updater" {
				childJob = 0
			}
			child, err := startUpdateProcess(executable, []string{"-test.run=^TestUpdateProcessFixture$", "-test.timeout=60s", "-update-fixture-role=" + role, "-update-fixture-root=" + *updateFixtureRoot, "-update-fixture-handle=" + strconv.FormatUint(uint64(handle), 10), "-update-fixture-identity=" + identity}, childJob)
			if err != nil {
				t.Fatalf("start %s fixture: %v", role, err)
			}
			defer windows.CloseHandle(child.Process)
		}
	} else {
		var info windows.ByHandleFileInformation
		err := windows.GetFileInformationByHandle(windows.Handle(*updateFixtureHandle), &info)
		identity := fmt.Sprintf("%d:%d:%d", info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow)
		if err := reportUpdateFixture(filepath.Join(*updateFixtureRoot, *updateFixtureRole+".json"), err == nil && identity == *updateFixtureIdentity); err != nil {
			t.Fatal(err)
		}
	}
	// A failed parent test cannot leave an unbounded detached fixture behind.
	<-time.After(45 * time.Second)
	t.Fatal("fixture was not retired by its owning test")
}

func TestDetachedUpdaterSurvivesWorkerJobAndParentExit(t *testing.T) {
	if *updateProofFromService {
		inside, err := winapi.ProcessInJob(windows.CurrentProcess(), 0)
		if err != nil || inside {
			t.Fatal("SCM proof did not start outside all jobs", inside, err)
		}
	} else if os.Getenv("GITHUB_ACTIONS") == "true" && os.Getenv("RUNNER_ENVIRONMENT") == "github-hosted" {
		runHostedUpdateProof(t)
		return
	}
	root := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	parent := exec.Command(executable, "-test.run=^TestUpdateProcessFixture$", "-test.timeout=60s", "-update-fixture-role=parent", "-update-fixture-root="+root)
	parent.Env = append(os.Environ(), "GOMAXPROCS=2", "GOMEMLIMIT=128MiB")
	parent.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.DETACHED_PROCESS}
	var output bytes.Buffer
	parent.Stdout, parent.Stderr = &output, &output
	if err := parent.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- parent.Wait() }()
	handles := map[string]windows.Handle{}
	t.Cleanup(func() {
		_ = parent.Process.Kill()
		for _, role := range []string{"worker", "updater"} {
			h := handles[role]
			if h == 0 {
				h, _ = openUpdateFixture(filepath.Join(root, role+".json"))
			}
			if h != 0 {
				_ = windows.TerminateProcess(h, 1)
				_, _ = windows.WaitForSingleObject(h, 10000)
				windows.CloseHandle(h)
			}
		}
	})
	deadline := time.Now().Add(20 * time.Second)
	for _, role := range []string{"worker", "updater"} {
		for {
			select {
			case err := <-done:
				if os.Getenv("GITHUB_ACTIONS") != "true" && os.Getenv("NETSWITCH_UPDATE_PROCESS_REQUIRED") != "1" && strings.Contains(output.String(), "inside=true assigned_job=false") {
					t.Skip("host retains children in a job after breakaway; strict launcher refusal verified, survival proof requires an unconstrained host")
				}
				t.Fatalf("fixture parent exited before proof: %v: %s", err, output.String())
			default:
			}
			h, report := openUpdateFixture(filepath.Join(root, role+".json"))
			if h != 0 {
				handles[role] = h
				if report.Inherited {
					t.Fatalf("%s inherited the sentinel file", role)
				}
				if report.InJob != (role == "worker") {
					t.Fatalf("%s job membership = %v", role, report.InJob)
				}
				state, err := windows.WaitForSingleObject(h, 0)
				if err != nil || state != uint32(windows.WAIT_TIMEOUT) {
					t.Fatalf("%s was not alive before parent exit", role)
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s did not become ready", role)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if err := parent.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("parent did not exit")
	}
	if state, err := windows.WaitForSingleObject(handles["worker"], 10000); err != nil || state != windows.WAIT_OBJECT_0 {
		t.Fatal("worker survived its owner's job closure", state, err)
	}
	if state, err := windows.WaitForSingleObject(handles["updater"], 0); err != nil || state != uint32(windows.WAIT_TIMEOUT) {
		t.Fatal("detached updater died with the worker job", state, err)
	}
	t.Log("UPDATE_PROCESS_PROOF worker_killed=true updater_survived=true inherited_sentinel=false outside_all_jobs=true")
}

// Bind cleanup to both PID and creation time, so a reused PID is never killed.
func openUpdateFixture(path string) (windows.Handle, updateProcessReport) {
	var report updateProcessReport
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &report) != nil || report.PID == 0 || report.Created == 0 {
		return 0, report
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE, false, report.PID)
	if err != nil {
		return 0, report
	}
	var created, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(h, &created, &exited, &kernel, &user) != nil || created.Nanoseconds() != report.Created {
		windows.CloseHandle(h)
		return 0, report
	}
	return h, report
}
