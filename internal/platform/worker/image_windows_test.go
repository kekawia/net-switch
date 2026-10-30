package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type fenceOwnerReport struct {
	Directory  string
	Child      uint32
	StartupMS  int64
	ImageBytes int64
}

func runFenceOwnerProof() int {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	began := time.Now()
	p, err := Start(exe, []string{"worker", "app-info"})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer p.Close()
	child, err := windows.GetProcessId(p.(*process).handle)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	info, err := os.Stat(p.(*process).image.executable)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err = json.NewEncoder(os.Stdout).Encode(fenceOwnerReport{Directory: p.(*process).image.directory, Child: child, StartupMS: time.Since(began).Milliseconds(), ImageBytes: info.Size()}); err != nil {
		return 1
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
	return 0
}

func requireRecordedFilters(t *testing.T, w *workerImage, present bool) {
	t.Helper()
	var engine windows.Handle
	if err := networkCall("FwpmEngineOpen0", 0, 10, 0, 0, uintptr(unsafe.Pointer(&engine))); err != nil {
		t.Fatal(err)
	}
	defer networkCall("FwpmEngineClose0", uintptr(engine))
	for i := range w.policy.Filters {
		var filter *networkFilter
		err := networkCall("FwpmFilterGetByKey0", uintptr(engine), uintptr(unsafe.Pointer(&w.policy.Filters[i])), uintptr(unsafe.Pointer(&filter)))
		if present {
			if err != nil {
				t.Fatalf("filter %d must exist before cleanup: %v", i, err)
			}
			if !sameFenceTag(filter.data, w) {
				t.Error("filter ownership marker differs")
			}
		} else if !errors.Is(err, windows.Errno(windows.FWP_E_FILTER_NOT_FOUND)) {
			t.Errorf("filter %d still present after recovery: %v", i, err)
		}
		if filter != nil {
			networkDLL.NewProc("FwpmFreeMemory0").Call(uintptr(unsafe.Pointer(&filter)))
		}
	}
}

func TestWorkerFenceRecovery(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Skip("requires disposable hosted Windows")
	}
	root := t.TempDir()
	previousRoot := imageRoot
	imageRoot = func() (string, error) { return root, nil }
	defer func() { imageRoot = previousRoot }()
	t.Setenv("NETSWITCH_WORKER_TEST_ROOT", root)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "fence-owner-proof")
	cmd.Env = os.Environ()
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	var report fenceOwnerReport
	if err = json.NewDecoder(output).Decode(&report); err != nil {
		t.Fatal(err)
	}
	t.Logf("private worker image bytes=%d startup_ms=%d", report.ImageBytes, report.StartupMS)
	w := &workerImage{directory: report.Directory, executable: filepath.Join(report.Directory, "worker.exe")}
	if err = readImageRecord(filepath.Join(report.Directory, "policy.json"), &w.policy); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recoverWorkerImage(w.directory) })
	child, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, report.Child)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if child != 0 {
			windows.CloseHandle(child)
		}
	}()
	if state, err := windows.WaitForSingleObject(child, 0); err != nil || state != uint32(windows.WAIT_TIMEOUT) {
		t.Fatalf("child not alive before crash: %d %v", state, err)
	}
	requireRecordedFilters(t, w, true)
	if err = recoverWorkerImage(w.directory); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(w.executable); err != nil {
		t.Fatal("recovery touched live owner", err)
	}
	requireRecordedFilters(t, w, true)
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if state, err := windows.WaitForSingleObject(child, 10000); err != nil || state != windows.WAIT_OBJECT_0 {
		t.Fatalf("job did not terminate child after owner death: %d %v", state, err)
	}
	windows.CloseHandle(child)
	child = 0
	// Prove leftovers still exist after owner death. Dynamic-session cleanup
	// must not receive credit for our recovery implementation.
	if _, err = os.Stat(w.executable); err != nil {
		t.Fatal("image missing before recovery", err)
	}
	requireRecordedFilters(t, w, true)
	if err = recoverWorkerImage(w.directory); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(w.directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("worker directory retained: %v", err)
	}
	requireRecordedFilters(t, w, false)
	owner, err := imageDirectoryOwner(filepath.Base(w.directory))
	if err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(root, fmt.Sprintf("%s%d-%d-%s", imagePrefix, owner.PID, owner.Created, strings.Repeat("a", 32)))
	if err = os.Mkdir(foreign, 0700); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetNamedSecurityInfo(foreign, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	policy, err := json.Marshal(w.policy)
	if err != nil {
		t.Fatal(err)
	}
	foreignRecord := filepath.Join(foreign, "policy.json")
	if err = os.WriteFile(foreignRecord, policy, 0600); err != nil {
		t.Fatal(err)
	}
	if err = recoverWorkerImages(); err != nil {
		t.Fatal(err)
	}
	if after, err := os.ReadFile(foreignRecord); err != nil || string(after) != string(policy) {
		t.Fatalf("recovery touched a foreign writable directory: %v", err)
	}
	t.Log("live owner preserved; owner killed; child exited through job; static filters and image existed afterwards; recovery removed both")
}
