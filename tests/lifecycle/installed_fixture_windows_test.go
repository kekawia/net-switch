package lifecycle_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/host"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/internal/lifecycle"
	"github.com/AyoubAchour/net-switch/internal/localipc"
	"github.com/AyoubAchour/net-switch/internal/service"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// installedFixture owns an installation, not a launcher process. Its owner IPC
// connection stays open for the complete session. Engine observations never
// acquire an attach epoch or renew Control's lease.
type installedFixture struct {
	directory, data, installOutput string
	owner                          actor
	client                         *client
	session                        struct{ Token, URL string }
	settings                       map[string]any
	control                        service.Status
	observer                       *lifecycle.RPC
	instance                       string
	epoch                          uint64
	cleanup                        func() error
}

func requireInstalledHarness(t *testing.T) {
	t.Helper()
	if !hosted() || os.Getenv("NETSWITCH_NATIVE_CI") != "1" {
		t.Skip("installed harness runs only on disposable hosted Windows runners")
	}
	if os.Getenv("NETSWITCH_NATIVE_FAULTS") != "1" {
		t.Fatal("installed owner-session fixture requires the lifecycle_test build")
	}
	if lifecycle.CurrentUser() != "S-1-5-18" {
		t.Fatal("use the existing run-hosted SYSTEM service runner")
	}
}

func installedRoot(t *testing.T) string {
	t.Helper()
	requireInstalledHarness(t)
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(os.Getenv("ProgramData"), "NetSwitch-Installed-"+hex.EncodeToString(nonce[:]))
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatal("fixture root already exists or cannot be inspected", root, err)
	}
	if err := lifecycle.PrepareDirectory(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error("fixture root cleanup", err)
		}
	})
	return root
}

func newInstalledFixture(t *testing.T, data string) *installedFixture {
	t.Helper()
	requireInstalledHarness(t)
	f := &installedFixture{directory: os.Getenv("NETSWITCH_LIFECYCLE_DIR"), data: data}
	if !filepath.IsAbs(f.directory) || !filepath.IsAbs(data) {
		t.Fatal("installation and store paths must be absolute")
	}
	// Never uninstall an installation this fixture did not create, even on a
	// hosted runner. An earlier failed cleanup is a failure, not a fresh start.
	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Disconnect()
	for _, name := range []string{service.Control, service.Engine} {
		s, err := m.OpenService(name)
		if err == nil {
			s.Close()
			t.Fatalf("refusing existing service %s", name)
		}
		if err != windows.ERROR_SERVICE_DOES_NOT_EXIST {
			t.Fatal(name, err)
		}
	}
	for _, name := range []string{"netswitch", "netswitch-engine", "netswitch-desktop", "netswitchctl"} {
		image := filepath.Join(f.directory, name+".exe")
		b, err := os.ReadFile(image)
		if err != nil {
			t.Fatal(err)
		}
		arg := "version"
		if name == "netswitch" || name == "netswitch-desktop" {
			arg = "--version"
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		version, err := exec.CommandContext(ctx, image, arg).CombinedOutput()
		cancel()
		if err != nil || strings.TrimSpace(string(version)) == "" {
			t.Fatal("binary identity", image, err, string(version))
		}
		t.Logf("INSTALLED_CANDIDATE path=%q sha256=%x version=%q", image, sha256.Sum256(b), strings.TrimSpace(string(version)))
	}
	f.owner = newActor(t, "NSNativeControlOwner")
	closed := false
	f.cleanup = func() error {
		if closed {
			return nil
		}
		if f.observer != nil {
			f.observer.Close()
			f.observer = nil
		}
		if f.client != nil {
			f.client.input.Close()
		}
		for _, name := range []string{service.Control, service.Engine} {
			stop, done := context.WithTimeout(context.Background(), 20*time.Second)
			err := service.Stop(stop, name)
			done()
			if err != nil {
				force, finish := context.WithTimeout(context.Background(), 15*time.Second)
				_ = service.ForceStop(force, name)
				finish()
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := service.Uninstall(ctx); err != nil {
			return err
		}
		if err := lifecycle.Cleanup(ctx, f.data); err != nil {
			return err
		}
		closed = true
		return nil
	}
	// Install can fail after creating its first service. Register teardown
	// before invoking it; actor cleanup runs after service teardown.
	t.Cleanup(func() {
		if err := f.cleanup(); err != nil {
			t.Error("installed fixture cleanup", err)
		}
		for _, name := range []string{"NetSwitch.log", "NetSwitchEngine.log", "control-journal.json"} {
			if b, err := os.ReadFile(filepath.Join(f.data, name)); err == nil {
				t.Logf("INSTALLED_EVIDENCE %s: %s", name, b)
			}
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, filepath.Join(f.directory, "netswitchctl.exe"), "install", "--directory", f.directory, "--data", data, "--mode", "tun").CombinedOutput()
	f.installOutput = string(b)
	t.Logf("INSTALLED_INSTALL %s", b)
	if err != nil {
		t.Fatal("native install", err, string(b))
	}
	f.data, err = lifecycle.ResolveStore(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.Enroll(ctx, f.data, f.owner.id()); err != nil {
		t.Fatal(err)
	}
	if err := service.SetOwner(f.owner.id()); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Save(filepath.Join(f.data, "fault-owner-sessions.json"), map[string]bool{f.owner.id(): true}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *installedFixture) start(t *testing.T, settings map[string]any) {
	t.Helper()
	f.settings = settings
	if err := lifecycle.Save(filepath.Join(f.data, "settings.json"), settings); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := service.Start(ctx, service.Control); err != nil {
		t.Fatal(err)
	}
	f.client = openClient(t, f.owner, false)
	f.client.must(t, "session", nil, &f.session)
	s := getStatus(t, f.client)
	f.control = installedIdentity(t, service.Control, filepath.Join(f.directory, "netswitch.exe"))
	if s.ControlPID != f.control.PID || f.session.Token == "" || f.session.URL == "" {
		t.Fatal("session/SCM identity mismatch", s, f.control)
	}
	if code, body := f.api(t, "GET", "/api/state", nil); code != 200 {
		t.Fatal("installed API", code, string(body))
	}
}

func (f *installedFixture) api(t *testing.T, method, route string, body any) (int, []byte) {
	t.Helper()
	text := ""
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		text = string(b)
	}
	return apiAs(t, f.owner, f.session.URL, f.session.Token, method, route, text)
}

func installedIdentity(t *testing.T, name, expected string) service.Status {
	t.Helper()
	s, err := service.Query(name)
	if err != nil || !s.Running || s.PID == 0 {
		t.Fatal("service not running", name, s, err)
	}
	installedProcessIdentity(t, s.PID, expected)
	return s
}

func installedProcessIdentity(t *testing.T, pid uint32, expected string) uint64 {
	t.Helper()
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	var token windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	u, err := token.GetTokenUser()
	if err != nil || u.User.Sid.String() != "S-1-5-18" {
		t.Fatal("service/child is not SYSTEM", pid, err)
	}
	image := nativeImage(t, pid)
	if !strings.EqualFold(filepath.Clean(image), filepath.Clean(expected)) {
		t.Fatal("wrong running image", image, expected)
	}
	b, err := os.ReadFile(image)
	if err != nil {
		t.Fatal(err)
	}
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		t.Fatal(err)
	}
	state, err := windows.WaitForSingleObject(h, 0)
	if err != nil || state != uint32(windows.WAIT_TIMEOUT) {
		t.Fatal("process exited during identity observation", pid, state, err)
	}
	t.Logf("INSTALLED_RUNNING pid=%d created=%d:%d user=SYSTEM path=%q sha256=%x", pid, created.HighDateTime, created.LowDateTime, image, sha256.Sum256(b))
	return uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)
}

func (f *installedFixture) observe(t *testing.T) protocol.Status {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if f.observer == nil {
		conn, err := localipc.DialNativeEngine(ctx, localipc.Endpoint{Path: localipc.DefaultPath("engine"), Kind: "engine", Service: service.Engine})
		if err != nil {
			t.Fatal(err)
		}
		f.observer = lifecycle.NewRPC(conn)
		s := installedIdentity(t, service.Engine, filepath.Join(f.directory, "netswitch-engine.exe"))
		if s.PID != conn.Peer.PID {
			t.Fatal("engine IPC peer is not SCM host", s, conn.Peer)
		}
	}
	var hello struct {
		Instance     string          `json:"engineInstanceId"`
		Epoch        uint64          `json:"epoch"`
		Status       protocol.Status `json:"status"`
		Capabilities []string        `json:"capabilities"`
	}
	if err := f.observer.Call(ctx, map[string]any{"method": "hello"}, &hello); err != nil {
		t.Fatal(err)
	}
	if hello.Instance == "" || hello.Epoch == 0 || hello.Status.Instance != hello.Instance || hello.Status.State != "on" || hello.Status.Applied == nil {
		t.Fatal("invalid installed native hello", hello)
	}
	for _, want := range []string{"revisions", "lease", "status", "paged-totals", "totals-ack", "terminal-stop", "probe-options"} {
		if !strings.Contains(" "+strings.Join(hello.Capabilities, " ")+" ", " "+want+" ") {
			t.Fatal("missing native capability", want, hello.Capabilities)
		}
	}
	if f.instance != "" && (f.instance != hello.Instance || f.epoch != hello.Epoch) {
		t.Fatal("Control ownership changed during observation", f.instance, f.epoch, hello.Instance, hello.Epoch)
	}
	f.instance, f.epoch = hello.Instance, hello.Epoch
	outcome, err := host.ReadOutcome(f.data, f.instance)
	if err != nil || outcome.Child == nil || outcome.Child.Completed || outcome.Child.PID != uint32(hello.Status.PID) {
		t.Fatal("native child identity", outcome, hello.Status, err)
	}
	installedProcessIdentity(t, outcome.Child.PID, filepath.Join(f.directory, "netswitch-engine.exe"))
	return hello.Status
}

func (f *installedFixture) flows(t *testing.T) []flows.Record {
	t.Helper()
	f.observe(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var records []flows.Record
	cursor := ""
	seen := map[string]bool{}
	for {
		var page flows.Page
		if err := f.observer.Call(ctx, map[string]any{"method": "flows", "engineInstanceId": f.instance, "epoch": f.epoch, "cursor": cursor}, &page); err != nil {
			t.Fatal(err)
		}
		records = append(records, page.Flows...)
		if page.Cursor == "" {
			break
		}
		if seen[page.Cursor] {
			t.Fatal("native page cursor repeated", page.Cursor)
		}
		seen[page.Cursor], cursor = true, page.Cursor
	}
	f.observe(t) // a read must not fence Control or replace its instance
	return records
}

func (f *installedFixture) quit(t *testing.T) {
	t.Helper()
	if code, body := f.api(t, "POST", "/api/quit", map[string]any{}); code != 200 {
		t.Fatal("installed Quit", code, string(body))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := service.WaitStopped(ctx, service.Control); err != nil {
		t.Fatal("Control service did not stop", err)
	}
	if err := service.WaitStopped(ctx, service.Engine); err != nil {
		t.Fatal("Engine service did not stop", err)
	}
	s, err := service.Query(service.Control)
	if err != nil || !s.Stopped || !s.ExitKnown || s.ExitCode != 0 {
		t.Fatal("Control quit status", s, err)
	}
	t.Logf("INSTALLED_QUIT %s", fmt.Sprint(s))
}
