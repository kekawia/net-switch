//go:build linux

package linuxui

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/desktop"
	"github.com/godbus/dbus/v5"
)

func TestHeadlessShellWithoutSessionBus(t *testing.T) {
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
	if CanConnectSessionBus(context.Background()) {
		t.Fatal("expected CanConnectSessionBus=false with empty DBUS_SESSION_BUS_ADDRESS")
	}
	if HasStatusNotifierWatcher(context.Background()) {
		t.Fatal("expected HasStatusNotifierWatcher=false with empty DBUS_SESSION_BUS_ADDRESS")
	}

	sh := StartShell(Callbacks{})
	if sh.HasTray() {
		t.Fatal("expected HasTray=false in headless mode")
	}
	sh.Update(desktop.WaitingTray(), desktop.UnavailableFlyout("waiting"))
	sh.Notify(context.Background(), "Net Switch", "test")
	sh.Close()
	sh.Close()
}

type mockNotifications struct {
	mu     sync.Mutex
	calls  []mockNoticeCall
	notify chan struct{}
}

type mockNoticeCall struct {
	AppName string
	Title   string
	Body    string
	Timeout int32
}

func (m *mockNotifications) Notify(appName string, replacesID uint32, appIcon, summary, body string, actions []string, hints map[string]dbus.Variant, expireTimeout int32) (uint32, *dbus.Error) {
	m.mu.Lock()
	m.calls = append(m.calls, mockNoticeCall{
		AppName: appName,
		Title:   summary,
		Body:    body,
		Timeout: expireTimeout,
	})
	m.mu.Unlock()
	select {
	case m.notify <- struct{}{}:
	default:
	}
	return 1, nil
}

func TestPrivateDBusWatcherAndNotifications(t *testing.T) {
	daemonPath, err := exec.LookPath("dbus-daemon")
	if err != nil {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Fatalf("dbus-daemon required in CI: %v", err)
		}
		t.Skip("dbus-daemon not installed")
	}

	cmd := exec.Command(daemonPath, "--session", "--nofork", "--print-address=1", "--nopidfile")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start dbus-daemon: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})

	addrLine, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatalf("read dbus-daemon address: %v", err)
	}
	addr := strings.TrimSpace(addrLine)
	if addr == "" {
		t.Fatal("dbus-daemon printed empty address")
	}
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", addr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if !CanConnectSessionBus(ctx) {
		t.Fatal("CanConnectSessionBus=false on private dbus-daemon")
	}
	if HasStatusNotifierWatcher(ctx) {
		t.Fatal("expected HasStatusNotifierWatcher=false before watcher is claimed")
	}

	serverBus, err := dbus.ConnectSessionBus(dbus.WithContext(ctx))
	if err != nil {
		t.Fatalf("connect mock server bus: %v", err)
	}
	defer serverBus.Close()

	reply, err := serverBus.RequestName("org.kde.StatusNotifierWatcher", dbus.NameFlagDoNotQueue)
	if err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("claim StatusNotifierWatcher: reply=%v err=%v", reply, err)
	}
	if !HasStatusNotifierWatcher(ctx) {
		t.Fatal("expected HasStatusNotifierWatcher=true after claiming org.kde.StatusNotifierWatcher")
	}

	mock := &mockNotifications{notify: make(chan struct{}, 2)}
	if err := serverBus.Export(mock, "/org/freedesktop/Notifications", "org.freedesktop.Notifications"); err != nil {
		t.Fatalf("export notifications mock: %v", err)
	}
	reply, err = serverBus.RequestName("org.freedesktop.Notifications", dbus.NameFlagDoNotQueue)
	if err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("claim Notifications: reply=%v err=%v", reply, err)
	}

	if err := SendNotification(ctx, "Line down", "Wi-Fi lost connection", 8000); err != nil {
		t.Fatalf("SendNotification: %v", err)
	}
	select {
	case <-mock.notify:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for mock notification")
	}

	mock.mu.Lock()
	defer mock.mu.Unlock()
	if len(mock.calls) != 1 || mock.calls[0].AppName != "Net Switch" || mock.calls[0].Title != "Line down" || mock.calls[0].Body != "Wi-Fi lost connection" {
		t.Fatalf("unexpected notification payload: %+v", mock.calls)
	}
}
