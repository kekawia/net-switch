package winplatform

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/platform/worker"
	"golang.org/x/sys/windows"
)

// Unlike authority probes, these execute real worker implementations. Each
// result must decode and each call is bounded even if a native provider stalls.
func TestWorkerNativeReads(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Skip("requires disposable hosted Windows")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("NETSWITCH_EXPECT_SYSTEM") == "1" && user.User.Sid.String() != "S-1-5-18" {
		t.Fatal("not SYSTEM")
	}
	t.Logf("native worker parent SID=%s", user.User.Sid.String())
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	s := worker.Supervisor{Executable: exe}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	for _, operation := range []string{"architecture", "policy", "network", "tcp-port-configuration", "port-holder", "tcp-identity", "app-info", "installed-apps", "autostart"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			value, err := s.Once(ctx, operation, map[string]any{"paths": []string{exe}, "port": port})
			if err != nil {
				t.Fatal(err)
			}
			b, err := json.Marshal(value)
			if err != nil || (string(b) == "null" && operation != "policy") {
				t.Fatalf("missing native result: %s %v", b, err)
			}
			t.Logf("native result: %s", b)
		})
	}
	for _, mode := range []string{"meters", "network", "outside", "policy"} {
		t.Run("stream-"+mode, func(t *testing.T) {
			p, err := worker.Start(exe, []string{"worker", mode, "--once"})
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			stop := context.AfterFunc(ctx, func() { _ = p.Kill() })
			defer stop()
			p.Input().Close()
			b, err := io.ReadAll(io.LimitReader(p.Output(), 4*1024*1024))
			e, _ := io.ReadAll(io.LimitReader(p.Errors(), 65536))
			if waitErr := p.Wait(); err != nil || waitErr != nil {
				t.Fatalf("read=%v exit=%v stderr=%s", err, waitErr, e)
			}
			if !json.Valid(b) {
				t.Fatalf("invalid native result: %s stderr=%s", b, e)
			}
			t.Logf("native result: %s", b)
		})
	}
}
