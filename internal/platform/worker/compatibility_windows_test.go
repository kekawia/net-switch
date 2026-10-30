package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Compare grants, not merely successful startup. This diagnostic never changes
// Start's policy and never treats a permissive variant as a passing sandbox.
func TestWorkerDLLCompatibility(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Skip("requires disposable hosted Windows")
	}
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("NETSWITCH_EXPECT_SYSTEM") == "1" && user.User.Sid.String() != "S-1-5-18" {
		t.Fatal("not SYSTEM")
	}
	t.Logf("parent SID=%s", user.User.Sid.String())
	groups, err := token.GetTokenGroups()
	if err != nil {
		t.Fatal(err)
	}
	logon := []string{}
	for _, group := range groups.AllGroups() {
		if group.Attributes&windows.SE_GROUP_LOGON_ID == windows.SE_GROUP_LOGON_ID {
			logon = append(logon, group.Sid.String())
		}
	}
	t.Logf("actual logon SIDs=%v (none is not replaced with SYSTEM)", logon)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	key := `SOFTWARE\NetSwitchDLLProof-` + strconv.Itoa(os.Getpid())
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, key, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	k.Close()
	t.Cleanup(func() { _ = registry.DeleteKey(registry.LOCAL_MACHINE, key) })
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	for _, variant := range []struct {
		name string
		sids []string
	}{
		{"null", []string{"S-1-0-0"}},
		{"restricted", []string{"S-1-5-12"}},
		{"restricted-and-logon", append([]string{"S-1-5-12"}, logon...)},
		{"write-restricted", []string{"S-1-5-33"}},
		{"users", []string{"S-1-5-32-545"}},
		{"everyone", []string{"S-1-1-0"}},
	} {
		t.Run(variant.name, func(t *testing.T) {
			p, err := startWithToken(exe, []string{"worker", "app-info"}, nil, windows.DETACHED_PROCESS, workerUILimits,
				func(source windows.Token) (windows.Token, error) {
					return workerTokenWithSIDs(source, false, variant.sids)
				})
			if err != nil {
				t.Errorf("start: %v", err)
				return
			}
			defer p.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			stop := context.AfterFunc(ctx, func() { _ = p.Kill() })
			defer stop()
			if err := json.NewEncoder(p.Input()).Encode(isolationRequest{Parent: uint32(os.Getpid()), Key: key, Address: listener.Addr().String()}); err != nil {
				t.Fatal(err)
			}
			p.Input().Close()
			b, readErr := io.ReadAll(io.LimitReader(p.Output(), 65536))
			e, _ := io.ReadAll(io.LimitReader(p.Errors(), 65536))
			err = p.Wait()
			if err != nil || readErr != nil {
				t.Errorf("exit=%v read=%v stderr=%s stdout=%s", err, readErr, e, b)
				return
			}
			var got isolationResult
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatal(err)
			}
			t.Logf("candidate=%s sids=%v result=%+v", variant.name, variant.sids, got)
			// This result is diagnostic evidence, not qualification: TCP here
			// has no live victim tuple. The separate isolation test supplies one.
			fmt.Printf("WORKER_DLL_CANDIDATE %s %s\n", variant.name, b)
		})
	}
}
