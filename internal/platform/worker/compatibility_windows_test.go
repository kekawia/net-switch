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
	"unsafe"

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
		name          string
		sids          []string
		disableSystem bool
	}{
		{"null", []string{"S-1-0-0"}, false},
		{"restricted", []string{"S-1-5-12"}, false},
		{"restricted-system-deny-only", []string{"S-1-5-12"}, true},
		{"restricted-and-logon", append([]string{"S-1-5-12"}, logon...), false},
		{"write-restricted", []string{"S-1-5-33"}, false},
		{"users", []string{"S-1-5-32-545"}, false},
		{"everyone", []string{"S-1-1-0"}, false},
	} {
		t.Run(variant.name, func(t *testing.T) {
			p, err := startWithToken(exe, []string{"worker", "app-info"}, nil, windows.DETACHED_PROCESS, workerUILimits,
				func(source windows.Token) (windows.Token, error) {
					restricted, err := constructWorkerToken(source, false, variant.sids, variant.disableSystem)
					if err == nil {
						logWorkerDesktopAccess(t, restricted)
					}
					return restricted, err
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

// Inspect the real desktop ACL; do not infer a denied object from error 1114.
func logWorkerDesktopAccess(t *testing.T, token windows.Token) {
	t.Helper()
	var impersonation windows.Token
	if err := windows.DuplicateTokenEx(token, windows.TOKEN_QUERY, nil, windows.SecurityIdentification, windows.TokenImpersonation, &impersonation); err != nil {
		t.Fatal(err)
	}
	defer impersonation.Close()
	user32 := windows.NewLazySystemDLL("user32.dll")
	station, _, _ := user32.NewProc("GetProcessWindowStation").Call()
	desktop, _, _ := user32.NewProc("GetThreadDesktop").Call(uintptr(windows.GetCurrentThreadId()))
	for _, object := range []struct {
		name    string
		handle  uintptr
		rights  []uint32
		mapping [4]uint32
	}{
		{"window-station", station, []uint32{0x2, 0x8, 0x20}, [4]uint32{0x20303, 0x2001c, 0x20060, 0xf037f}},
		{"desktop", desktop, []uint32{0x1, 0x2, 0x80}, [4]uint32{0x20041, 0x200be, 0x20100, 0xf01ff}},
	} {
		sd, err := windows.GetSecurityInfo(windows.Handle(object.handle), windows.SE_WINDOW_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Errorf("%s descriptor: %v", object.name, err)
			continue
		}
		t.Logf("%s SDDL=%s", object.name, sd.String())
		for _, access := range object.rights {
			// WRITE_RESTRICTED needs the object's real generic-write mapping.
			// The queried station bits have the same classification on both
			// interactive and service window stations.
			mapping := object.mapping
			privileges := new([64]uint64)
			size := uint32(unsafe.Sizeof(*privileges))
			var granted, allowed uint32
			ok, _, callErr := windows.NewLazySystemDLL("advapi32.dll").NewProc("AccessCheck").Call(uintptr(unsafe.Pointer(sd)), uintptr(impersonation), uintptr(access), uintptr(unsafe.Pointer(&mapping[0])), uintptr(unsafe.Pointer(privileges)), uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&granted)), uintptr(unsafe.Pointer(&allowed)))
			t.Logf("OBJECT_ACCESS object=%s requested=%#x api=%d error=%v allowed=%d granted=%#x", object.name, access, ok, callErr, allowed, granted)
			if ok == 0 {
				t.Errorf("AccessCheck failed: %v", callErr)
			}
		}
	}
}
