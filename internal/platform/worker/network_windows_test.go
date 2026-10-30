package worker

import (
	"context"
	"encoding/binary"
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

// This is the old constructor from main: disabled elevated groups, stripped
// privileges, Medium integrity, but no restricting SIDs or disabled SYSTEM user.
// Inject it only into a disposable test child; never select it in Start.
func legacyReadToken(source windows.Token) (windows.Token, error) {
	groups, err := source.GetTokenGroups()
	if err != nil {
		return 0, err
	}
	filtered, err := filteredTokenGroups(source)
	if err != nil {
		return 0, err
	}
	disabled, err := disabledWorkerGroups(groups.AllGroups(), filtered)
	if err != nil {
		return 0, err
	}
	var entries *windows.SIDAndAttributes
	if len(disabled) > 0 {
		entries = &disabled[0]
	}
	var token windows.Token
	ok, _, callErr := windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken").Call(uintptr(source), 1, uintptr(len(disabled)), uintptr(unsafe.Pointer(entries)), 0, 0, 0, 0, uintptr(unsafe.Pointer(&token)))
	if ok == 0 {
		return 0, callErr
	}
	if err := mediumIntegrity(token); err != nil {
		token.Close()
		return 0, err
	}
	return token, nil
}

func authorityAnswer(t *testing.T, p Process, input isolationRequest) isolationResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = p.Kill() })
	defer stop()
	if err := json.NewEncoder(p.Input()).Encode(input); err != nil {
		t.Fatal(err)
	}
	p.Input().Close()
	b, err := io.ReadAll(io.LimitReader(p.Output(), 65536))
	e, _ := io.ReadAll(io.LimitReader(p.Errors(), 65536))
	if waitErr := p.Wait(); err != nil || waitErr != nil {
		t.Fatalf("read=%v wait=%v stderr=%s stdout=%s", err, waitErr, e, b)
	}
	var result isolationResult
	if err := json.Unmarshal(b, &result); err != nil {
		t.Fatal(err)
	}
	if result.Error != "" {
		t.Fatal(result.Error)
	}
	return result
}

func TestWorkerNetworkFenceMutation(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Skip("requires disposable hosted Windows")
	}
	root := t.TempDir()
	previousRoot := imageRoot
	imageRoot = func() (string, error) { return root, nil }
	defer func() { imageRoot = previousRoot }()
	t.Setenv("NETSWITCH_WORKER_TEST_ROOT", root)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("NETSWITCH_EXPECT_SYSTEM") == "1" && user.User.Sid.String() != "S-1-5-18" {
		t.Fatal("not SYSTEM")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	key := `SOFTWARE\NetSwitchFenceMutation-` + strconv.Itoa(os.Getpid())
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
	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	local, remote := client.LocalAddr().(*net.TCPAddr), client.RemoteAddr().(*net.TCPAddr)
	port := func(p int) uint32 { return uint32((p&255)<<8 | p>>8) }
	input := isolationRequest{Parent: uint32(os.Getpid()), Key: key, Address: listener.Addr().String(), TCP: [5]uint32{12, binary.LittleEndian.Uint32(local.IP.To4()), port(local.Port), binary.LittleEndian.Uint32(remote.IP.To4()), port(remote.Port)}}
	current, err := Start(exe, []string{"worker", "query", "app-info"})
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close() // Keep its filter present during the controls below.
	got := authorityAnswer(t, current, input)
	t.Logf("current SID=%s result=%+v", user.User.Sid.String(), got)
	if !got.OutboundDenied || !got.RegistryDenied || !got.RegistryDACDenied || !got.ProcessDenied || !got.TCPDenied {
		t.Error("current worker retained forbidden authority")
	}
	probe, err := Start(exe, []string{"worker", "probe"})
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	allowed := authorityAnswer(t, probe, input)
	if allowed.OutboundCode != "<nil>" || !allowed.RegistryDenied || !allowed.ProcessDenied || !allowed.TCPDenied {
		t.Errorf("probe affected by another worker's filter: %+v", allowed)
	}
	parent, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal("parent affected by worker filter", err)
	}
	parent.Close()
	mutated, err := startWithToken(current.(*process).image.executable, []string{"worker", "query", "app-info"}, nil, windows.DETACHED_PROCESS, workerUILimits, legacyReadToken)
	if err != nil {
		t.Fatal(err)
	}
	defer mutated.Close()
	old := authorityAnswer(t, mutated, input)
	if !old.OutboundDenied || len(old.Restricted) != 0 {
		t.Fatalf("token mutation must retain the independent image fence and remove restricting SIDs: %+v", old)
	}
	if user.User.Sid.String() == "S-1-5-18" && (old.RegistryDenied || old.TCPDenied) {
		t.Fatalf("old SYSTEM token did not reproduce write authority: %+v", old)
	}
	fmt.Printf("OLD_TOKEN_MUTATION_REPRODUCED parent=%s registryDenied=%t tcpDeleteDenied=%t outboundDenied=%t restrictedSIDs=%v; production constructor unchanged\n", user.User.Sid.String(), old.RegistryDenied, old.TCPDenied, old.OutboundDenied, old.Restricted)
	// Remove only this fixture's network rules, retain the current token and
	// exact same image, then restore the rules and prove denial returns.
	concrete := current.(*process)
	if err := concrete.fence.close(); err != nil {
		t.Fatal(err)
	}
	concrete.fence = nil
	launchCurrent := func() Process {
		p, err := startWithToken(concrete.image.executable, []string{"worker", "app-info"}, nil, windows.DETACHED_PROCESS, workerUILimits, func(source windows.Token) (windows.Token, error) {
			return workerTokenWithSIDs(source, false, workerReadSIDs("app-info"))
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = p.Close() })
		return p
	}
	unfencedProcess := launchCurrent()
	unfenced := authorityAnswer(t, unfencedProcess, input)
	if err := unfencedProcess.Close(); err != nil {
		t.Fatal(err)
	}
	if unfenced.OutboundCode != "<nil>" || !unfenced.RegistryDenied || !unfenced.ProcessDenied {
		t.Fatalf("network-only mutation did not isolate the fence: %+v", unfenced)
	}
	concrete.fence, err = fenceWorkerNetwork(concrete.image)
	if err != nil {
		t.Fatal(err)
	}
	restoredProcess := launchCurrent()
	restored := authorityAnswer(t, restoredProcess, input)
	if err := restoredProcess.Close(); err != nil {
		t.Fatal(err)
	}
	if !restored.OutboundDenied {
		t.Fatalf("restored fence did not restore denial: %+v", restored)
	}
	t.Log("NETWORK_FENCE_MUTATION_REPRODUCED: same image and current token connected with fixture rules removed; denied again after restoration")
}
