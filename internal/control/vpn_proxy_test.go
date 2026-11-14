package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/apppath"
	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
)

func newServiceCoreForVPNProxy(t *testing.T) (*Core, *fakeEngine, *fakeClock, *memoryFiles) {
	t.Helper()
	files := &memoryFiles{data: map[string][]byte{}}
	initial := map[string]any{
		"lines":   testLines(),
		"combine": true,
	}
	b, err := js.Marshal(initial)
	if err != nil {
		t.Fatal(err)
	}
	files.data[filepath.Join("/test", "settings.json")] = b
	clock := &fakeClock{at: time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)}
	return testCoreWithFilesMode(t, files, clock, true)
}

func TestVPNAutoDiscoveryExcludeIncludeAndBlockByDefault(t *testing.T) {
	c, eng, _, _ := newServiceCoreForVPNProxy(t)
	ctx := context.Background()
	if err := c.Routing(ctx, true); err != nil {
		t.Fatalf("Routing(true): %v", err)
	}

	// 1. Active VPN with default route auto-discovers in exclude mode (onlyChosen=false),
	// becomes p.Lines[0], disables physical combining while active, and keeps physical
	// lines available for bypass pins.
	netScan := map[string]any{
		"readAt": float64(c.now()),
		"adapters": []any{
			map[string]any{"alias": "Ethernet", "status": "Up", "gateway": "192.0.2.254", "ipv4s": []any{"192.0.2.1"}},
			map[string]any{"alias": "Wi-Fi", "status": "Up", "gateway": "192.0.2.253", "ipv4s": []any{"192.0.2.2"}},
		},
		"defaultRoutes": []any{
			map[string]any{"interfaceAddress": "192.0.2.1"},
			map[string]any{"interfaceAddress": "192.0.2.2"},
		},
		"vpnAdapters": []any{
			map[string]any{
				"alias":           "Mullvad",
				"status":          "Up",
				"ipv4":            "10.64.0.2",
				"ipv4s":           []any{"10.64.0.2"},
				"ipv6":            false,
				"hasDefaultRoute": true,
			},
		},
	}
	if err := c.ApplyNetwork(ctx, netScan, c.generation, c.networkIssued.Add(1)); err != nil {
		t.Fatalf("ApplyNetwork: %v", err)
	}

	snap := eng.Snapshot()
	if len(snap.Policy.Lines) != 3 || !snap.Policy.Lines[0].VPN || snap.Policy.Lines[0].Alias != "Mullvad" {
		t.Fatalf("expected exclude-mode VPN at Policy.Lines[0], got %+v", snap.Policy.Lines)
	}
	if snap.Policy.Combine {
		t.Fatalf("expected physical Combine to pause while exclude-mode VPN owns unpinned apps")
	}
	vpnID := snap.Policy.Lines[0].ID

	// 2. When the VPN drops (status Down) and fallback is false (default), vpnID is Blocked!
	netScan["vpnAdapters"] = []any{
		map[string]any{
			"alias":           "Mullvad",
			"status":          "Down",
			"ipv4s":           []any{},
			"hasDefaultRoute": false,
		},
	}
	if err := c.ApplyNetwork(ctx, netScan, c.generation, c.networkIssued.Add(1)); err != nil {
		t.Fatalf("ApplyNetwork(down): %v", err)
	}
	if err := c.Poll(ctx); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	snap = eng.Snapshot()
	if !slices.Contains(snap.Policy.Blocked, vpnID) {
		t.Fatalf("expected down VPN without fallback in Blocked, got %+v", snap.Policy.Blocked)
	}

	// NativeRevision compiles cleanly with main VPN blocked.
	if _, err := engine.NativeRevision(engine.Revision{Number: 1, Policy: snap.Policy}, apppath.Windows); err != nil {
		t.Fatalf("NativeRevision with blocked main VPN failed: %v", err)
	}

	// 3. Opting into fallback=true redirects the down VPN lane onto Ethernet and unblocks it.
	if _, err := c.Action(ctx, "POST", "/api/lines/update", map[string]any{"id": vpnID, "fallback": true}); err != nil {
		t.Fatalf("update fallback=true: %v", err)
	}
	snap = eng.Snapshot()
	if slices.Contains(snap.Policy.Blocked, vpnID) || snap.Policy.Lanes[vpnID] != "a1" {
		t.Fatalf("expected down VPN with fallback=true to redirect to a1, got blocked=%v lanes=%v", snap.Policy.Blocked, snap.Policy.Lanes)
	}

	// 4. Switching VPN to include mode (onlyChosen=true) restores Ethernet as Policy.Lines[0] and re-enables Combine.
	if _, err := c.Action(ctx, "POST", "/api/lines/update", map[string]any{"id": vpnID, "onlyChosen": true}); err != nil {
		t.Fatalf("update onlyChosen=true: %v", err)
	}
	snap = eng.Snapshot()
	if snap.Policy.Lines[0].ID != "a1" || !snap.Policy.Combine {
		t.Fatalf("expected include-mode VPN to leave a1 primary and Combine=true, got lines=%+v combine=%v", snap.Policy.Lines, snap.Policy.Combine)
	}

	// 5. Removing the VPN records it in removedVpns so reconnect does not auto-add it,
	// but exposes it in candidates so /api/lines/add can re-add it explicitly.
	if _, err := c.Action(ctx, "POST", "/api/lines/remove", map[string]any{"id": vpnID}); err != nil {
		t.Fatalf("remove VPN: %v", err)
	}
	netScan["vpnAdapters"] = []any{
		map[string]any{
			"alias":           "Mullvad",
			"status":          "Up",
			"ipv4":            "10.64.0.2",
			"ipv4s":           []any{"10.64.0.2"},
			"hasDefaultRoute": false,
		},
	}
	if err := c.ApplyNetwork(ctx, netScan, c.generation, c.networkIssued.Add(1)); err != nil {
		t.Fatalf("ApplyNetwork(reconnect after remove): %v", err)
	}
	state := c.State()
	stateLines := state["lines"].([]any)
	if len(stateLines) != 2 {
		t.Fatalf("removed VPN unexpectedly auto-added back: %d lines", len(stateLines))
	}
	cands := state["candidates"].([]any)
	foundCand := false
	for _, raw := range cands {
		m := raw.(map[string]any)
		if m["alias"] == "Mullvad" && m["vpn"] == true {
			foundCand = true
		}
	}
	if !foundCand {
		t.Fatalf("expected removed connected VPN in candidates, got %+v", cands)
	}
	if _, err := c.Action(ctx, "POST", "/api/lines/add", map[string]any{"alias": "Mullvad", "vpn": true}); err != nil {
		t.Fatalf("manual re-add VPN: %v", err)
	}
	if len(c.itemsLocked()) != 3 {
		t.Fatalf("expected 3 lines after manual VPN add, got %d", len(c.itemsLocked()))
	}
}

func TestProxyLineCRUDSealedSecretsAndNoPasswordLeak(t *testing.T) {
	c, eng, _, files := newServiceCoreForVPNProxy(t)
	ctx := context.Background()
	if err := c.Routing(ctx, true); err != nil {
		t.Fatalf("Routing(true): %v", err)
	}

	const secretPass = "placeholder-alpha-bravo" // ggignore
	stateRaw, err := c.Action(ctx, "POST", "/api/lines/add", map[string]any{
		"label": "Local Clash",
		"proxy": map[string]any{
			"protocol": "socks5",
			"server":   "127.0.0.1:7890",
			"carrier":  "main",
			"udp":      true,
			"ipv6":     false,
			"username": "alice",
			"password": secretPass,
		},
	})
	if err != nil {
		t.Fatalf("add proxy line: %v", err)
	}

	// Verify password never appears in settings.json, control-journal.json, proxy-secrets.json, or /api/state!
	stateBytes, err := json.Marshal(stateRaw)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stateBytes, []byte(secretPass)) {
		t.Fatalf("/api/state leaked proxy password: %s", stateBytes)
	}
	for _, name := range []string{"settings.json", "control-journal.json", "proxy-secrets.json"} {
		data, pErr := files.peekFile(filepath.Join("/test", name))
		if pErr != nil {
			t.Fatalf("missing %s: %v", name, pErr)
		}
		if bytes.Contains(data, []byte(secretPass)) {
			t.Fatalf("%s leaked plaintext proxy password!", name)
		}
		if name != "proxy-secrets.json" && bytes.Contains(data, []byte("alice")) {
			t.Fatalf("%s leaked proxy username!", name)
		}
	}

	items := c.itemsLocked()
	if len(items) != 3 || items[2].Proxy == nil {
		t.Fatalf("expected 3rd line to be proxy, got %+v", items)
	}
	proxyLine := items[2]
	rev1 := proxyLine.Proxy.CredentialsRev
	if rev1 == 0 || proxyLine.Proxy.CredentialsRef == "" {
		t.Fatalf("expected sealed CredentialsRef & Rev > 0, got %+v", proxyLine.Proxy)
	}

	// Check /api/state redacted proxy representation.
	stateMap := stateRaw.(map[string]any)
	lineEntry := stateMap["lines"].([]any)[2].(map[string]any)
	proxyJSON := lineEntry["proxy"].(map[string]any)
	if proxyJSON["hasAuth"] != true || proxyJSON["username"] != "alice" {
		t.Fatalf("unexpected redacted proxy state: %+v", proxyJSON)
	}
	if _, hasPass := proxyJSON["password"]; hasPass {
		t.Fatalf("proxy state must never contain password key: %+v", proxyJSON)
	}

	// NativeRevision resolves Carrier="main" -> "a1" (primary physical line).
	compiled1, err := engine.NativeRevision(engine.Revision{Number: 1, Policy: eng.Snapshot().Policy}, apppath.Windows)
	if err != nil {
		t.Fatalf("NativeRevision: %v", err)
	}
	var compiledProxy *platform.ProxyLine
	for _, pl := range compiled1.Config.Lines {
		if pl.ID == proxyLine.ID {
			compiledProxy = pl.Proxy
		}
	}
	if compiledProxy == nil || compiledProxy.Carrier != "a1" || compiledProxy.CredentialsRev != rev1 {
		t.Fatalf("unexpected compiled proxy line: %+v", compiledProxy)
	}

	// Rotating password increments CredentialsRev and changes compiled policy.Hash!
	if _, err := c.Action(ctx, "POST", "/api/lines/update", map[string]any{
		"id":         proxyLine.ID,
		"onlyChosen": false,
		"proxy": map[string]any{
			"protocol": "socks5",
			"server":   "127.0.0.1:7890",
			"carrier":  "main",
			"udp":      true,
			"username": "alice",
			"password": "placeholder-charlie-delta", // ggignore
		},
	}); err != nil {
		t.Fatalf("rotate proxy password: %v", err)
	}
	updatedState := c.State()
	updatedProxyEntry := updatedState["lines"].([]any)[2].(map[string]any)
	if updatedProxyEntry["onlyChosen"] != false || updatedProxyEntry["main"] != true {
		t.Fatalf("expected proxy onlyChosen=false to mark proxy as main, got %+v", updatedProxyEntry)
	}
	compiled2, err := engine.NativeRevision(engine.Revision{Number: 2, Policy: eng.Snapshot().Policy}, apppath.Windows)
	if err != nil {
		t.Fatalf("NativeRevision after rotation: %v", err)
	}
	if compiled2.Hash == compiled1.Hash {
		t.Fatalf("expected policy.Hash to change on password rotation")
	}
	creds, err := c.ProxyCredentials()
	if err != nil || creds[proxyLine.Proxy.CredentialsRef].Password != "placeholder-charlie-delta" {
		t.Fatalf("unexpected resolved credentials after rotation: %+v, err=%v", creds, err)
	}

	// Removing proxy line deletes credentials from secret store.
	if _, err := c.Action(ctx, "POST", "/api/lines/remove", map[string]any{"id": proxyLine.ID}); err != nil {
		t.Fatalf("remove proxy line: %v", err)
	}
	_, _, stillThere, err := c.secrets.Get(proxyLine.Proxy.CredentialsRef)
	if err != nil || stillThere {
		t.Fatalf("expected secret deleted after line removal: stillThere=%v err=%v", stillThere, err)
	}
}

func TestIsolatedProxyConnectivityCheckDoesNotMutateState(t *testing.T) {
	c, _, _, files := newServiceCoreForVPNProxy(t)
	ctx := context.Background()

	// Spin up an echo target and a minimal SOCKS5 server on 127.0.0.1.
	targetLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetLn.Close()
	go func() {
		for {
			conn, err := targetLn.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	socksLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socksLn.Close()
	go func() {
		for {
			conn, err := socksLn.Accept()
			if err != nil {
				return
			}
			go func(sc net.Conn) {
				defer sc.Close()
				buf := make([]byte, 64)
				n, err := sc.Read(buf)
				if err != nil || n < 3 || buf[0] != 0x05 {
					return
				}
				// Require username/password (0x02)
				_, _ = sc.Write([]byte{0x05, 0x02})
				n, err = sc.Read(buf)
				if err != nil || n < 5 || buf[0] != 0x01 {
					return
				}
				uLen := int(buf[1])
				user := string(buf[2 : 2+uLen])
				pLen := int(buf[2+uLen])
				pass := string(buf[3+uLen : 3+uLen+pLen])
				if user != "tester" || pass != "rightpass" {
					_, _ = sc.Write([]byte{0x01, 0x01})
					return
				}
				_, _ = sc.Write([]byte{0x01, 0x00})
				// Read CONNECT or UDP ASSOCIATE request
				n, err = sc.Read(buf)
				if err != nil || n < 10 {
					return
				}
				cmd := buf[1]
				if cmd == 0x03 {
					// UDP ASSOCIATE
					uLn, uErr := net.ListenPacket("udp4", "127.0.0.1:0")
					if uErr != nil {
						return
					}
					defer uLn.Close()
					uAddr := uLn.LocalAddr().(*net.UDPAddr)
					reply := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, byte(uAddr.Port >> 8), byte(uAddr.Port)}
					_, _ = sc.Write(reply)
					_, _ = io.Copy(io.Discard, sc)
					return
				}
				tc, tErr := net.Dial("tcp4", targetLn.Addr().String())
				if tErr != nil {
					_, _ = sc.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
				defer tc.Close()
				_, _ = sc.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0})
				_, _ = io.Copy(tc, sc)
			}(conn)
		}
	}()

	beforeSettings, _ := files.peekFile(filepath.Join("/test", "settings.json"))

	// Wrong password -> authFailed
	badRes, err := c.Action(ctx, "POST", "/api/lines/add", map[string]any{
		"test":   true,
		"target": targetLn.Addr().String(),
		"proxy": map[string]any{
			"protocol": "socks5",
			"server":   socksLn.Addr().String(),
			"carrier":  "local",
			"username": "tester",
			"password": "wrong",
		},
	})
	if err != nil {
		t.Fatalf("testProxyAction(wrong pass): %v", err)
	}
	badMap := badRes.(map[string]any)
	if badMap["ok"] != false || badMap["errorKind"] != "auth" {
		t.Fatalf("expected auth errorKind, got %+v", badMap)
	}

	// Correct password -> ok=true, udpOk=true
	okRes, err := c.Action(ctx, "POST", "/api/lines/add", map[string]any{
		"test":   true,
		"target": targetLn.Addr().String(),
		"proxy": map[string]any{
			"protocol": "socks5",
			"server":   socksLn.Addr().String(),
			"carrier":  "local",
			"udp":      true,
			"username": "tester",
			"password": "rightpass",
		},
	})
	if err != nil {
		t.Fatalf("testProxyAction(right pass): %v", err)
	}
	okMap := okRes.(map[string]any)
	udpPtr, _ := okMap["udpOk"].(*bool)
	if okMap["ok"] != true || udpPtr == nil || !*udpPtr {
		t.Fatalf("expected ok=true and udpOk=true, got %+v", okMap)
	}

	// Non-local carrier while routing is off -> engineOff
	offRes, err := c.Action(ctx, "POST", "/api/lines/add", map[string]any{
		"test": true,
		"proxy": map[string]any{
			"protocol": "socks5",
			"server":   socksLn.Addr().String(),
			"carrier":  "main",
		},
	})
	if err != nil {
		t.Fatalf("testProxyAction(carrier=main while off): %v", err)
	}
	if offRes.(map[string]any)["errorKind"] != "engineOff" {
		t.Fatalf("expected engineOff, got %+v", offRes)
	}

	// Verify zero mutation to settings.json or proxy-secrets.json.
	afterSettings, _ := files.peekFile(filepath.Join("/test", "settings.json"))
	if !bytes.Equal(beforeSettings, afterSettings) {
		t.Fatalf("isolated proxy test mutated settings.json!")
	}
	if _, err := files.peekFile(filepath.Join("/test", "proxy-secrets.json")); err == nil {
		t.Fatalf("isolated proxy test unexpectedly created proxy-secrets.json!")
	}
}

func TestStateSurfacesVPNFirewallAndUnsupportedUDPWithoutTouchingPhysicalShape(t *testing.T) {
	c, eng, _, _ := newServiceCoreForVPNProxy(t)
	ctx := context.Background()

	// Physical-only state must not carry vpnFirewall or extra keys on lines.
	physState := c.State()
	physLine := physState["lines"].([]any)[0].(map[string]any)
	for _, extra := range []string{"vpn", "onlyChosen", "fallback", "proxy", "unsupportedUdp"} {
		if _, exists := physLine[extra]; exists {
			t.Fatalf("physical line unexpectedly emitted %q", extra)
		}
	}

	// Add an HTTP proxy line and simulate VPNFirewall + UnsupportedUDP summary.
	if _, err := c.Action(ctx, "POST", "/api/lines/add", map[string]any{
		"label": "HTTP Proxy",
		"proxy": map[string]any{
			"protocol": "http",
			"server":   "127.0.0.1:8080",
			"carrier":  "local",
		},
	}); err != nil {
		t.Fatalf("add HTTP proxy: %v", err)
	}
	pxID := c.itemsLocked()[2].ID

	eng.mu.Lock()
	eng.s.VPNFirewall = &platform.VPNFirewall{
		Blocked:    true,
		SteppedOut: true,
		Blocker:    "Mullvad Kill Switch",
		Reason:     "WFP block-all filter active",
	}
	eng.mu.Unlock()

	c.mu.Lock()
	c.unsupportedUDP = flows.UnsupportedUDPSummary{
		Total: 7,
		Lines: map[string]uint64{pxID: 7},
		Apps:  map[string]uint64{strings.ToLower(`C:\Games\Quake.exe`): 7},
	}
	conn := apps.Connection{
		ID:     "1",
		Chains: []string{"line-" + pxID},
	}
	conn.Metadata.ProcessPath = `C:\Games\Quake.exe`
	c.tracker.Ingest([]apps.Connection{conn}, c.now())
	c.mu.Unlock()

	st := c.State()
	routing := st["routing"].(map[string]any)
	fw, ok := routing["vpnFirewall"].(*platform.VPNFirewall)
	if !ok || fw == nil || !fw.SteppedOut || fw.Blocker != "Mullvad Kill Switch" {
		t.Fatalf("expected vpnFirewall on routing state, got %+v", routing["vpnFirewall"])
	}
	pxEntry := st["lines"].([]any)[2].(map[string]any)
	if pxEntry["unsupportedUdp"] != uint64(7) {
		t.Fatalf("expected unsupportedUdp=7 on proxy line, got %+v", pxEntry["unsupportedUdp"])
	}
	appRows := st["apps"].([]any)
	if len(appRows) != 1 || appRows[0].(map[string]any)["unsupportedUdp"] != uint64(7) {
		t.Fatalf("expected unsupportedUdp=7 on app row, got %+v", appRows)
	}
}
