//go:build windows

package winengine

import (
	"context"
	"maps"
	"os"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// wfpSession matches documented FWPM_SESSION0 on 64-bit Windows (x64 and ARM64).
type wfpSession struct {
	Key        windows.GUID
	Display    wfpDisplay
	Flags      uint32
	TxnTimeout uint32
	ProcessID  uint32
	_          uint32
	SID        uintptr
	Username   *uint16
	KernelMode int32
	_          uint32
}

const (
	fwpmSessionFlagDynamic = 0x00000001
	fwpActionPermit        = 0x1002
	fwpMatchNotEqual       = 10
	fwpTypeUint8           = 1
	fwpTypeUint32          = 3
	probeTargetHostOrder   = (uint32(198) << 24) | (uint32(18) << 16) | 2 // 198.18.0.2
)

func TestWFPSessionLayoutSize(t *testing.T) {
	if got := unsafe.Sizeof(wfpSession{}); got != 72 {
		t.Fatalf("unsafe.Sizeof(wfpSession{}) = %d, want 72", got)
	}
	var s wfpSession
	if got := unsafe.Offsetof(s.Flags); got != 32 {
		t.Fatalf("Offsetof(Flags) = %d, want 32", got)
	}
	if got := unsafe.Offsetof(s.SID); got != 48 {
		t.Fatalf("Offsetof(SID) = %d, want 48", got)
	}
	if got := unsafe.Offsetof(s.KernelMode); got != 64 {
		t.Fatalf("Offsetof(KernelMode) = %d, want 64", got)
	}
}

func TestHostedDynamicWFPKillSwitchStepAside(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" ||
		os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" ||
		os.Getenv("NETSWITCH_WFP_KILLSWITCH_CI") != "1" {
		t.Skip("Skipping live kernel WFP kill-switch test outside gated GitHub-hosted CI")
	}

	adapters, err := Discover()
	if err != nil {
		t.Fatalf("Discover() failed: %v", err)
	}
	probeIndex := 0
	for _, a := range adapters {
		if a.Up && a.Default4 && a.Index4 > 0 && !a.Tunnel {
			probeIndex = int(a.Index4)
			break
		}
	}
	if probeIndex <= 0 {
		t.Fatalf("no physical IPv4 default adapter found in %+v", adapters)
	}

	var key [32]byte
	for i := range key {
		key[i] = byte(0xA0 + i)
	}
	ctx := context.Background()

	// Baseline: without a foreign kill switch, the UDP challenge to 198.18.0.2:9
	// hits read deadline (permitted by WFP) and must NOT trigger step-aside.
	var baseRoutes Routes
	if fw, err := baseRoutes.CheckVPNFirewall(ctx, probeIndex, 9, key[:]); err != nil || fw != nil {
		t.Fatalf("baseline CheckVPNFirewall = (%+v, %v), want (nil, nil)", fw, err)
	}

	sessName, _ := windows.UTF16PtrFromString("NetSwitch CI WireGuard KillSwitch Simulation")
	sessDesc, _ := windows.UTF16PtrFromString("Dynamic WFP session cleaned automatically on handle close")
	sess := &wfpSession{
		Display:    wfpDisplay{Name: sessName, Description: sessDesc},
		Flags:      fwpmSessionFlagDynamic,
		TxnTimeout: 5000,
	}

	var h windows.Handle
	if err := wfpCall("FwpmEngineOpen0", 0, 10, 0, uintptr(unsafe.Pointer(sess)), uintptr(unsafe.Pointer(&h))); err != nil {
		t.Fatalf("FwpmEngineOpen0(dynamic) failed: %v", err)
	}
	runtime.KeepAlive(sess)
	runtime.KeepAlive(sessName)
	runtime.KeepAlive(sessDesc)
	closed := false
	closeDynamic := func() {
		if !closed && h != 0 {
			closed = true
			_ = wfpCall("FwpmEngineClose0", uintptr(h))
		}
	}
	t.Cleanup(closeDynamic)

	subKey, err := windows.GenerateGUID()
	if err != nil {
		t.Fatalf("GenerateGUID(sublayer): %v", err)
	}
	permitKey, err := windows.GenerateGUID()
	if err != nil {
		t.Fatalf("GenerateGUID(permit): %v", err)
	}
	blockKey, err := windows.GenerateGUID()
	if err != nil {
		t.Fatalf("GenerateGUID(block): %v", err)
	}

	subName, _ := windows.UTF16PtrFromString("WireGuard filters")
	subDesc, _ := windows.UTF16PtrFromString("Permissive and blocking filters")
	subRow := &wfpSubLayer{
		Key:     subKey,
		Display: wfpDisplay{Name: subName, Description: subDesc},
		Weight:  0xFFFF,
	}
	if err := wfpCall("FwpmSubLayerAdd0", uintptr(h), uintptr(unsafe.Pointer(subRow)), 0); err != nil {
		t.Fatalf("FwpmSubLayerAdd0 failed: %v", err)
	}
	runtime.KeepAlive(subRow)
	runtime.KeepAlive(subName)
	runtime.KeepAlive(subDesc)

	// High-weight permit for every destination EXCEPT 198.18.0.2 so the GitHub
	// Actions runner control plane, DNS, and loopback never lose connectivity.
	permitName, _ := windows.UTF16PtrFromString("Permit non-probe runner traffic")
	permitDesc, _ := windows.UTF16PtrFromString("Protects hosted CI runner while testing zero-condition block")
	permitCond := &wfpCondition{
		Field: wfpCondRemoteAddr,
		Match: fwpMatchNotEqual,
		Value: wfpValue{Type: fwpTypeUint32, Value: uintptr(probeTargetHostOrder)},
	}
	permitFilter := &wfpFilter{
		Key:        permitKey,
		Display:    wfpDisplay{Name: permitName, Description: permitDesc},
		Layer:      wfpLayerALEConnectV4,
		SubLayer:   subKey,
		Weight:     wfpValue{Type: fwpTypeUint8, Value: 15},
		Count:      1,
		Conditions: permitCond,
		Action:     wfpAction{Type: fwpActionPermit},
	}
	if err := wfpCall("FwpmFilterAdd0", uintptr(h), uintptr(unsafe.Pointer(permitFilter)), 0, 0); err != nil {
		t.Fatalf("FwpmFilterAdd0(permit) failed: %v", err)
	}
	runtime.KeepAlive(permitFilter)
	runtime.KeepAlive(permitCond)
	runtime.KeepAlive(permitName)
	runtime.KeepAlive(permitDesc)

	// Lower-weight zero-condition catch-all hard block matching WireGuard's
	// real "Block all outbound (IPv4)" filter on FWPM_LAYER_ALE_AUTH_CONNECT_V4.
	blockName, _ := windows.UTF16PtrFromString("Block all outbound (IPv4)")
	blockDesc, _ := windows.UTF16PtrFromString("")
	blockFilter := &wfpFilter{
		Key:      blockKey,
		Display:  wfpDisplay{Name: blockName, Description: blockDesc},
		Layer:    wfpLayerALEConnectV4,
		SubLayer: subKey,
		Weight:   wfpValue{Type: fwpTypeUint8, Value: 1},
		Count:    0,
		Action:   wfpAction{Type: fwpActionBlock},
	}
	if err := wfpCall("FwpmFilterAdd0", uintptr(h), uintptr(unsafe.Pointer(blockFilter)), 0, 0); err != nil {
		t.Fatalf("FwpmFilterAdd0(block) failed: %v", err)
	}
	runtime.KeepAlive(blockFilter)
	runtime.KeepAlive(blockName)
	runtime.KeepAlive(blockDesc)

	// 1. Pre-capture CheckVPNFirewall must detect kernel WSAEACCES and name WireGuard.
	var r Routes
	start := time.Now()
	fw, err := r.CheckVPNFirewall(ctx, probeIndex, 9, key[:])
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("CheckVPNFirewall returned unexpected error: %v", err)
	}
	if fw == nil || !fw.Blocked || !fw.SteppedOut || fw.Blocker != "WireGuard" {
		t.Fatalf("CheckVPNFirewall = %+v, want Blocked=true SteppedOut=true Blocker=WireGuard", fw)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("CheckVPNFirewall took %v, want <= 500ms", elapsed)
	}

	// 2. Live route-monitor check must trigger once and suppress duplicate emissions.
	var liveRoutes Routes
	liveRoutes.fwIndex = probeIndex
	liveRoutes.fwPort = 9
	liveRoutes.fwKey = key
	live := liveRoutes.checkLiveVPNFirewall(ctx)
	if live == nil || !live.Blocked || !live.SteppedOut || live.Blocker != "WireGuard" {
		t.Fatalf("checkLiveVPNFirewall = %+v, want Blocked=true SteppedOut=true Blocker=WireGuard", live)
	}
	if again := liveRoutes.checkLiveVPNFirewall(ctx); again != nil {
		t.Fatalf("second checkLiveVPNFirewall after step-aside = %+v, want nil", again)
	}

	// 3. Coexistence under BFE sublayer weight normalization: while WireGuard's
	// dynamic "WireGuard filters" sublayer holds Weight 0xFFFF, creating Net Switch's
	// persistent wfp-sublayer causes BFE to normalize readback Weight below 65535.
	// Both live inspection (!recovering) and cleanup removal must accept the owned
	// sublayer and delete it cleanly without stranding it in BFE.
	initialFW, err := FirewallState()
	if err != nil {
		t.Fatalf("FirewallState() before sublayer coexistence check: %v", err)
	}
	if initialFW["sublayer"] == true {
		t.Fatalf("unexpected pre-existing NetSwitch WFP sublayer before test: %+v", initialFW)
	}
	subLayerOwner := "0123456789abcdef0123456789abcdef"
	subLayerFP := wfpLayerFingerprint(subLayerOwner)
	wfpObj := &objects{}
	t.Cleanup(func() {
		wfpObj.recovering = true
		_ = removeWFP(wfpObj, "wfp-sublayer", subLayerFP)
		_ = wfpObj.commitFirewallBatch()
		_ = wfpObj.closeFirewall()
	})
	wfpObj.wfpCreates = 1
	if err := createWFP(wfpObj, "wfp-sublayer", subLayerFP); err != nil {
		t.Fatalf("createWFP(wfp-sublayer) alongside 0xFFFF WireGuard sublayer failed: %v", err)
	}
	var readbackRow *wfpSubLayer
	ourSubKey := mustGUID(wfpSubLayerKey)
	if err := wfpCall("FwpmSubLayerGetByKey0", uintptr(wfpObj.wfp), uintptr(unsafe.Pointer(&ourSubKey)), uintptr(unsafe.Pointer(&readbackRow))); err != nil {
		t.Fatalf("FwpmSubLayerGetByKey0(wfp-sublayer) failed: %v", err)
	}
	readbackWeight := readbackRow.Weight
	wfpDLL.NewProc("FwpmFreeMemory0").Call(uintptr(unsafe.Pointer(&readbackRow)))
	t.Logf("BFE readback weight for wfp-sublayer alongside 0xFFFF WireGuard sublayer: %d", readbackWeight)
	if readbackWeight < wfpMinSubLayerWeight {
		t.Fatalf("readback weight %d is below wfpMinSubLayerWeight (%d)", readbackWeight, wfpMinSubLayerWeight)
	}
	liveFP, foundSub, err := inspectWFP(wfpObj, "wfp-sublayer", subLayerFP)
	if err != nil || !foundSub || !maps.Equal(liveFP, subLayerFP) {
		t.Fatalf("inspectWFP(wfp-sublayer) alongside 0xFFFF sublayer = (%v, %v, %v), want (%v, true, nil)", liveFP, foundSub, err, subLayerFP)
	}
	if err := removeWFP(wfpObj, "wfp-sublayer", subLayerFP); err != nil {
		t.Fatalf("removeWFP(wfp-sublayer) failed: %v", err)
	}
	if err := wfpObj.commitFirewallBatch(); err != nil {
		t.Fatalf("commitFirewallBatch(remove wfp-sublayer) failed: %v", err)
	}
	if _, stillThere, err := inspectWFP(wfpObj, "wfp-sublayer", subLayerFP); err != nil || stillThere {
		t.Fatalf("after removeWFP: inspectWFP = (found=%v, err=%v), want (false, nil)", stillThere, err)
	}

	// 4. Closing the dynamic WFP session removes all dynamic filters and restores normal probing.
	closeDynamic()
	if blocker, found, err := inspectForeignVPNKillSwitch(); err != nil || found {
		t.Fatalf("after dynamic session close: inspectForeignVPNKillSwitch = (%q, %v, %v), want (\"\", false, nil)", blocker, found, err)
	}
	if after, err := r.CheckVPNFirewall(ctx, probeIndex, 9, key[:]); err != nil || after != nil {
		t.Fatalf("after dynamic session close: CheckVPNFirewall = (%+v, %v), want (nil, nil)", after, err)
	}
}
