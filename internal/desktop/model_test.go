package desktop

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testKB = 1024
	testMB = 1024 * testKB
	testGB = 1024 * testMB
)

func testLine(id, label string, extra map[string]any) map[string]any {
	m := map[string]any{
		"id":          id,
		"alias":       "Ethernet",
		"label":       label,
		"kind":        "wired",
		"main":        false,
		"connected":   true,
		"problem":     nil,
		"ping":        18,
		"connections": 6,
		"carrying":    true,
		"target":      id,
		"rate":        map[string]any{"down": 38 * testKB, "up": 1234},
		"ssid":        nil,
		"metered":     false,
		"strict":      false,
		"cap":         nil,
		"usage":       map[string]any{"bytes": 0.4 * testGB, "periodStart": "2026-10-01T00:00:00.000Z"},
		"exhausted":   false,
		"weight":      1,
		"share":       nil,
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func cloneMap(src map[string]any) map[string]any {
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func downLine(base map[string]any, problem, target string) map[string]any {
	m := cloneMap(base)
	m["connected"] = false
	m["problem"] = problem
	m["ping"] = nil
	m["connections"] = 0
	m["carrying"] = false
	m["target"] = target
	m["rate"] = map[string]any{"down": 0, "up": 0}
	return m
}

func testApp(name string, score float64, down float64, extra map[string]any) map[string]any {
	m := map[string]any{
		"key":           strings.ToLower(name),
		"path":          `C:\Apps\` + name + `.exe`,
		"name":          name,
		"hasIcon":       false,
		"switchable":    true,
		"reconnectable": true,
		"line":          nil,
		"rate":          map[string]any{"down": down, "up": 0},
		"lineDown":      map[string]any{},
		"sortScore":     score,
		"connections":   map[string]any{},
		"outside":       nil,
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func testState(status, mode string, lines, apps []map[string]any, combine map[string]any) map[string]any {
	if status == "" {
		status = "on"
	}
	if mode == "" {
		mode = "tun"
	}
	c := map[string]any{"on": false, "active": false, "mode": "auto"}
	for k, v := range combine {
		c[k] = v
	}
	outLines := make([]map[string]any, len(lines))
	for i, l := range lines {
		cl := cloneMap(l)
		cl["main"] = i == 0
		outLines[i] = cl
	}
	var ipv6 any
	if status == "on" {
		ipv6 = false
	}
	return map[string]any{
		"mode":       mode,
		"elevated":   true,
		"version":    "0.3.0",
		"update":     nil,
		"features":   map[string]any{"reconnect": true, "combine": true, "lines": true},
		"combine":    c,
		"routing":    map[string]any{"status": status, "wanted": status == "on" || status == "starting", "error": nil, "measuring": status == "on", "proxyPort": nil, "retryAt": nil, "ipv6": ipv6},
		"lines":      outLines,
		"candidates": []any{},
		"apps":       apps,
		"events":     []any{},
		"settings":   map[string]any{"autostart": nil, "checkForUpdates": true, "probeTargets": []string{"1.1.1.1:443", "8.8.8.8:443"}},
	}
}

func fixtureLines() (cable, wifi, phone, wifi2, cableNow, wifiNow map[string]any) {
	cable = testLine("k3f9", "Cable", map[string]any{"alias": "Ethernet", "rate": map[string]any{"down": 38 * testKB, "up": 1234}})
	wifi = testLine("p2x1", "Wi-Fi stick", map[string]any{
		"alias": "Wi-Fi 2", "ssid": "Home", "kind": "wifi", "ping": 31, "rate": map[string]any{"down": 915 * testKB, "up": 50},
	})
	phone = testLine("ph01", "Phone", map[string]any{
		"alias": "Ethernet 3", "kind": "phone", "ping": 54, "metered": true,
		"cap":   map[string]any{"bytes": 10 * testGB, "period": "month"},
		"usage": map[string]any{"bytes": 6.2 * testGB, "periodStart": "2026-10-01T00:00:00.000Z"},
		"rate":  map[string]any{"down": 120 * testKB, "up": 8 * testKB},
	})
	wifi2 = testLine("w2x9", "Wi-Fi stick 2", map[string]any{
		"alias": "Wi-Fi 3", "ssid": "Upstairs", "kind": "wifi", "ping": 27, "rate": map[string]any{"down": 300 * testKB, "up": 20 * testKB},
	})
	cableNow = cloneMap(cable)
	cableNow["rate"] = map[string]any{"down": 6098, "up": 6916}
	wifiNow = cloneMap(wifi)
	wifiNow["rate"] = map[string]any{"down": 937439, "up": 0}
	return
}

func TestTrayTooltipsAndSignatures(t *testing.T) {
	cable, wifi, phone, wifi2, cableNow, wifiNow := fixtureLines()

	routingOn := TrayFromState(testState("on", "", []map[string]any{cableNow, wifiNow}, nil, nil))
	if got, want := Tooltip(routingOn), "Net Switch: routing is on\nCable: \u2193 6 KB/s  \u2191 7 KB/s\nWi-Fi stick: \u2193 915 KB/s  \u2191 0 KB/s"; got != want {
		t.Fatalf("routingOn tooltip=%q want %q", got, want)
	}
	oneLine := TrayFromState(testState("on", "", []map[string]any{cableNow}, nil, nil))
	if got, want := Tooltip(oneLine), "Net Switch: routing is on\nCable: \u2193 6 KB/s  \u2191 7 KB/s"; got != want {
		t.Fatalf("oneLine tooltip=%q want %q", got, want)
	}
	if got := Tooltip(TrayFromState(testState("off", "", []map[string]any{cableNow, wifiNow}, nil, nil))); !strings.HasPrefix(got, "Net Switch: routing is off\n") {
		t.Fatalf("routingOff tooltip=%q", got)
	}
	if got := Tooltip(TrayFromState(testState("error", "", []map[string]any{cableNow, wifiNow}, nil, nil))); !strings.HasPrefix(got, "Net Switch: routing stopped\n") {
		t.Fatalf("stopped tooltip=%q", got)
	}
	if got := Tooltip(TrayFromState(testState("on", "proxy", []map[string]any{cableNow, wifiNow}, nil, nil))); !strings.HasPrefix(got, "Net Switch: routing is on (test mode)\n") {
		t.Fatalf("testMode tooltip=%q", got)
	}

	secondDown := TrayFromState(testState("on", "", []map[string]any{cableNow, downLine(wifi, "no internet", "k3f9")}, nil, nil))
	if !strings.HasSuffix(Tooltip(secondDown), "\nWi-Fi stick: no internet") {
		t.Fatalf("secondDown=%q", Tooltip(secondDown))
	}
	checking := TrayFromState(testState("on", "", []map[string]any{cableNow, downLine(wifi, "checking", "k3f9")}, nil, nil))
	if !strings.HasSuffix(Tooltip(checking), "\nWi-Fi stick: checking\u2026") {
		t.Fatalf("checking=%q", Tooltip(checking))
	}
	exhaustedPhone := cloneMap(phone)
	exhaustedPhone["exhausted"] = true
	exhausted := TrayFromState(testState("on", "", []map[string]any{cableNow, wifiNow, exhaustedPhone}, nil, nil))
	if !strings.HasSuffix(Tooltip(exhausted), "\nPhone: cap reached") {
		t.Fatalf("exhausted=%q", Tooltip(exhausted))
	}
	noSpeedCable := cloneMap(cableNow)
	noSpeedCable["rate"] = nil
	noSpeed := TrayFromState(testState("on", "", []map[string]any{noSpeedCable, wifiNow}, nil, nil))
	if !strings.Contains(Tooltip(noSpeed), "\nCable: speed not available\n") {
		t.Fatalf("noSpeed=%q", Tooltip(noSpeed))
	}

	fourLines := TrayFromState(testState("on", "", []map[string]any{cable, wifi, phone, wifi2}, nil, nil))
	if got, want := Tooltip(fourLines), "Net Switch: routing is on\nCable: \u2193 38 KB/s\nWi-Fi stick: \u2193 915 KB/s\nPhone: \u2193 120 KB/s\nWi-Fi stick 2: \u2193 300 KB/s"; got != want {
		t.Fatalf("fourLinesTip=%q want %q", got, want)
	}

	var six []map[string]any
	for n := 1; n <= 6; n++ {
		six = append(six, testLine("c"+string(rune('0'+n)), "Connection "+string(rune('0'+n)), nil))
	}
	sixLines := TrayFromState(testState("on", "", six, nil, nil))
	if got, want := Tooltip(sixLines), "Net Switch: routing is on\nConnection 1: \u2193 38 KB/s\nConnection 2: \u2193 38 KB/s\nConnection 3: \u2193 38 KB/s\n+3 more lines"; got != want {
		t.Fatalf("sixLines=%q want %q", got, want)
	}

	if got, want := Tooltip(UnreachableTray(true)), "Net Switch isn\u2019t responding\nClick for Open Net Switch."; got != want {
		t.Fatalf("stuck=%q want %q", got, want)
	}
	if got, want := Tooltip(UnreachableTray(false)), "Net Switch isn\u2019t running\nClick for Open Net Switch."; got != want {
		t.Fatalf("gone=%q want %q", got, want)
	}
	if got, want := Tooltip(QuittingTray()), "Net Switch is quitting\u2026"; got != want {
		t.Fatalf("quitting=%q want %q", got, want)
	}

	longLine := testLine("rt", "Realtek USB GbE Family Controller #2", map[string]any{"rate": map[string]any{"down": 123456789, "up": 123456789}})
	longLabel := TrayFromState(testState("stopping", "", []map[string]any{cableNow, longLine}, nil, nil))
	longTip := Tooltip(longLabel)
	if utf16Len(longTip) > MaxTip {
		t.Fatalf("longLabel len=%d > %d", utf16Len(longTip), MaxTip)
	}
	if !strings.HasPrefix(longTip, "Net Switch: turning off routing\u2026\n") || !strings.HasSuffix(longTip, "\nRealtek USB GbE F\u2026: \u2193 117.7 MB/s  \u2191 117.7 MB/s") {
		t.Fatalf("longTip=%q", longTip)
	}

	uploadOnly := TrayFromState(testState("on", "", []map[string]any{cableNow, testLine("ph", "Phone", map[string]any{"rate": map[string]any{"down": 0, "up": 2000000}})}, nil, nil))
	threeLines := TrayFromState(testState("on", "", []map[string]any{cableNow, wifiNow, testLine("ph", "Phone", map[string]any{"rate": map[string]any{"down": 120 * testKB, "up": 8 * testKB}})}, nil, nil))

	if got := IconSignature(routingOn); got != "on|True1|True4" {
		t.Fatalf("routingOn sig=%q", got)
	}
	if got := IconSignature(uploadOnly); got != "on|True1|True4" {
		t.Fatalf("uploadOnly sig=%q", got)
	}
	if got := IconSignature(noSpeed); got != "on|True0|True4" {
		t.Fatalf("noSpeed sig=%q", got)
	}
	if got := IconSignature(oneLine); got != "on|True1|False0" {
		t.Fatalf("oneLine sig=%q", got)
	}
	if got := IconSignature(secondDown); got != "on|True1|False0" {
		t.Fatalf("secondDown sig=%q", got)
	}
	if got := IconSignature(threeLines); got != "on|True1|True4|True3" {
		t.Fatalf("threeLines sig=%q", got)
	}
	if got := len(strings.Split(IconSignature(sixLines), "|")); got != 4 {
		t.Fatalf("sixLines sig parts=%d", got)
	}
	if got := IconSignature(UnreachableTray(true)); got != "off|False0|False0" {
		t.Fatalf("stuck sig=%q", got)
	}
}

func TestRatesAndLitMeters(t *testing.T) {
	cases := []struct {
		v    float64
		text string
		lit  int
	}{
		{0, "0 KB/s", 0},
		{1000, "<1 KB/s", 1},
		{1024, "1 KB/s", 1},
		{1048575, "1024 KB/s", 4},
		{1048576, "1.0 MB/s", 4},
		{10 * 1048576, "10.0 MB/s", 5},
	}
	for _, tc := range cases {
		if Rate(tc.v) != tc.text || Lit(tc.v) != tc.lit {
			t.Fatalf("rate(%v) = (%q, %d) want (%q, %d)", tc.v, Rate(tc.v), Lit(tc.v), tc.text, tc.lit)
		}
	}
	if got := []int{FlyoutLit(0), FlyoutLit(1024), FlyoutLit(1024 * 1024), FlyoutLit(10 * 1024 * 1024)}; !reflect.DeepEqual(got, []int{0, 1, 18, 24}) {
		t.Fatalf("FlyoutLit=%v", got)
	}
}

func TestFlyoutStatesAndUsageError(t *testing.T) {
	cable, wifi, phone, wifi2, _, _ := fixtureLines()
	busy := []map[string]any{
		testApp("Steam", 2600*testKB, 2600*testKB, nil),
		testApp("Firefox", 640*testKB, 640*testKB, map[string]any{"line": "p2x1"}),
		testApp("Discord", 14*testKB, 14*testKB, nil),
		testApp("Spotify", 160*testKB, 160*testKB, map[string]any{"line": "ph01"}),
	}

	one := FlyoutFromState(testState("on", "", []map[string]any{cable}, busy[:3], nil))
	if len(one.Lines) != 1 || one.Lines[0].Main || one.Lines[0].Detail != "Ethernet \u00b7 18 ms" || one.Lines[0].Speed != "38 KB/s" || one.Health != "Cable reaches the internet" {
		t.Fatalf("oneLine mismatch: %+v", one)
	}
	if len(one.Options) != 1 || one.CanCombine || one.CombineDetail != "Add a second line" {
		t.Fatalf("oneLine combine mismatch: %+v", one)
	}

	two := FlyoutFromState(testState("on", "", []map[string]any{cable, wifi}, busy[:3], nil))
	if two.Status != "Routing on \u00b7 953 KB/s" || two.Tone != "ok" || !two.Lines[0].Main || two.Lines[1].Detail != "Wi-Fi 2 \u00b7 Home \u00b7 31 ms" || two.Lines[1].Lit != 18 || two.Health != "Both lines reach the internet" || two.HealthTone != "ok" {
		t.Fatalf("twoLines mismatch: %+v", two)
	}
	if !two.CompactChoice || len(two.Options) != 2 || two.Options[0].Send != nil || *two.Options[1].Send != "p2x1" {
		t.Fatalf("twoLines options mismatch: %+v", two.Options)
	}
	if len(two.Apps) != 3 || *two.Apps[0].Choice != "k3f9" || *two.Apps[1].Choice != "p2x1" || *two.Apps[2].Choice != "k3f9" {
		t.Fatalf("twoLines apps mismatch: %+v", two.Apps)
	}

	four := FlyoutFromState(testState("on", "", []map[string]any{cable, wifi, phone, wifi2}, busy, nil))
	if len(four.Lines) != 3 || four.MoreLines != 1 || !four.Lines[2].Metered || four.Lines[2].Detail != "6.2 GB of 10 GB \u00b7 54 ms" || !strings.Contains(four.Lines[2].Tip, "6.2 GB of 10 GB this month") || four.Health != "All 4 lines reach the internet" || four.CombineName != "Combine lines" || four.CompactChoice || len(four.Options) != 4 {
		t.Fatalf("fourLines mismatch: %+v", four)
	}

	lineDown := FlyoutFromState(testState("on", "", []map[string]any{cable, downLine(wifi, "no internet", "k3f9")}, busy[:3], nil))
	if lineDown.Tone != "warning" || lineDown.HealthTone != "warning" || lineDown.Health != "Wi-Fi stick: no internet \u00b7 its apps use the Cable" || lineDown.Lines[1].Note != "Its apps use the Cable until it\u2019s back" {
		t.Fatalf("lineDown mismatch: %+v", lineDown)
	}

	mainDown := FlyoutFromState(testState("on", "", []map[string]any{downLine(cable, "no address", "p2x1"), wifi}, busy[:3], nil))
	if mainDown.Lines[0].Health != "No address" || mainDown.Lines[0].Tone != "down" || mainDown.Health != "Cable: no address \u00b7 apps use the Wi-Fi stick" {
		t.Fatalf("mainDown mismatch: %+v", mainDown)
	}

	checking := FlyoutFromState(testState("on", "", []map[string]any{cable, downLine(wifi, "checking", "k3f9")}, busy[:3], nil))
	if checking.Lines[1].Health != "Checking\u2026" || checking.Health != "Wi-Fi stick: checking \u00b7 its apps use the Cable" {
		t.Fatalf("checking mismatch: %+v", checking)
	}

	cappedPhone := cloneMap(phone)
	cappedPhone["usage"] = map[string]any{"bytes": 10.3 * testGB, "periodStart": "2026-10-01T00:00:00.000Z"}
	cappedPhone["exhausted"] = true
	cappedPhone["carrying"] = false
	cappedPhone["target"] = "k3f9"
	cappedPhone["rate"] = map[string]any{"down": 0, "up": 0}
	capped := FlyoutFromState(testState("on", "", []map[string]any{cable, wifi, cappedPhone}, busy[:3], nil))
	if capped.Lines[2].Health != "Cap reached" || capped.Lines[2].Detail != "10.3 GB of 10 GB" || capped.Lines[2].Note != "Its apps use the Cable until the cap resets" || !reflect.DeepEqual(capped.SharingColors, []int{0, 1}) || !capped.CanCombine {
		t.Fatalf("capped mismatch: %+v", capped)
	}

	combining := FlyoutFromState(testState("on", "", []map[string]any{cable, wifi}, []map[string]any{
		testApp("Steam", 2600*testKB, 2600*testKB, nil),
		testApp("Firefox", 640*testKB, 640*testKB, map[string]any{"line": "p2x1"}),
		testApp("Discord", 14*testKB, 14*testKB, map[string]any{"line": "k3f9"}),
	}, map[string]any{"on": true, "active": true}))
	if !combining.CombineOn || combining.CombineDetail != "Combining" || len(combining.Options) != 3 || !combining.Options[0].Shared || combining.Apps[0].Choice != nil || *combining.Apps[1].Choice != "p2x1" {
		t.Fatalf("combining mismatch: %+v", combining)
	}

	off := FlyoutFromState(testState("off", "", []map[string]any{cable, wifi}, nil, nil))
	if off.Status != "Routing off \u00b7 953 KB/s" || off.Tone != "dim" || off.RoutingWanted || off.Health != "Routing is off \u00b7 apps use Windows' connection" || off.Lines[0].Detail != "Ethernet \u00b7 Online" {
		t.Fatalf("routingOff mismatch: %+v", off)
	}

	unavail := FlyoutFromState(nil)
	if unavail.Available || unavail.Message != "Net Switch isn\u2019t responding." || len(unavail.Apps) != 0 || len(unavail.Lines) != 0 {
		t.Fatalf("unavailable mismatch: %+v", unavail)
	}

	// Approved usageError flyout contract: healthy green header dot, dim (i) info footer.
	resetState := testState("on", "", []map[string]any{cable, wifi}, busy[:3], nil)
	resetState["usageError"] = "Corrupt usage history preserved as usage.json.corrupt-123; accounting continues: bad json"
	resetView := FlyoutFromState(resetState)
	if resetView.Tone != "ok" || resetView.HealthTone != "info" || resetView.Health != "Saved data use was reset" {
		t.Fatalf("usage reset view mismatch: tone=%q healthTone=%q health=%q", resetView.Tone, resetView.HealthTone, resetView.Health)
	}

	writeFailState := testState("on", "", []map[string]any{cable, wifi}, busy[:3], nil)
	writeFailState["usageError"] = "Usage history unavailable; routing continues: access denied"
	writeFailView := FlyoutFromState(writeFailState)
	if writeFailView.Tone != "ok" || writeFailView.HealthTone != "info" || writeFailView.Health != "Can\u2019t save data use right now" {
		t.Fatalf("usage write fail view mismatch: tone=%q healthTone=%q health=%q", writeFailView.Tone, writeFailView.HealthTone, writeFailView.Health)
	}

	// Higher-severity line problem keeps warning tone and line message over usageError.
	bothState := testState("on", "", []map[string]any{cable, downLine(wifi, "no internet", "k3f9")}, busy[:3], nil)
	bothState["usageError"] = "Usage history unavailable; routing continues: disk full"
	bothView := FlyoutFromState(bothState)
	if bothView.Tone != "warning" || bothView.HealthTone != "warning" || !strings.Contains(bothView.Health, "no internet") {
		t.Fatalf("line warning should outrank usageError: %+v", bothView)
	}
}

func TestUpdateOfferAndSettingsAndNotifier(t *testing.T) {
	offered := UpdateOffer(map[string]any{"update": map[string]any{
		"version":   "0.3.0",
		"installer": "https://github.com/AyoubAchour/net-switch/releases/download/v0.3.0/NetSwitch-Setup-0.3.0-x64.exe",
	}})
	if offered == nil || offered[0] != "0.3.0" {
		t.Fatalf("offered=%v", offered)
	}
	if UpdateOffer(map[string]any{"update": map[string]any{"version": "0.3.0", "installer": "https://example.com/setup.exe"}}) != nil {
		t.Fatal("accepted non-release installer URL")
	}
	if UpdateOffer(map[string]any{"update": nil}) != nil {
		t.Fatal("accepted nil update")
	}

	dir := t.TempDir()
	damaged := filepath.Join(dir, "damaged.json")
	if err := os.WriteFile(damaged, []byte("{ not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if !LoadTraySettings(filepath.Join(dir, "missing.json")).LineNotifications {
		t.Fatal("missing settings should default true")
	}
	if !LoadTraySettings(damaged).LineNotifications {
		t.Fatal("damaged settings should default true")
	}
	savedFile := filepath.Join(dir, "tray-settings.json")
	if err := (TraySettings{LineNotifications: false}).Save(savedFile); err != nil {
		t.Fatal(err)
	}
	if LoadTraySettings(savedFile).LineNotifications {
		t.Fatal("saved false did not reload as false")
	}

	evt := func(id, kind, lineID, text string) LineEvent {
		return LineEvent{ID: id, Kind: kind, LineID: lineID, Text: text}
	}
	e1 := evt("e1", "down", "p2x1", "Wi-Fi stick is down: it doesn\u2019t reach the internet.")
	e2 := evt("e2", "up", "p2x1", "Wi-Fi stick is back.")
	e3 := evt("e3", "down", "ph01", "Phone is down: it isn\u2019t connected.")
	e4 := evt("e4", "down", "p2x1", "Wi-Fi stick is down: it doesn\u2019t reach the internet.")
	e5 := evt("e5", "up", "p2x1", "Wi-Fi stick is back.")
	e6 := evt("e6", "down", "p2x1", "Wi-Fi stick is down: it doesn\u2019t reach the internet.")
	e7 := evt("e7", "up", "p2x1", "Wi-Fi stick is back.")
	e8 := evt("e8", "down", "ph01", "Phone is down: it isn\u2019t connected.")
	e9 := evt("e9", "cap-reset", "ph01", "Phone can be used again: its data cap has reset.")

	steps := map[int]struct {
		enabled bool
		events  []LineEvent
	}{
		0:  {true, []LineEvent{e1, e2}},
		5:  {true, []LineEvent{e1, e2, e3}},
		6:  {true, []LineEvent{e1, e2, e3, e4}},
		12: {true, []LineEvent{e1, e2, e3, e4, e5}},
		14: {true, []LineEvent{e1, e2, e3, e4, e5, e6}},
		16: {true, []LineEvent{e1, e2, e3, e4, e5, e6, e7}},
		50: {false, []LineEvent{e1, e2, e3, e4, e5, e6, e7, e8}},
		60: {true, []LineEvent{e1, e2, e3, e4, e5, e6, e7, e8}},
		70: {true, []LineEvent{e1, e2, e3, e4, e5, e6, e7, e8, e9}},
	}
	var notifier EventNotifier
	start := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	type gotNotice struct {
		At      int
		ID      string
		Title   string
		Warning bool
	}
	var shown []gotNotice
	var cur *struct {
		enabled bool
		events  []LineEvent
	}
	for sec := 0; sec <= 80; sec++ {
		if s, ok := steps[sec]; ok {
			copyStep := s
			cur = &copyStep
		}
		if cur != nil {
			notifier.Read(cur.events, true, cur.enabled)
		}
		if n := notifier.Next(start.Add(time.Duration(sec) * time.Second)); n != nil {
			shown = append(shown, gotNotice{At: sec, ID: n.EventID, Title: n.Title, Warning: n.Warning})
		}
	}
	want := []gotNotice{
		{5, "e3", "Line down", true},
		{9, "e4", "Line down", true},
		{39, "e7", "Line back", false},
		{70, "e9", "Data cap reset", false},
	}
	if !reflect.DeepEqual(shown, want) {
		t.Fatalf("notifier shown=%+v want %+v", shown, want)
	}
}

func TestClientRefreshesTokenOn401AndRejectsNonLoopback(t *testing.T) {
	if _, err := NewClient("http://example.com:47821", "tok"); err == nil {
		t.Fatal("accepted non-loopback control URL")
	}

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		tok := r.Header.Get("X-Token")
		if n == 1 && tok == "stale" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if tok != "fresh" {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"routing": map[string]any{"status": "on"}})
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL, "stale")
	if err != nil {
		t.Fatal(err)
	}
	c.SetUnauthorizedHook(func(context.Context) (string, bool) {
		return "fresh", true
	})
	st, err := c.FetchState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if textVal(childMap(st, "routing"), "status") != "on" {
		t.Fatalf("unexpected state: %+v", st)
	}
	if calls.Load() != 2 {
		t.Fatalf("expected 1 retry after 401 refresh, got %d calls", calls.Load())
	}
}

func TestPaintIconNRGBAAndPNG(t *testing.T) {
	v := TrayFromState(testState("on", "tun", []map[string]any{
		testLine("a", "Fiber", map[string]any{"main": true, "rate": map[string]any{"down": 5 * testMB, "up": 0}}),
		testLine("b", "LTE", map[string]any{"rate": map[string]any{"down": 0, "up": 0}}),
	}, nil, nil))
	for _, size := range []int{16, 24, 32, 64} {
		img := PaintIconNRGBA(v, size)
		if img.Bounds().Dx() != size || img.Bounds().Dy() != size {
			t.Fatalf("unexpected icon size %v for %d", img.Bounds(), size)
		}
		if corner := img.NRGBAAt(0, 0); corner.A != 0 {
			t.Fatalf("expected transparent rounded corner at size %d, got %+v", size, corner)
		}
		center := img.NRGBAAt(size/2, size/2)
		if center != iconPanel {
			t.Fatalf("expected panel background at center (%d), got %+v", size, center)
		}
		data, err := PaintIconPNG(v, size)
		if err != nil || len(data) < 8 || string(data[:4]) != "\x89PNG" {
			t.Fatalf("invalid PNG at size %d: err=%v len=%d", size, err, len(data))
		}
	}
}
