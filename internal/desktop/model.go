// Package desktop implements the shared model, flyout state, notifications,
// settings, HTTP client, and single-instance coordination for the native Net
// Switch desktop app.
package desktop

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
)

// UICallbacks wires lifecycle actions from a platform UI shell back to Control.
type UICallbacks struct {
	OpenPair       func(ctx context.Context) (pairURL, code, owner string, err error)
	RefreshToken   func(ctx context.Context) (string, bool)
	ToggleRouting  func(wantOn bool)
	ToggleCombine  func(wantOn bool)
	SetAppLine     func(appPath string, line *string)
	DismissUpdate  func(version string)
	Quit           func()
	FallbackStatus func(text string) error
}

// UI represents a platform-native tray, flyout, and window controller.
type UI interface {
	SetSession(baseURL, token, owner string)
	ShowWindow(appKey string)
	UpdateState(raw map[string]any, reachable bool)
	SetActionFeedback(pendingKey, errMsg string)
	SetQuitting()
	Notify(title, body string, warning bool)
	Close()
}

// NoopUI is a headless no-op implementation of UI.
type NoopUI struct{}

func (NoopUI) SetSession(string, string, string) {}
func (NoopUI) ShowWindow(string)                 {}
func (NoopUI) UpdateState(map[string]any, bool)  {}
func (NoopUI) SetActionFeedback(string, string)  {}
func (NoopUI) SetQuitting()                      {}
func (NoopUI) Notify(string, string, bool)       {}
func (NoopUI) Close()                            {}

const (
	TrayCells       = 5
	MaxTip          = 127
	MaxTrayRows     = 3
	PaletteSize     = 6
	MaxLabel        = 18
	MaxBriefLabel   = 14
	InstallerPrefix = "https://github.com/AyoubAchour/net-switch/releases/download/"
)

// LineView is a summarized line row rendered in the tray icon and tooltip.
type LineView struct {
	Label    string
	Color    int
	Working  bool
	Problem  string
	Measured bool
	Down     float64
	Up       float64
}

// TrayView describes what the tray icon and its tooltip show at one moment.
type TrayView struct {
	Status  string
	Hint    string
	Routing bool
	Lines   []LineView
}

// IconRow describes one horizontal meter row inside the tray icon.
type IconRow struct {
	Available bool
	Lit       int
}

var trayStatuses = map[string]string{
	"on":       "Net Switch: routing is on",
	"starting": "Net Switch: starting routing\u2026",
	"stopping": "Net Switch: turning off routing\u2026",
	"off":      "Net Switch: routing is off",
	"error":    "Net Switch: routing stopped",
}

// UpdateOffer returns [version, installerURL] when state offers a verified
// Net Switch release installer URL, or nil otherwise.
func UpdateOffer(state map[string]any) *[2]string {
	update := childMap(state, "update")
	version := textVal(update, "version")
	installer := textVal(update, "installer")
	if version == "" || installer == "" {
		return nil
	}
	if !strings.HasPrefix(installer, InstallerPrefix) {
		return nil
	}
	return &[2]string{version, installer}
}

// WaitingTray returns the initial tray view before Control responds.
func WaitingTray() TrayView {
	return TrayView{Status: "Net Switch"}
}

// UnreachableTray returns the tray view shown when Control is unavailable.
func UnreachableTray(processRunning bool) TrayView {
	status := "Net Switch isn\u2019t running"
	if processRunning {
		status = "Net Switch isn\u2019t responding"
	}
	return TrayView{
		Status: status,
		Hint:   "Click for Open Net Switch.",
	}
}

// QuittingTray returns the tray view shown while Net Switch shuts down.
func QuittingTray() TrayView {
	return TrayView{Status: "Net Switch is quitting\u2026"}
}

// TrayFromState builds a TrayView from a /api/state JSON object.
func TrayFromState(state map[string]any) TrayView {
	routing := childMap(state, "routing")
	status := textVal(routing, "status")
	headline, ok := trayStatuses[status]
	if !ok {
		headline = "Net Switch"
	}
	if textVal(state, "mode") == "proxy" {
		headline += " (test mode)"
	}
	view := TrayView{
		Status:  headline,
		Routing: status == "on",
	}
	items := stateLines(state)
	view.Lines = make([]LineView, 0, len(items))
	for i, line := range items {
		view.Lines = append(view.Lines, trayLineView(line, i, view.Routing))
	}
	return view
}

func trayLineView(line map[string]any, index int, routingOn bool) LineView {
	health, tone := LineHealth(line, routingOn)
	problem := ""
	if tone != "ok" {
		problem = health
	}
	rate := childMap(line, "rate")
	return LineView{
		Label:    LineLabel(line, index),
		Color:    index % PaletteSize,
		Working:  flagVal(line, "connected") && textVal(line, "problem") == "",
		Problem:  problem,
		Measured: rate != nil,
		Down:     numberVal(rate, "down"),
		Up:       numberVal(rate, "up"),
	}
}

// LineHealth matches ui/app.js lineHealth and returns the text and tone
// ("ok", "warn", or "down").
func LineHealth(line map[string]any, routingOn bool) (string, string) {
	problem := textVal(line, "problem")
	if problem == "checking" {
		return "Checking\u2026", "warn"
	}
	if problem == "no internet" {
		return "No internet", "warn"
	}
	if problem != "" {
		if problem == "no address" {
			return "No address", "down"
		}
		return "No route", "down"
	}
	if !flagVal(line, "connected") {
		return "Not connected", "down"
	}
	if flagVal(line, "exhausted") {
		return "Cap reached", "warn"
	}
	if routingOn && line != nil {
		if raw, ok := line["ping"]; ok && isNumber(raw) {
			return fmt.Sprintf("%.0f ms", roundAwayFromZero(numberVal(line, "ping"))), "ok"
		}
	}
	return "Online", "ok"
}

// Tooltip builds the tray tooltip clamped to Windows' 127-character limit.
func Tooltip(view TrayView) string {
	tip, complete := formatTooltip(view, false)
	if !complete {
		tip, _ = formatTooltip(view, true)
	}
	return clampUTF16(tip, MaxTip)
}

func formatTooltip(view TrayView, brief bool) (string, bool) {
	lines := []string{view.Status}
	if view.Hint != "" {
		lines = append(lines, view.Hint)
	}
	length := utf16Len(strings.Join(lines, "\n"))
	count := len(view.Lines)
	complete := true
	for i := 0; i < count; i++ {
		text := TrayLineText(view.Lines[i], brief)
		rest := count - i - 1
		needed := 1 + utf16Len(text)
		if rest > 0 {
			needed += 1 + utf16Len(moreLinesText(rest))
		}
		if length+needed > MaxTip {
			lines = append(lines, moreLinesText(count-i))
			complete = false
			break
		}
		lines = append(lines, text)
		length += 1 + utf16Len(text)
	}
	return strings.Join(lines, "\n"), complete
}

func moreLinesText(count int) string {
	if count == 1 {
		return "+1 more line"
	}
	return fmt.Sprintf("+%d more lines", count)
}

// TrayLineText formats a single line's tooltip summary.
func TrayLineText(line LineView, brief bool) string {
	maxLen := MaxLabel
	if brief {
		maxLen = MaxBriefLabel
	}
	label := Shorten(line.Label, maxLen)
	if line.Problem != "" {
		return label + ": " + LowerFirst(line.Problem)
	}
	if !line.Measured {
		if brief {
			return label + ": no speed"
		}
		return label + ": speed not available"
	}
	if brief {
		return label + ": \u2193 " + Rate(line.Down)
	}
	return label + ": \u2193 " + Rate(line.Down) + "  \u2191 " + Rate(line.Up)
}

// Rate formats bytes per second matching ui/app.js formatRate.
func Rate(bytesPerSecond float64) string {
	if !(bytesPerSecond >= 1) || math.IsNaN(bytesPerSecond) || math.IsInf(bytesPerSecond, 0) {
		return "0 KB/s"
	}
	if bytesPerSecond < 1024 {
		return "<1 KB/s"
	}
	if bytesPerSecond < 1024*1024 {
		return fmt.Sprintf("%.0f KB/s", roundAwayFromZero(bytesPerSecond/1024))
	}
	return fmt.Sprintf("%.1f MB/s", bytesPerSecond/1024/1024)
}

// Lit returns the number of lit cells (0..5) on the tray icon logarithmic scale.
func Lit(bytesPerSecond float64) int {
	if !(bytesPerSecond >= 1) || math.IsNaN(bytesPerSecond) || math.IsInf(bytesPerSecond, 0) {
		return 0
	}
	level := math.Log10(bytesPerSecond/1024) / math.Log10(10*1024)
	lit := int(roundAwayFromZero(level * TrayCells))
	if lit < 1 {
		return 1
	}
	if lit > TrayCells {
		return TrayCells
	}
	return lit
}

// TrayRowState computes availability and lit cells for a line row.
func TrayRowState(line *LineView) IconRow {
	if line == nil || !line.Working {
		return IconRow{}
	}
	lit := 0
	if line.Measured {
		lit = Lit(line.Down + line.Up)
	}
	return IconRow{Available: true, Lit: lit}
}

// TrayRows returns the 2 or 3 meter rows rendered inside the tray icon.
func TrayRows(view TrayView) []IconRow {
	count := len(view.Lines)
	if count < 2 {
		count = 2
	}
	if count > MaxTrayRows {
		count = MaxTrayRows
	}
	rows := make([]IconRow, count)
	for i := 0; i < count; i++ {
		if i < len(view.Lines) {
			l := view.Lines[i]
			rows[i] = TrayRowState(&l)
		} else {
			rows[i] = IconRow{}
		}
	}
	return rows
}

// IconSignature changes only when the tray icon bitmap needs redrawing.
func IconSignature(view TrayView) string {
	var b strings.Builder
	if view.Routing {
		b.WriteString("on")
	} else {
		b.WriteString("off")
	}
	for _, row := range TrayRows(view) {
		b.WriteByte('|')
		if row.Available {
			b.WriteString("True")
		} else {
			b.WriteString("False")
		}
		b.WriteString(strconv.Itoa(row.Lit))
	}
	return b.String()
}

// LineLabel returns the user label, falling back to adapter alias or "Line N".
func LineLabel(line map[string]any, index int) string {
	label := strings.TrimSpace(textVal(line, "label"))
	if label == "" {
		label = strings.TrimSpace(textVal(line, "alias"))
	}
	if label != "" {
		return label
	}
	return "Line " + strconv.Itoa(index+1)
}

// Shorten trims and truncates text with an ellipsis without trailing spaces before "…".
func Shorten(text string, maxRunes int) string {
	text = strings.TrimSpace(text)
	if utf16Len(text) <= maxRunes {
		return text
	}
	runes := []rune(text)
	if maxRunes <= 1 {
		return "\u2026"
	}
	var out []rune
	units := 0
	for _, r := range runes {
		u := utf16.RuneLen(r)
		if u < 0 {
			u = 1
		}
		if units+u > maxRunes-1 {
			break
		}
		out = append(out, r)
		units += u
	}
	return strings.TrimRightFunc(string(out), unicode.IsSpace) + "\u2026"
}

// LowerFirst lowercases only the leading rune of text.
func LowerFirst(text string) string {
	if text == "" {
		return text
	}
	runes := []rune(text)
	runes[0] = unicode.ToLower(runes[0])
	return string(runes)
}

func roundAwayFromZero(v float64) float64 {
	if v < 0 {
		return math.Ceil(v - 0.5)
	}
	return math.Floor(v + 0.5)
}

func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		l := utf16.RuneLen(r)
		if l < 0 {
			l = 1
		}
		n += l
	}
	return n
}

func clampUTF16(s string, maxUnits int) string {
	if utf16Len(s) <= maxUnits {
		return s
	}
	limit := maxUnits - 1
	var out []rune
	units := 0
	for _, r := range s {
		l := utf16.RuneLen(r)
		if l < 0 {
			l = 1
		}
		if units+l > limit {
			break
		}
		out = append(out, r)
		units += l
	}
	return string(out) + "\u2026"
}

func stateLines(state map[string]any) []map[string]any {
	return itemMaps(state, "lines")
}

func itemMaps(parent map[string]any, key string) []map[string]any {
	if parent == nil {
		return nil
	}
	raw, ok := parent[key]
	if !ok || raw == nil {
		return nil
	}
	var items []map[string]any
	switch typed := raw.(type) {
	case []any:
		for _, item := range typed {
			if m, ok := item.(map[string]any); ok {
				items = append(items, m)
			}
		}
	case []map[string]any:
		items = append(items, typed...)
	}
	return items
}

func childMap(parent map[string]any, key string) map[string]any {
	if parent == nil {
		return nil
	}
	v, ok := parent[key]
	if !ok || v == nil {
		return nil
	}
	m, _ := v.(map[string]any)
	return m
}

func textVal(parent map[string]any, key string) string {
	if parent == nil {
		return ""
	}
	v, ok := parent[key]
	if !ok || v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

func hasStringVal(parent map[string]any, key string) (string, bool) {
	if parent == nil {
		return "", false
	}
	v, ok := parent[key]
	if !ok || v == nil {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func flagVal(parent map[string]any, key string) bool {
	if parent == nil {
		return false
	}
	v, ok := parent[key]
	if !ok || v == nil {
		return false
	}
	b, _ := v.(bool)
	return b
}

func optionalFlag(parent map[string]any, key string, fallback bool) bool {
	if parent == nil {
		return fallback
	}
	v, ok := parent[key]
	if !ok || v == nil {
		return fallback
	}
	b, ok := v.(bool)
	if !ok {
		return fallback
	}
	return b
}

func isNumber(v any) bool {
	switch v.(type) {
	case int, int32, int64, uint, uint32, uint64, float32, float64:
		return true
	default:
		return false
	}
}

func numberVal(parent map[string]any, key string) float64 {
	if parent == nil {
		return 0
	}
	v, ok := parent[key]
	if !ok || v == nil {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return n
	case float32:
		return float64(n)
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case int32:
		return float64(n)
	case uint64:
		return float64(n)
	case uint:
		return float64(n)
	case uint32:
		return float64(n)
	default:
		return 0
	}
}
