package desktop

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	FlyoutMaxLines       = 3
	FlyoutMaxOptions     = 3
	FlyoutMaxOptionLabel = 12
	FlyoutMeterCells     = 24
	byteMB               = 1024.0 * 1024.0
	byteGB               = 1024.0 * byteMB
)

// FlyoutLine describes one line row inside the tray flyout.
type FlyoutLine struct {
	ID      string
	Name    string
	Color   int
	Main    bool
	Metered bool
	Health  string
	Tone    string
	Healthy bool
	Detail  string
	Note    string
	StandIn string
	Speed   string
	Down    float64
	Lit     int
	Tip     string
}

// FlyoutOption describes one routing option for an app in the flyout.
type FlyoutOption struct {
	Value  string
	HasVal bool
	Send   *string
	Label  string
	Name   string
	Color  int
	Shared bool
}

// FlyoutApp describes one running/active app row inside the tray flyout.
type FlyoutApp struct {
	Name       string
	Path       string
	Identity   string
	Choice     *string
	Speed      string
	Initial    string
	ColorIndex int
	CanMove    bool
	Score      float64
	HasTraffic bool
}

// FlyoutView holds the complete pre-computed view rendered by the tray flyout.
type FlyoutView struct {
	Available     bool
	Message       string
	Status        string
	Tone          string
	TotalDown     float64
	RoutingWanted bool
	CombineOn     bool
	CanCombine    bool
	CombineName   string
	CombineDetail string
	Health        string
	HealthTone    string
	Lines         []FlyoutLine
	MoreLines     int
	SharingColors []int
	Options       []FlyoutOption
	CompactChoice bool
	Apps          []FlyoutApp
}

// UnavailableFlyout builds the disconnected view when Control cannot be reached.
func UnavailableFlyout(message string) FlyoutView {
	return FlyoutView{
		Available: false,
		Message:   message,
		Status:    "Not connected",
		Tone:      "dim",
		Lines:     []FlyoutLine{},
		Apps:      []FlyoutApp{},
	}
}

// FlyoutFromState builds the flyout model from a /api/state response.
func FlyoutFromState(state map[string]any) FlyoutView {
	if state == nil {
		return UnavailableFlyout("Net Switch isn\u2019t responding.")
	}
	routing := childMap(state, "routing")
	status := textVal(routing, "status")
	if status == "" {
		status = "off"
	}
	routingOn := status == "on"
	lines := stateLines(state)

	view := FlyoutView{
		Available:     true,
		RoutingWanted: optionalFlag(routing, "wanted", routingOn),
	}

	names := make(map[string]string, len(lines))
	for i, line := range lines {
		if id, ok := hasStringVal(line, "id"); ok {
			if _, exists := names[id]; !exists {
				names[id] = LineLabel(line, i)
			}
		}
	}

	all := make([]FlyoutLine, 0, len(lines))
	for i, line := range lines {
		row := buildFlyoutLine(line, i, len(lines), routingOn, names)
		view.TotalDown += row.Down
		all = append(all, row)
	}
	limit := FlyoutMaxLines
	if len(all) < limit {
		limit = len(all)
	}
	view.Lines = append([]FlyoutLine{}, all[:limit]...)
	view.MoreLines = len(all) - len(view.Lines)

	combine := childMap(state, "combine")
	combining := flagVal(combine, "on") && len(lines) > 1
	active := combining && flagVal(combine, "active")
	for i, line := range lines {
		if !flagVal(line, "strict") && !flagVal(line, "exhausted") {
			view.SharingColors = append(view.SharingColors, i%PaletteSize)
		}
	}
	view.CombineOn = combining
	view.CanCombine = combining || len(view.SharingColors) >= 2
	if len(lines) == 2 {
		view.CombineName = "Both lines"
	} else {
		view.CombineName = "Combine lines"
	}
	switch {
	case combining && !routingOn:
		view.CombineDetail = "On"
	case combining && active:
		view.CombineDetail = "Combining"
	case combining:
		view.CombineDetail = "Paused"
	case view.CanCombine:
		view.CombineDetail = "Off"
	case len(lines) < 2:
		view.CombineDetail = "Add a second line"
	default:
		view.CombineDetail = "Needs two lines"
	}

	headline := "Routing off"
	switch status {
	case "on":
		headline = "Routing on"
	case "starting":
		headline = "Starting routing\u2026"
	case "stopping":
		headline = "Turning routing off\u2026"
	case "error":
		headline = "Routing stopped"
	}
	view.Status = headline + " \u00b7 " + Rate(view.TotalDown)
	switch status {
	case "on":
		view.Tone = "ok"
	case "error":
		view.Tone = "error"
	default:
		view.Tone = "dim"
	}
	computeFlyoutHealth(&view, status, all)
	// Header dot reflects line problems, matching the window's top bar.
	if status == "on" && view.HealthTone != "ok" {
		view.Tone = view.HealthTone
	}
	// Quiet usage notice shown only in the footer when routing & lines are healthy;
	// never promotes the header status dot to a warning.
	if usageErr := textVal(state, "usageError"); usageErr != "" && view.HealthTone == "ok" {
		view.HealthTone = "info"
		if strings.HasPrefix(usageErr, "Corrupt usage history") {
			view.Health = "Saved data use was reset"
		} else {
			view.Health = "Can\u2019t save data use right now"
		}
	}

	var mainID *string
	if len(lines) > 0 {
		if id, ok := hasStringVal(lines[0], "id"); ok {
			mainID = strPtr(id)
		}
	}
	if combining {
		view.Options = append(view.Options, FlyoutOption{
			Label:  "Shared",
			Name:   "Shared",
			Color:  -1,
			Shared: true,
		})
	}
	for i, line := range lines {
		id, ok := hasStringVal(line, "id")
		if !ok {
			continue
		}
		name := LineLabel(line, i)
		var send *string
		if !(!combining && mainID != nil && id == *mainID) {
			send = strPtr(id)
		}
		view.Options = append(view.Options, FlyoutOption{
			Value:  id,
			HasVal: true,
			Send:   send,
			Label:  Shorten(name, FlyoutMaxOptionLabel),
			Name:   name,
			Color:  i % PaletteSize,
		})
	}
	view.CompactChoice = len(view.Options) <= FlyoutMaxOptions

	for _, app := range itemMaps(state, "apps") {
		rate := childMap(app, "rate")
		name := textVal(app, "name")
		if strings.TrimSpace(name) == "" {
			name = "App"
		}
		path := textVal(app, "path")
		identity := textVal(app, "identity")
		if identity == "" {
			identity = path
		}
		var pinned *string
		if rawPinned, ok := hasStringVal(app, "line"); ok {
			if _, exists := names[rawPinned]; exists {
				pinned = strPtr(rawPinned)
			}
		}
		choice := pinned
		if !combining && choice == nil {
			choice = mainID
		}
		down := numberVal(rate, "down")
		up := numberVal(rate, "up")
		var hash uint32
		for _, r := range utf8RunesOrUTF16(name) {
			hash = hash*31 + uint32(r)
		}
		row := FlyoutApp{
			Name:       name,
			Path:       path,
			Identity:   identity,
			Choice:     choice,
			Speed:      Rate(down),
			Score:      numberVal(app, "sortScore"),
			HasTraffic: down+up > 0,
			CanMove:    optionalFlag(app, "switchable", true) && identity != "",
			Initial:    firstGraphemeUpper(strings.TrimSpace(name)),
			ColorIndex: int(hash % 6),
		}
		view.Apps = append(view.Apps, row)
	}

	anyTraffic := false
	for _, app := range view.Apps {
		if app.HasTraffic {
			anyTraffic = true
			break
		}
	}
	if anyTraffic {
		filtered := view.Apps[:0]
		for _, app := range view.Apps {
			if app.HasTraffic {
				filtered = append(filtered, app)
			}
		}
		view.Apps = filtered
	}
	sort.SliceStable(view.Apps, func(i, j int) bool {
		a, b := view.Apps[i], view.Apps[j]
		if a.Score != b.Score {
			return b.Score < a.Score
		}
		if cmp := compareFold(a.Name, b.Name); cmp != 0 {
			return cmp < 0
		}
		return compareFold(a.Path, b.Path) < 0
	})
	if len(view.Apps) > 3 {
		view.Apps = view.Apps[:3]
	}
	if view.Apps == nil {
		view.Apps = []FlyoutApp{}
	}
	return view
}

func buildFlyoutLine(line map[string]any, index, count int, routingOn bool, names map[string]string) FlyoutLine {
	health, tone := LineHealth(line, routingOn)
	healthy := tone == "ok"
	rate := childMap(line, "rate")
	down := numberVal(rate, "down")
	speed := "Not measured"
	if rate != nil {
		speed = Rate(down)
	}
	lit := 0
	if healthy {
		lit = FlyoutLit(down)
	}
	id := textVal(line, "id")
	name := LineLabel(line, index)
	where := joinMidDot(textVal(line, "alias"), textVal(line, "ssid"))
	capObj := childMap(line, "cap")
	used := numberVal(childMap(line, "usage"), "bytes")
	metered := flagVal(line, "metered")

	usageText := ""
	periodText := ""
	if capObj != nil {
		usageText = FormatData(used) + " of " + FormatData(numberVal(capObj, "bytes"))
		if textVal(capObj, "period") == "day" {
			periodText = " today"
		} else {
			periodText = " this month"
		}
	} else if metered {
		usageText = FormatData(used) + " used"
	}

	leftDetail := where
	if usageText != "" {
		leftDetail = usageText
	}
	rightDetail := ""
	if healthy {
		rightDetail = health
	}
	detail := joinMidDot(leftDetail, rightDetail)

	row := FlyoutLine{
		ID:      id,
		Name:    name,
		Color:   index % PaletteSize,
		Main:    index == 0 && count > 1,
		Metered: metered,
		Health:  health,
		Tone:    tone,
		Healthy: healthy,
		Detail:  detail,
		Speed:   speed,
		Down:    down,
		Lit:     lit,
	}

	if target, ok := hasStringVal(line, "target"); ok && routingOn && target != id {
		if standIn, exists := names[target]; exists {
			row.StandIn = standIn
			suffix := " until it\u2019s back"
			if flagVal(line, "exhausted") {
				suffix = " until the cap resets"
			}
			row.Note = "Its apps use the " + standIn + suffix
		}
	}

	usageWithPeriod := ""
	if usageText != "" {
		usageWithPeriod = usageText + periodText
	}
	tip := joinMidDot(joinMidDot(name, where), joinMidDot(usageWithPeriod, health))
	if row.Note != "" {
		tip += "\n" + row.Note
	}
	row.Tip = tip
	return row
}

func joinMidDot(first, second string) string {
	if first == "" {
		return second
	}
	if second == "" {
		return first
	}
	return first + " \u00b7 " + second
}

// FormatData formats byte counters matching ui/app.js formatData.
func FormatData(bytes float64) string {
	if !(bytes >= byteMB) {
		if bytes > 0 {
			return "<1 MB"
		}
		return "0 MB"
	}
	if bytes < byteGB {
		return fmt.Sprintf("%.0f MB", roundAwayFromZero(bytes/byteMB))
	}
	gigabytes := bytes / byteGB
	if gigabytes >= 100 {
		return fmt.Sprintf("%.0f GB", roundAwayFromZero(gigabytes))
	}
	rounded := roundAwayFromZero(gigabytes*10) / 10
	s := fmt.Sprintf("%.1f", rounded)
	s = strings.TrimSuffix(s, ".0")
	return s + " GB"
}

// FlyoutLit returns 0..24 lit meter cells matching ui/app.js litCells.
func FlyoutLit(down float64) int {
	if !(down >= 1) || math.IsNaN(down) || math.IsInf(down, 0) {
		return 0
	}
	level := math.Log10(down/1024) / math.Log10(10*1024)
	lit := int(roundAwayFromZero(level * FlyoutMeterCells))
	if lit < 1 {
		return 1
	}
	if lit > FlyoutMeterCells {
		return FlyoutMeterCells
	}
	return lit
}

func computeFlyoutHealth(view *FlyoutView, status string, lines []FlyoutLine) {
	view.HealthTone = "dim"
	if status != "on" {
		switch status {
		case "starting":
			view.Health = "Routing is starting\u2026"
		case "stopping":
			view.Health = "Routing is turning off\u2026"
		case "error":
			view.Health = "Routing stopped \u00b7 apps use Windows' connection"
			view.HealthTone = "error"
		default:
			view.Health = "Routing is off \u00b7 apps use Windows' connection"
		}
		return
	}
	if len(lines) == 0 {
		view.HealthTone = "warning"
		view.Health = "No line is set up"
		return
	}
	var problems []int
	firstHealthy := -1
	for i, l := range lines {
		if !l.Healthy {
			problems = append(problems, i)
		} else if firstHealthy < 0 {
			firstHealthy = i
		}
	}
	working := len(lines) - len(problems)
	if len(problems) == 0 {
		view.HealthTone = "ok"
		switch len(lines) {
		case 1:
			view.Health = lines[0].Name + " reaches the internet"
		case 2:
			view.Health = "Both lines reach the internet"
		default:
			view.Health = fmt.Sprintf("All %d lines reach the internet", len(lines))
		}
		return
	}
	if working == 0 {
		view.HealthTone = "error"
	} else {
		view.HealthTone = "warning"
	}
	if len(problems) == 1 {
		idx := problems[0]
		line := lines[idx]
		moved := ""
		if line.StandIn != "" {
			if idx == 0 {
				moved = " \u00b7 apps use the " + line.StandIn
			} else {
				moved = " \u00b7 its apps use the " + line.StandIn
			}
		}
		healthWord := strings.TrimRight(LowerFirst(line.Health), "\u2026")
		view.Health = line.Name + ": " + healthWord + moved
		return
	}
	switch working {
	case 0:
		view.Health = "No line reaches the internet"
	case 1:
		view.Health = "Only the " + lines[firstHealthy].Name + " reaches the internet"
	default:
		view.Health = fmt.Sprintf("%d of %d lines reach the internet", working, len(lines))
	}
}

func strPtr(s string) *string { return &s }

func firstGraphemeUpper(s string) string {
	if s == "" {
		return ""
	}
	r, _ := utf8.DecodeRuneInString(s)
	return strings.ToUpper(string(r))
}

func compareFold(a, b string) int {
	la := strings.ToLower(a)
	lb := strings.ToLower(b)
	if la < lb {
		return -1
	}
	if la > lb {
		return 1
	}
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func utf8RunesOrUTF16(s string) []uint16 {
	out := make([]uint16, 0, len(s))
	for _, r := range s {
		if r < 0x10000 {
			out = append(out, uint16(r))
		} else {
			r1 := uint16(((r - 0x10000) >> 10) + 0xD800)
			r2 := uint16(((r - 0x10000) & 0x3FF) + 0xDC00)
			out = append(out, r1, r2)
		}
	}
	return out
}

// Helper for uppercase rune check if ever needed.
var _ = unicode.ToUpper
