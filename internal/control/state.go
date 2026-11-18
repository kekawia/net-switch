package control

import (
	"encoding/json"
	"strings"

	"github.com/kekawia/net-switch/internal/apps"
	"github.com/kekawia/net-switch/internal/control/engine"
	js "github.com/kekawia/net-switch/internal/jsvalue"
	"github.com/kekawia/net-switch/internal/lines"
)

// Keep the API's nested numeric records in the JSON sanitizer's object form.
// encoding/json rejects NaN in a struct before it can emit the required null.
func rateJSON(rate *apps.Rate) any {
	if rate == nil {
		return nil
	}
	return map[string]any{"down": rate.Down, "up": rate.Up}
}
func outsideJSON(row *apps.OutsideRow) any {
	if row == nil {
		return nil
	}
	return map[string]any{"connections": row.Connections, "byLine": row.ByLine, "beforeRouting": row.BeforeRouting, "measured": row.Measured, "rate": rateJSON(row.Rate)}
}

func (c *Core) combineActiveLocked(s engine.Snapshot) bool {
	if !s.Policy.Combine || s.Status != "on" {
		return false
	}
	n := 0
	for _, share := range s.Policy.Shares {
		if share.Value > 0 && c.targetLocked(share.ID, s) == share.ID {
			n++
		}
	}
	return n >= 2
}
func (c *Core) targetLocked(id string, s engine.Snapshot) string {
	if s.StartedWith == nil || (len(s.StartedWith.Lines) < 2 && !hasVirtualLines(s.StartedWith.Lines)) {
		return id
	}
	if l := c.lanes[id]; l != nil && l.target != nil {
		return *l.target
	}
	return id
}
func metric(a map[string]any) float64 {
	m := 9999.0
	if a["metric"] != nil {
		m = js.Number(a["metric"])
	}
	if a["routeMetric"] != nil {
		m += js.Number(a["routeMetric"])
	}
	return m
}
func (c *Core) outrankingLocked() (map[string]any, []map[string]any) {
	var main map[string]any
	others := []map[string]any{}
	items := c.itemsLocked()
	mainIdx := primaryPhysicalIndex(items)
	if mainIdx < 0 {
		return main, others
	}
	for _, a := range c.adapters {
		if a["alias"] == items[mainIdx].Alias && a["connected"] == true {
			main = a
			break
		}
	}
	if main == nil {
		return main, others
	}
	for i, l := range items {
		if i == mainIdx || l.IsVirtual() {
			continue
		}
		for _, a := range c.adapters {
			if a["alias"] == l.Alias && a["alias"] != main["alias"] && a["connected"] == true && metric(a) <= metric(main) {
				others = append(others, a)
			}
		}
	}
	return main, others
}
func baseName(path string) string {
	for _, prefix := range []string{"flatpak:", "snap:", "appimage:"} {
		if strings.HasPrefix(path, prefix) {
			return strings.TrimPrefix(path, prefix)
		}
	}
	path = strings.ReplaceAll(path, "/", `\`)
	parts := strings.Split(path, `\`)
	name := parts[len(parts)-1]
	if strings.HasSuffix(strings.ToLower(name), ".exe") {
		name = name[:len(name)-4]
	}
	return name
}
func (c *Core) describeLocked(path, identity string) map[string]any {
	target := path
	if identity != "" {
		target = identity
	}
	key := c.appKey(target)
	name := baseName(target)
	if name == "" {
		name = baseName(path)
	}
	windowsServices := c.pathRules().Separator == `\` && key == `c:\windows\system32\svchost.exe`
	switchable, reconnectable := true, true
	if key == "unknown" {
		name = "Unknown app"
		switchable = false
		reconnectable = false
	} else if windowsServices {
		name = "Windows services"
		reconnectable = false
	}
	info := c.info[key]
	c.queueInfoLocked([]string{target})
	if v := js.Text(info["name"]); v != "" && !windowsServices {
		name = v
	}
	return map[string]any{"name": name, "hasIcon": js.Truth(info["icon"]), "switchable": switchable, "reconnectable": reconnectable}
}

// State emits every legacy field, including explicit nulls. It takes one state
// lock so a response cannot mix policy generations.
func (c *Core) State() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.op.Engine.Snapshot()
	for _, line := range c.itemsLocked() {
		if lane := c.lanes[line.ID]; lane != nil && lane.health.Up == nil {
			c.sampleLinesLocked(s)
			break
		}
	}
	items := c.itemsLocked()
	mainID := primaryDisplayID(items)
	routing := s.Status == "on"
	ll := []any{}
	candidates := []any{}
	appRows := []any{}
	wifi := false
	hasWifiLine := false
	for _, line := range items {
		var adapter map[string]any
		for _, a := range c.adapters {
			if a["alias"] == line.Alias {
				adapter = a
				break
			}
		}
		kind := any(line.Kind)
		if line.Proxy != nil {
			kind = "proxy"
		} else if line.VPN {
			kind = "vpn"
		} else if line.Kind == nil {
			kind = adapter["kind"]
		}
		if !line.IsVirtual() && ((line.Kind != nil && *line.Kind == "wifi") || adapter["kind"] == "wifi") {
			hasWifiLine = true
		}
		l := c.lanes[line.ID]
		connected := l != nil && l.health.Up != nil && *l.health.Up
		var problem any
		var ping any
		if l != nil {
			if l.health.Up != nil && !*l.health.Up {
				problem = l.health.Reason
			}
			if connected {
				ping = l.delay
			}
		}
		var target any
		carrying := false
		if routing {
			t := c.targetLocked(line.ID, s)
			target = t
			carrying = t == line.ID
		}
		var rate any
		if line.Proxy != nil {
			if routing && c.monitorFailures < 3 {
				r := c.tracker.LineRate(line.ID)
				rate = rateJSON(&r)
			}
		} else if m, ok := c.meters[line.Alias]; ok && c.now()-m.at <= 5000 {
			rate = rateJSON(m.rate)
		}
		ssid := adapter["ssid"]
		if line.IsVirtual() || !js.Truth(ssid) {
			ssid = nil
		}
		blocked := false
		for _, id := range s.Policy.Blocked {
			blocked = blocked || id == line.ID
		}
		var share any
		if s.Policy.Combine {
			share = float64(0)
			for _, v := range s.Policy.Shares {
				if v.ID == line.ID {
					share = v.Value
				}
			}
		}
		entry := map[string]any{
			"id": line.ID, "alias": line.Alias, "label": json.RawMessage(js.MarshalString(line.Label)),
			"kind": kind, "main": line.ID == mainID, "connected": connected, "problem": problem, "ping": ping,
			"connections": c.connections[line.ID], "carrying": carrying, "target": target,
			"rate": rate, "ssid": ssid, "metered": line.Metered, "strict": line.Strict,
			"cap": line.Cap, "usage": c.usage.Used(line.ID), "exhausted": c.exhausted[line.ID],
			"blocked": blocked, "weight": line.Weight, "share": share,
		}
		if line.VPN {
			entry["vpn"] = true
			entry["onlyChosen"] = line.IsOnlyChosen()
			entry["fallback"] = line.AllowsFallback()
		} else if line.Proxy != nil {
			entry["onlyChosen"] = line.IsOnlyChosen()
			entry["fallback"] = line.AllowsFallback()
			entry["proxy"] = c.proxyStateJSONLocked(line.Proxy)
		} else if line.Fallback != nil {
			entry["fallback"] = *line.Fallback
		}
		if drop := c.unsupportedUDP.Lines[line.ID]; drop > 0 {
			entry["unsupportedUdp"] = drop
		}
		ll = append(ll, entry)
	}
	for _, a := range c.adapters {
		if c.findVPNAdapterLocked(js.Text(a["alias"]), js.Text(a["guid"])) != nil {
			continue
		}
		if a["kind"] == "wifi" {
			wifi = true
		}
		taken := false
		for _, l := range items {
			taken = taken || l.Alias == a["alias"]
		}
		if a["connected"] == true && !taken {
			ssid := a["ssid"]
			if !js.Truth(ssid) {
				ssid = nil
			}
			candidates = append(candidates, map[string]any{"alias": a["alias"], "label": lines.LineLabel(a), "kind": a["kind"], "ssid": ssid})
		}
	}
	for _, v := range c.vpnAdapters {
		if v["connected"] != true {
			continue
		}
		alias := js.Text(v["alias"])
		taken := false
		for _, l := range items {
			taken = taken || l.Alias == alias
		}
		if !taken {
			candidates = append(candidates, map[string]any{
				"alias":           alias,
				"label":           alias,
				"kind":            "vpn",
				"vpn":             true,
				"hasDefaultRoute": js.Truth(v["hasDefaultRoute"]),
				"ssid":            nil,
			})
		}
	}
	for _, a := range apps.MergeRowsWith(c.tracker.Snapshot(c.pinsLocked()), c.outside, c.pinsLocked(), c.pathRules()) {
		row := c.describeLocked(a.Path, a.Identity)
		row["key"] = a.Key
		row["path"] = a.Path
		row["line"] = a.Line
		row["rate"] = rateJSON(&a.Rate)
		row["lineDown"] = a.LineDown
		row["sortScore"] = a.SortScore
		row["connections"] = a.Connections
		row["outside"] = outsideJSON(a.Outside)
		// Only Linux sandbox apps have an identity apart from their path; a
		// path pin that cannot match such an app is kept but flagged, never
		// routed by guess. Windows rows and 0.3.x shapes are unchanged.
		if a.Identity != "" {
			row["identity"] = a.Identity
		}
		if len(c.unsupportedUDP.Apps) > 0 {
			drop := c.unsupportedUDP.Apps[a.Identity]
			if drop == 0 {
				drop = c.unsupportedUDP.Apps[a.Key]
			}
			if drop == 0 {
				drop = c.unsupportedUDP.Apps[a.Path]
			}
			if drop > 0 {
				row["unsupportedUdp"] = drop
			}
		}
		if a.Line != nil {
			trackedIdentity := a.Identity
			if trackedIdentity == "" && c.pathRules().Separator == "/" {
				trackedIdentity = c.trackedSandboxAtPathLocked(a.Path)
			}
			for _, p := range c.pinsLocked() {
				if c.appKey(p.Path) == a.Key && apps.PinNeedsReselection(p, trackedIdentity) {
					row["pinNeedsReselection"] = true
				}
			}
		}
		appRows = append(appRows, row)
	}
	var retryAt, ipv6, offer, autostart any
	if routing {
		ipv6 = s.StartedWith != nil && s.StartedWith.IPv6
	}
	if c.wanted && s.Status == "error" && (c.op.Mode != "tun" || c.elevated) && (!c.op.ServiceMode || len(c.failureTimes) < 5) {
		retryAt = c.retryAt
	}
	if c.offer != nil && c.values["skippedUpdate"] != c.offer.Version {
		offer = c.offer
	}
	if c.op.AutostartAllowed {
		autostart = c.autostart
	}
	undo := map[string]any{}
	if c.op.Undo != nil {
		undo = c.op.Undo.Values()
	}
	metricChanged := false
	for _, v := range js.Object(undo["metrics"]) {
		metricChanged = metricChanged || len(array(v)) > 0
	}
	_, policyChanged := js.Object(undo["policy"])["value"]
	_, others := c.outrankingLocked()
	updates := c.op.Mode != "proxy" && c.values["checkForUpdates"] == true
	routingState := map[string]any{
		"status": s.Status, "wanted": c.wanted, "error": s.Error,
		"measuring": routing && c.monitorFailures < 3,
		"proxyPort": s.ProxyPort, "ipv6": ipv6, "retryAt": retryAt,
	}
	if s.VPNFirewall != nil {
		routingState["vpnFirewall"] = s.VPNFirewall
	}
	features := map[string]any{"reconnect": true, "combine": true, "lines": true, "installedApps": true}
	state := map[string]any{
		"mode": c.op.Mode, "elevated": c.elevated, "version": c.op.Version,
		"update": offer, "updateChecks": updates,
		"features": features,
		"combine":  map[string]any{"on": s.Policy.Combine, "active": c.combineActiveLocked(s), "mode": c.values["combineMode"]},
		"routing":  routingState,
		"lines":    ll, "candidates": candidates, "apps": appRows,
		"events": append([]map[string]any{}, c.events...),
		"settings": map[string]any{
			"autostart": autostart, "checkForUpdates": updates,
			"probeTargets": probeTargets(c.values["probeTargets"], c.values["probeTargetsCustom"] == true),
		},
		"setup": map[string]any{
			"cableNotDefault": len(others) > 0, "wifiBlocked": c.policy == float64(3) && wifi,
			"keepBothConnected": len(items) > 1 && hasWifiLine && c.policy != float64(0) && c.policy != float64(3),
			"changed":           map[string]any{"cableDefault": metricChanged, "keepBoth": policyChanged},
		},
	}
	if c.usageIssue != "" {
		state["usageError"] = c.usageIssue
	}
	if c.op.Updater != nil {
		features["signedUpdates"] = true
		if update := c.op.Updater.Status(); update != nil {
			state["updateStatus"] = update
		}
	}
	return state
}
