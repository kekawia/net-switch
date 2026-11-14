package control

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/probe"
	"github.com/AyoubAchour/net-switch/internal/engine/proxy"
	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
	"github.com/AyoubAchour/net-switch/internal/lines"
)

func isCaptureAlias(alias string) bool {
	lower := strings.ToLower(strings.TrimSpace(alias))
	return lower == "netswitch" || lower == "netswitch0"
}

func hasVirtualLines(items []lines.Line) bool {
	for _, l := range items {
		if l.VPN || l.Proxy != nil {
			return true
		}
	}
	return false
}

func hasProxyLines(items []lines.Line) bool {
	for _, l := range items {
		if l.Proxy != nil {
			return true
		}
	}
	return false
}

func primaryPhysicalIndex(items []lines.Line) int {
	for i, l := range items {
		if !l.VPN && l.Proxy == nil {
			return i
		}
	}
	return -1
}

func clearPrimaryPhysicalStrict(items []lines.Line) {
	if idx := primaryPhysicalIndex(items); idx >= 0 {
		items[idx].Strict = false
	}
}

// policyLinesLocked orders lines for compiled engine policy:
//   - Physical-only lists keep their exact saved order.
//   - An exclude-mode VPN (!IsOnlyChosen) moves to index 0 so unpinned apps
//     follow the VPN while apps pinned to physical lines bypass it.
//   - Otherwise, if index 0 is a chosen-only virtual line and a physical line
//     exists, the first physical line moves to index 0 so unpinned apps never
//     land on a chosen-only VPN or proxy.
func (c *Core) policyLinesLocked(items []lines.Line) []lines.Line {
	if !hasVirtualLines(items) || len(items) <= 1 {
		return items
	}
	for i, l := range items {
		if l.VPN && !l.IsOnlyChosen() {
			if i == 0 {
				return items
			}
			out := make([]lines.Line, 0, len(items))
			out = append(out, items[i])
			out = append(out, items[:i]...)
			out = append(out, items[i+1:]...)
			return out
		}
	}
	if items[0].IsVirtual() {
		if phys := primaryPhysicalIndex(items); phys > 0 {
			out := make([]lines.Line, 0, len(items))
			out = append(out, items[phys])
			out = append(out, items[:phys]...)
			out = append(out, items[phys+1:]...)
			return out
		}
	}
	return items
}

func primaryDisplayID(items []lines.Line) string {
	for _, l := range items {
		if l.VPN && !l.IsOnlyChosen() {
			return l.ID
		}
	}
	if idx := primaryPhysicalIndex(items); idx >= 0 {
		return items[idx].ID
	}
	if len(items) > 0 {
		return items[0].ID
	}
	return ""
}

func prepareVPNAdapters(v any) []map[string]any {
	list, ok := v.([]any)
	if !ok || len(list) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(list))
	for _, raw := range list {
		m := js.Object(raw)
		if m == nil {
			continue
		}
		alias := js.Text(m["alias"])
		if alias == "" || isCaptureAlias(alias) {
			continue
		}
		ips := array(m["ipv4s"])
		active := m["status"] == "Up" && (len(ips) > 0 || m["ipv6"] == true)
		cp := map[string]any{}
		for k, val := range m {
			cp[k] = val
		}
		cp["connected"] = active
		out = append(out, cp)
	}
	return out
}

func (c *Core) findVPNAdapterLocked(alias, guid string) map[string]any {
	norm := func(s string) string { return strings.ToLower(strings.NewReplacer("{", "", "}", "").Replace(s)) }
	if guid != "" {
		for _, v := range c.vpnAdapters {
			if g := js.Text(v["guid"]); g != "" && norm(g) == norm(guid) {
				return v
			}
		}
	}
	for _, v := range c.vpnAdapters {
		if js.Text(v["alias"]) == alias {
			return v
		}
	}
	return nil
}

func (c *Core) vpnHasIPv6Locked(alias string) bool {
	if v := c.findVPNAdapterLocked(alias, ""); v != nil && v["ipv6"] == true {
		return true
	}
	for _, a := range c.adapters {
		if a["alias"] == alias && a["ipv6"] == true {
			return true
		}
	}
	return false
}

func (c *Core) virtualPrerequisiteLocked(item lines.Line, items []lines.Line) (address bool, route bool) {
	if item.Proxy != nil {
		carrier := item.Proxy.Carrier
		if carrier == "local" {
			return true, true
		}
		var carrierLine *lines.Line
		if carrier == "" || carrier == "main" {
			if idx := primaryPhysicalIndex(items); idx >= 0 {
				carrierLine = &items[idx]
			} else {
				for i := range items {
					if items[i].Proxy == nil {
						carrierLine = &items[i]
						break
					}
				}
			}
		} else {
			for i := range items {
				if items[i].ID == carrier && items[i].Proxy == nil {
					carrierLine = &items[i]
					break
				}
			}
		}
		if carrierLine == nil {
			return false, false
		}
		if cl := c.lanes[carrierLine.ID]; cl != nil && cl.health.Up != nil {
			ok := *cl.health.Up
			return ok, ok
		}
		if carrierLine.VPN {
			return c.virtualPrerequisiteLocked(*carrierLine, items)
		}
		for _, a := range c.adapters {
			if a["alias"] == carrierLine.Alias {
				hasIP := len(array(a["ipv4s"])) > 0 || (item.Proxy.IPv6 && a["ipv6"] == true)
				return hasIP, hasIP
			}
		}
		return false, false
	}
	if v := c.findVPNAdapterLocked(item.Alias, ptrStringValue(item.GUID)); v != nil {
		active := v["status"] == "Up" && (len(array(v["ipv4s"])) > 0 || v["ipv6"] == true)
		return active, active
	}
	for _, a := range c.adapters {
		if a["alias"] == item.Alias {
			active := a["status"] == "Up" && (len(array(a["ipv4s"])) > 0 || a["ipv6"] == true)
			return active, active
		}
	}
	return false, false
}

func ptrStringValue(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func (c *Core) removedVPNsLocked() []string {
	var out []string
	for _, v := range array(c.values["removedVpns"]) {
		if s := js.Text(v); s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func nextUniqueLineID(items []lines.Line, source lines.IDSource) string {
	if source == nil {
		source = lines.RandomID
	}
	taken := map[string]bool{}
	for _, l := range items {
		taken[l.ID] = true
	}
	for {
		id := source()
		if !taken[id] {
			return id
		}
	}
}

// ProxyCredentials resolves sealed credentials for all configured proxy lines.
// When no proxy line uses authentication, it returns nil without disk I/O.
func (c *Core) ProxyCredentials() (map[string]proxy.Credentials, error) {
	c.mu.Lock()
	items := c.itemsLocked()
	store := c.secrets
	c.mu.Unlock()
	if store == nil {
		return nil, nil
	}
	var refs []string
	for _, l := range items {
		if l.Proxy != nil && l.Proxy.CredentialsRef != "" {
			refs = append(refs, l.Proxy.CredentialsRef)
		}
	}
	if len(refs) == 0 {
		return nil, nil
	}
	return store.Resolve(refs)
}

func (c *Core) syncEngineCredentials(ctx context.Context) error {
	pe, ok := c.op.Engine.(engine.ProxyRuntime)
	if !ok {
		return nil
	}
	creds, err := c.ProxyCredentials()
	if err != nil {
		return err
	}
	return pe.SyncProxyCredentials(ctx, creds)
}

func (c *Core) proxyStateJSONLocked(spec *lines.ProxySpec) map[string]any {
	if spec == nil {
		return nil
	}
	hasAuth := spec.CredentialsRef != ""
	username := ""
	if hasAuth && c.secrets != nil {
		if creds, _, ok, err := c.secrets.Get(spec.CredentialsRef); err == nil && ok {
			username = creds.Username
		}
	}
	out := map[string]any{
		"protocol": spec.Protocol,
		"server":   spec.Server,
		"carrier":  spec.Carrier,
		"udp":      spec.UDP,
		"ipv6":     spec.IPv6,
		"hasAuth":  hasAuth,
	}
	if spec.ServerName != "" {
		out["serverName"] = spec.ServerName
	}
	if username != "" {
		out["username"] = username
	}
	return out
}

func validateCarrier(carrier string, selfID string, items []lines.Line) (string, error) {
	trimmed := strings.TrimSpace(carrier)
	if trimmed == "" {
		trimmed = "main"
	}
	if trimmed == "local" || trimmed == "main" {
		return trimmed, nil
	}
	if trimmed == selfID {
		return "", bad("A proxy line can’t use itself as its carrier.")
	}
	for _, l := range items {
		if l.ID == trimmed {
			if l.Proxy != nil {
				return "", bad("Choose a normal or VPN connection to carry this proxy, not another proxy.")
			}
			return trimmed, nil
		}
	}
	return "", bad("Choose which connection reaches this proxy server.")
}

func parseProxyInput(raw any, selfID string, items []lines.Line) (*lines.ProxySpec, string, string, bool, bool, error) {
	m := js.Object(raw)
	if m == nil {
		return nil, "", "", false, false, bad("Enter the proxy details, then try again.")
	}
	proto := strings.ToLower(js.Trim(js.Text(m["protocol"])))
	if proto != "socks5" && proto != "http" && proto != "https" {
		return nil, "", "", false, false, bad("Choose SOCKS5, HTTP CONNECT, or HTTPS CONNECT.")
	}
	server, ok := lines.ValidHostPort(js.Text(m["server"]))
	if !ok {
		return nil, "", "", false, false, bad("Enter the proxy server as host:port, like 127.0.0.1:1080.")
	}
	var serverName string
	if proto == "https" {
		sni, sniOK := lines.ValidServerName(js.Text(m["serverName"]))
		if !sniOK {
			return nil, "", "", false, false, bad("Enter a valid TLS server name.")
		}
		serverName = sni
	}
	carrier, err := validateCarrier(js.Text(m["carrier"]), selfID, items)
	if err != nil {
		return nil, "", "", false, false, err
	}
	username := strings.TrimSpace(js.Text(m["username"]))
	password := js.Text(m["password"])
	if len(username) > 255 || len(password) > 255 {
		return nil, "", "", false, false, bad("Keep the proxy username and password under 255 characters.")
	}
	spec := &lines.ProxySpec{
		Protocol:   proto,
		Server:     server,
		ServerName: serverName,
		Carrier:    carrier,
		UDP:        m["udp"] == true && proto == "socks5",
		IPv6:       m["ipv6"] == true,
	}
	return spec, username, password, m["keepPassword"] == true, m["clearAuth"] == true, nil
}

func resolveRuntimeCarrier(carrier string, items []lines.Line) string {
	if carrier == "local" {
		return "local"
	}
	if carrier != "" && carrier != "main" {
		for _, l := range items {
			if l.ID == carrier && l.Proxy == nil {
				return carrier
			}
		}
	}
	if idx := primaryPhysicalIndex(items); idx >= 0 {
		return items[idx].ID
	}
	for _, l := range items {
		if l.Proxy == nil {
			return l.ID
		}
	}
	return "local"
}

func (c *Core) testProxyAction(ctx context.Context, b map[string]any) (any, error) {
	c.mu.Lock()
	items := c.itemsLocked()
	targets := probeTargets(c.values["probeTargets"], c.values["probeTargetsCustom"] == true)
	custom := customTargets(c.values["probeTargets"], c.values["probeTargetsCustom"] == true)
	store := c.secrets
	c.mu.Unlock()

	editID := js.Text(b["id"])
	spec, username, password, keepPassword, clearAuth, err := parseProxyInput(b["proxy"], editID, items)
	if err != nil {
		return nil, err
	}
	if !clearAuth && password == "" && keepPassword && editID != "" && store != nil {
		for _, l := range items {
			if l.ID == editID && l.Proxy != nil && l.Proxy.CredentialsRef != "" {
				if saved, _, ok, gErr := store.Get(l.Proxy.CredentialsRef); gErr == nil && ok {
					if username == "" {
						username = saved.Username
					}
					password = saved.Password
				}
				break
			}
		}
	}
	if clearAuth {
		username, password = "", ""
	}

	target := ""
	if custom && len(targets) > 0 {
		target = targets[0]
	} else if t := strings.TrimSpace(js.Text(b["target"])); t != "" {
		if ap, pErr := netip.ParseAddrPort(t); pErr == nil && ap.Port() != 0 {
			target = ap.String()
		}
	}

	resolvedCarrier := resolveRuntimeCarrier(spec.Carrier, items)
	pLine := platform.ProxyLine{
		Protocol:   spec.Protocol,
		Server:     spec.Server,
		ServerName: spec.ServerName,
		Carrier:    resolvedCarrier,
		UDP:        spec.UDP,
	}

	testCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var res platform.ProxyTestResult
	usedEngine := false
	if pe, ok := c.op.Engine.(engine.ProxyRuntime); ok {
		engRes, engErr := pe.TestProxyLine(testCtx, engine.ProxyTestRequest{
			Line:     pLine,
			Username: username,
			Password: password,
			Target:   target,
		})
		if engErr == nil {
			res = engRes
			usedEngine = true
		}
	}

	if !usedEngine {
		if spec.Carrier != "local" {
			res = platform.ProxyTestResult{
				OK:        false,
				ErrorKind: "engineOff",
				Error:     "Turn on routing first to test a proxy through another line.",
			}
		} else {
			res = runLocalProxyTest(testCtx, pLine, proxy.Credentials{Username: username, Password: password}, target)
		}
	}

	return map[string]any{
		"ok":        res.OK,
		"latencyMs": res.LatencyMS,
		"udpOk":     res.UDPOK,
		"ipv6Ok":    res.IPv6OK,
		"errorKind": res.ErrorKind,
		"error":     res.Error,
	}, nil
}

func runLocalProxyTest(ctx context.Context, spec platform.ProxyLine, creds proxy.Credentials, target string) platform.ProxyTestResult {
	const testID = "_proxy_test"
	const credID = "_proxy_test_cred"
	spec.Carrier = proxy.CarrierLocal
	if !creds.Empty() {
		spec.CredentialsRef = credID
	}
	d := proxy.NewDialer(nil, proxy.Options{
		MaxHandshakes:      4,
		MaxUDPAssociations: 4,
	})
	d.SetLines([]platform.Line{{ID: testID, Proxy: &spec}})
	if !creds.Empty() {
		d.SetCredentials(map[string]proxy.Credentials{credID: creds})
	}
	req := platform.ProbeRequest{Operator: "quick:cloudflare", Quick: true}
	if target != "" {
		req = platform.ProbeRequest{Target: target, Quick: true, Custom: true}
	}
	var dialErr error
	pr, err := probe.Run(ctx, req, probe.Options{
		Dial: func(dialCtx context.Context, dst netip.AddrPort) (net.Conn, error) {
			conn, dErr := d.DialTCP(dialCtx, testID, dst)
			if dErr != nil {
				dialErr = dErr
			}
			return conn, dErr
		},
	})
	if err != nil {
		return platform.ProxyTestResult{OK: false, ErrorKind: "unreachable", Error: err.Error()}
	}
	out := platform.ProxyTestResult{OK: pr.OK, LatencyMS: pr.LatencyMS}
	if !pr.OK {
		out.Error = pr.Error
		if len(out.Error) > 256 {
			out.Error = out.Error[:256]
		}
		out.ErrorKind = "unreachable"
		var pe *proxy.Error
		if errors.As(dialErr, &pe) {
			out.ErrorKind = pe.Kind.String()
		}
		return out
	}
	if spec.Protocol == "socks5" {
		testUDP := spec
		testUDP.UDP = true
		d.SetLines([]platform.Line{{ID: testID, Proxy: &testUDP}})
		uCtx, cancelU := context.WithTimeout(ctx, 2*time.Second)
		uConn, uErr := d.OpenUDP(uCtx, testID, false)
		cancelU()
		udpOK := uErr == nil
		if uConn != nil {
			_ = uConn.Close()
		}
		out.UDPOK = &udpOK
	} else {
		udpOK := false
		out.UDPOK = &udpOK
	}
	if target == "" {
		v6Ctx, cancelV6 := context.WithTimeout(ctx, 1500*time.Millisecond)
		v6Conn, v6Err := d.DialTCP(v6Ctx, testID, netip.MustParseAddrPort("[2606:4700:4700::1111]:443"))
		cancelV6()
		v6OK := v6Err == nil
		if v6Conn != nil {
			_ = v6Conn.Close()
		}
		out.IPv6OK = &v6OK
	}
	return out
}

func cleanLineLabel(raw any, fallback string, existing []lines.Line) (string, error) {
	if raw == nil {
		return lines.UniqueLabel(fallback, existing), nil
	}
	label := js.Trim(js.Text(raw))
	if label == "" {
		return lines.UniqueLabel(fallback, existing), nil
	}
	if len(utf16.Encode([]rune(label))) > 40 {
		return "", bad("Give the line a name of up to 40 characters.")
	}
	return label, nil
}
