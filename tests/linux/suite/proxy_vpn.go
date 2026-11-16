//go:build linux

package suite

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kekawia/net-switch/internal/engine/platform"
	"github.com/kekawia/net-switch/tests/linux/app"
	"github.com/kekawia/net-switch/tests/linux/engine"
	"github.com/kekawia/net-switch/tests/linux/harness"
	"github.com/kekawia/net-switch/tests/linux/inet"
	"github.com/kekawia/net-switch/tests/linux/topo"
	"github.com/kekawia/net-switch/tests/linux/wire"
)

func init() { register(15, addProxyVPN) }

var peerPublic4 = netip.MustParseAddr("192.0.2.13")

func addProxyVPN(r *registry) {
	r.add("proxy.dante-socks5", "Dante SOCKS5 server: TCP, HTTP and UDP ASSOCIATE route over the selected carrier line", harness.Requires10, "12.14", 90*time.Second, proxyDanteSOCKS5)
	r.add("proxy.3proxy-socks5-http-auth", "3proxy SOCKS5 and HTTP CONNECT: RFC 1929 and Basic auth, wrong-password isolation and live credential update", harness.Requires10, "12.14", 90*time.Second, proxy3ProxyAuth)
	r.add("proxy.microsocks-tcp-only-udp-no-leak", "MicroSocks TCP-only SOCKS5: TCP succeeds while UDP is refused promptly with zero packet leak and healthy line status", harness.Requires10, "12.14", 90*time.Second, proxyMicroSocksTCPOnly)
	r.add("proxy.squid-http-https-tls-and-403", "Squid OpenSSL HTTP and HTTPS CONNECT: verified TLS proxy, destination 403 non-fault isolation and UDP fail-closed refusal", harness.Requires10, "12.14", 2*time.Minute, proxySquidHTTPAndTLS)
	r.add("vpn.wg-quick-start-orders-modes-and-split", "wg-quick VPN: both start orders, exclude and Table=off include modes, fail-closed vs failover and split-tunnel bypass", harness.Requires10, "12.12, 12.13", 2*time.Minute, vpnWgQuickMatrix)
	r.add("vpn.killswitch-step-aside", "VPN kill switch: startup wg-quick PostUp and live Mullvad nftables output blocks step aside cleanly", harness.Requires10, "12.13, 12.15", 90*time.Second, vpnKillSwitchStepAside)
}

func requireTool(e *Env, names ...string) string {
	extraDirs := []string{"/usr/sbin", "/sbin", "/usr/local/bin", "/usr/bin", "/bin"}
	for _, name := range names {
		if envKey := os.Getenv(name); envKey != "" {
			if st, err := os.Stat(envKey); err == nil && !st.IsDir() {
				return envKey
			}
		}
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
		for _, dir := range extraDirs {
			cand := filepath.Join(dir, name)
			if st, err := os.Stat(cand); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
				return cand
			}
		}
	}
	e.T.Fatalf("required third-party tool missing from PATH and sbin: %v", names)
	return ""
}

func setupPeerNetns(e *Env) netip.Addr {
	ctx := e.Ctx()
	r := e.Net.R
	if _, err := r.Run(ctx, "ip", "netns", "add", topo.CTR); err != nil {
		e.T.Fatalf("add peer netns %s: %v", topo.CTR, err)
	}
	if err := r.Sysctl(ctx, topo.CTR,
		"net.ipv4.ip_forward=1",
		"net.ipv6.conf.all.accept_dad=0",
		"net.ipv6.conf.default.accept_dad=0",
	); err != nil {
		e.T.Fatalf("sysctl peer netns: %v", err)
	}
	if _, err := r.Run(ctx, "ip", "link", "add", "peer-wan", "netns", topo.CTR, "type", "veth", "peer", "name", "up-peer", "netns", topo.INET); err != nil {
		e.T.Fatalf("add peer veth: %v", err)
	}
	if err := r.Batch(ctx, topo.INET, []string{
		"addr add 192.0.2.14/30 dev up-peer",
		"link set up-peer up",
	}); err != nil {
		e.T.Fatalf("configure up-peer in inet: %v", err)
	}
	if err := r.Batch(ctx, topo.CTR, []string{
		"link set lo up",
		"addr add 192.0.2.13/30 dev peer-wan",
		"link set peer-wan up",
		"route add default via 192.0.2.14",
	}); err != nil {
		e.T.Fatalf("configure peer-wan in %s: %v", topo.CTR, err)
	}
	nftNat := "table ip wgnat {\n chain post {\n  type nat hook postrouting priority 100; policy accept;\n  oifname \"peer-wan\" masquerade\n }\n}\n"
	e.T.Require(r.Nft(ctx, topo.CTR, nftNat) == nil, "install peer-wan masquerade in peer netns")
	return peerPublic4
}

func startPeerDaemon(e *Env, label, bin string, ports []uint16, args ...string) *Bg {
	bg := e.Start(Run{
		Program: bin,
		Args:    args,
		Netns:   topo.CTR,
		User:    AsRoot,
		Timeout: 3 * time.Minute,
	})
	e.T.Cleanup(func() { bg.Stop() })

	deadline := time.Now().Add(15 * time.Second)
	for {
		if !bg.Running() {
			e.T.Fatalf("%s (%s) exited early: stdout=%s stderr=%s", label, bin, strings.TrimSpace(bg.stdout.String()), strings.TrimSpace(bg.stderr.String()))
		}
		allBound := true
		for _, port := range ports {
			out, err := e.Net.R.In(e.Ctx(), topo.CTR, "ss", "-H", "-tln", fmt.Sprintf("sport = :%d", port))
			if err != nil || strings.TrimSpace(out) == "" {
				allBound = false
				break
			}
		}
		if allBound {
			return bg
		}
		if time.Now().After(deadline) {
			ssOut, _ := e.Net.R.In(e.Ctx(), topo.CTR, "ss", "-tulpn")
			e.T.Fatalf("%s (%s) did not listen on %v within 15s:\nss:\n%s\nstdout:\n%s\nstderr:\n%s",
				label, bin, ports, ssOut, bg.stdout.String(), bg.stderr.String())
		}
		e.Sleep(50 * time.Millisecond)
	}
}

func countSeenAddr(seen map[string]int, want netip.Addr) int {
	total := 0
	for raw, n := range seen {
		if ap, err := netip.ParseAddrPort(raw); err == nil {
			if ap.Addr().Unmap() == want {
				total += n
			}
			continue
		}
		if a, err := netip.ParseAddr(strings.TrimSpace(raw)); err == nil && a.Unmap() == want {
			total += n
		}
	}
	return total
}

func expectSeenTCP(e *Env, label, appName string, want netip.Addr, count int) {
	r := e.TCP(appName, AsUser, "--to", To(topo.Server4, wire.PortWhoami), "--count", strconv.Itoa(count), "--timeout", "5000")
	got := countSeenAddr(r.Seen, want)
	e.T.Check(r.OK == count && got == count,
		"%s: %d/%d TCP connections exited %s (seen %v, errors %v)", label, got, count, want, r.Seen, r.Errors)
}

func expectSeenUDP(e *Env, label, appName string, want netip.Addr, count int) {
	r := e.UDP(appName, AsUser, "--to", To(topo.Server4, wire.PortUDPEcho), "--count", strconv.Itoa(count), "--wait", "2000")
	got := countSeenAddr(r.Seen, want)
	e.T.Check(r.Received == count && r.Sent == count && got == count,
		"%s: %d/%d UDP datagrams exited %s (seen %v, sendErr %v, recvErr %v)", label, got, count, want, r.Seen, r.SendErrors, r.RecvErrors)
}

func expectSeenHTTP(e *Env, label, appName string, want netip.Addr) {
	var h app.HTTPResult
	e.RunJSON(Run{App: appName, User: AsUser, Args: []string{"http", "--url", "http://" + To(topo.Server4, wire.PortHTTP) + "/"}}, &h)
	got, _ := netip.ParseAddr(strings.TrimSpace(h.Seen))
	e.T.Check(h.Status == 200 && got.Unmap() == want,
		"%s: HTTP status %d, server saw %q (want %s, err %q)", label, h.Status, h.Seen, want, h.Err)
}

func expectUDPRefusedWithZeroLeak(e *Env, label, appName string, lineID engine.LineID, count int) {
	_, ctrl := e.v1()
	beforeStats, err := ctrl.Stats(e.Ctx())
	e.T.Require(err == nil, "%s: read stats before UDP refusal (%v)", label, err)

	from := e.Mark()
	var udpRes app.UDPResult
	e.RunJSON(Run{
		App:  appName,
		User: AsUser,
		Args: []string{"udp", "--to", To(topo.Server4, wire.PortUDPEcho), "--count", strconv.Itoa(count), "--wait", "1500", "--connect"},
	}, &udpRes)
	refused := udpRes.RecvErrors["ECONNREFUSED"] + udpRes.SendErrors["ECONNREFUSED"]
	e.T.Check(udpRes.Received == 0 && refused > 0,
		"%s: connected UDP refused promptly without hanging (received=%d, ECONNREFUSED=%d, sendErr=%v, recvErr=%v)",
		label, udpRes.Received, refused, udpRes.SendErrors, udpRes.RecvErrors)

	escaped := Select(e.Records(), func(r inet.Record) bool {
		return r.T >= from && r.Kind == "udp" && strings.HasPrefix(r.Dst, topo.Server4.String()+":")
	})
	e.T.Check(len(escaped) == 0, "%s: zero UDP datagrams leaked directly onto physical lines (%d escaped)", label, len(escaped))

	afterStats, err := ctrl.Stats(e.Ctx())
	e.T.Require(err == nil, "%s: read stats after UDP refusal (%v)", label, err)
	e.T.Check(afterStats.UnsupportedUDP > beforeStats.UnsupportedUDP && afterStats.UnsupportedUDPInfo.Lines[string(lineID)] > 0,
		"%s: unsupportedUDP counter incremented (before=%d after=%d lines=%v)",
		label, beforeStats.UnsupportedUDP, afterStats.UnsupportedUDP, afterStats.UnsupportedUDPInfo.Lines)

	probeRes, err := ctrl.Probe(e.Ctx(), fmt.Sprintf("probe-after-udp-%s-%d", lineID, time.Now().UnixNano()), lineID, engine.ProbeRequest{Target: To(topo.ProbeTargets["cloudflare"], 443), Quick: true})
	e.T.Check(err == nil && probeRes.OK,
		"%s: proxy line %s stays healthy after UDP refusal (probe ok=%v err=%v/%q)", label, lineID, probeRes.OK, err, probeRes.Error)
}

func proxyDanteSOCKS5(e *Env) {
	danted := requireTool(e, "danted")
	peerIP := setupPeerNetns(e)

	dir := filepath.Join(e.T.Dir(), "dante")
	e.T.Require(os.MkdirAll(dir, 0o777) == nil && os.Chmod(dir, 0o777) == nil, "create dante workdir")
	confPath := filepath.Join(dir, "danted.conf")
	pidPath := filepath.Join(dir, "danted.pid")
	conf := fmt.Sprintf(`logoutput: stderr
internal: %s port = 11080
external: %s
clientmethod: none
socksmethod: none
user.privileged: root
user.notprivileged: nobody
client pass {
	from: 0.0.0.0/0 to: 0.0.0.0/0
}
socks pass {
	from: 0.0.0.0/0 to: 0.0.0.0/0
	command: bind connect udpassociate
	protocol: tcp udp
}
socks pass {
	from: 0.0.0.0/0 to: 0.0.0.0/0
	command: bindreply udpreply
	protocol: tcp udp
}
`, peerIP, peerIP)
	e.T.Require(os.WriteFile(confPath, []byte(conf), 0o644) == nil, "write danted.conf")
	startPeerDaemon(e, "danted", danted, []uint16{11080}, "-f", confPath, "-p", pidPath, "-N", "1")

	pxSpec := platform.ProxyLine{
		Protocol: "socks5",
		Server:   netip.AddrPortFrom(peerIP, 11080).String(),
		UDP:      true,
		Carrier:  "b",
	}
	cfg := e.DefaultConfig()
	cfg.Lines = append(cfg.Lines, engine.Line{ID: "px-dante", Proxy: &pxSpec})
	cfg.Policy.Pins = []engine.Pin{
		{App: e.App("bravo"), Line: "px-dante"},
		{App: e.App("charlie"), Line: "c"},
	}
	e.StartEngine(cfg)

	_, ctrl := e.v1()
	testRes, err := ctrl.TestProxyLine(e.Ctx(), "test-dante-1", pxSpec, engine.ProxyCredential{}, To(topo.ProbeTargets["cloudflare"], 443))
	e.T.Check(err == nil && testRes.OK, "TestProxyLine against live Dante succeeds (ok=%v err=%v/%q)", testRes.OK, err, testRes.Error)

	e.ExpectTCP("alpha unpinned stays on a", "alpha", AsUser, "a", topo.Server4, 3)
	expectSeenTCP(e, "bravo TCP via Dante SOCKS5", "bravo", peerIP, 4)
	expectSeenHTTP(e, "bravo HTTP via Dante SOCKS5", "bravo", peerIP)
	expectSeenUDP(e, "bravo UDP via Dante SOCKS5 UDP ASSOCIATE", "bravo", peerIP, 5)

	// Carrier binding proof: taking line a down leaves px-dante (bound to carrier b) working;
	// taking carrier b down breaks px-dante until b recovers.
	e.T.Require(e.Net.UplinkDown(e.Ctx(), "a") == nil, "take carrier a down")
	expectSeenTCP(e, "bravo via Dante survives line a outage", "bravo", peerIP, 3)
	e.T.Require(e.Net.UplinkUp(e.Ctx(), "a") == nil, "bring carrier a back up")

	e.T.Require(e.Net.UplinkDown(e.Ctx(), "b") == nil, "take carrier b down")
	broken := e.TCP("bravo", AsUser, "--to", To(topo.Server4, wire.PortWhoami), "--count", "2", "--timeout", "1500")
	e.T.Check(broken.OK == 0, "bravo via Dante fails closed when bound carrier b is down (ok=%d)", broken.OK)
	e.T.Require(e.Net.UplinkUp(e.Ctx(), "b") == nil, "bring carrier b back up")
	expectSeenTCP(e, "bravo via Dante recovers when carrier b returns", "bravo", peerIP, 3)
}

func proxy3ProxyAuth(e *Env) {
	bin3proxy := requireTool(e, "NSACCEPT_3PROXY_BIN", "3proxy")
	peerIP := setupPeerNetns(e)

	dir := filepath.Join(e.T.Dir(), "3proxy")
	e.T.Require(os.MkdirAll(dir, 0o755) == nil, "create 3proxy workdir")
	confPath := filepath.Join(dir, "3proxy.cfg")
	conf := fmt.Sprintf(`nserver %s
nscache 65536
timeouts 1 5 30 60 180 1800 15 60
users nsuser:CL:nspass
auth strong
allow nsuser
socks -p11081 -i%s -e%s
proxy -p13128 -i%s -e%s
flush
`, topo.Server4, peerIP, peerIP, peerIP, peerIP)
	e.T.Require(os.WriteFile(confPath, []byte(conf), 0o600) == nil, "write 3proxy.cfg")
	startPeerDaemon(e, "3proxy", bin3proxy, []uint16{11081, 13128}, confPath)

	socksSpec := platform.ProxyLine{
		Protocol:       "socks5",
		Server:         netip.AddrPortFrom(peerIP, 11081).String(),
		UDP:            true,
		CredentialsRef: "px-3p-socks",
		Carrier:        "b",
	}
	httpSpec := platform.ProxyLine{
		Protocol:       "http",
		Server:         netip.AddrPortFrom(peerIP, 13128).String(),
		CredentialsRef: "px-3p-http",
		Carrier:        "b",
	}
	cfg := e.DefaultConfig()
	cfg.Lines = append(cfg.Lines,
		engine.Line{ID: "px-3p-socks", Proxy: &socksSpec},
		engine.Line{ID: "px-3p-http", Proxy: &httpSpec},
	)
	cfg.ProxyCredentials = map[engine.LineID]engine.ProxyCredential{
		"px-3p-socks": {Username: "nsuser", Password: "nspass"},
		"px-3p-http":  {Username: "nsuser", Password: "nspass"},
	}
	cfg.Policy.Pins = []engine.Pin{
		{App: e.App("bravo"), Line: "px-3p-socks"},
		{App: e.App("charlie"), Line: "px-3p-http"},
		{App: e.App("delta"), Line: "b"},
	}
	e.StartEngine(cfg)

	_, ctrl := e.v1()
	badTest, err := ctrl.TestProxyLine(e.Ctx(), "test-3p-bad", socksSpec, engine.ProxyCredential{Username: "nsuser", Password: "wrong"}, To(topo.ProbeTargets["cloudflare"], 443))
	e.T.Check(err == nil && !badTest.OK && (badTest.ErrorKind == "auth" || badTest.ErrorKind == "proxy-rejected"),
		"TestProxyLine rejects wrong 3proxy SOCKS5 password (res=%+v err=%v)", badTest, err)
	badHTTPTest, err := ctrl.TestProxyLine(e.Ctx(), "test-3p-http-bad", httpSpec, engine.ProxyCredential{Username: "nsuser", Password: "wrong"}, To(topo.ProbeTargets["cloudflare"], 443))
	e.T.Check(err == nil && !badHTTPTest.OK && badHTTPTest.ErrorKind == "auth",
		"TestProxyLine rejects wrong 3proxy HTTP password with 407 auth (res=%+v err=%v)", badHTTPTest, err)
	goodHTTPTest, err := ctrl.TestProxyLine(e.Ctx(), "test-3p-http-ok", httpSpec, engine.ProxyCredential{Username: "nsuser", Password: "nspass"}, To(topo.ProbeTargets["cloudflare"], 443))
	e.T.Check(err == nil && goodHTTPTest.OK, "TestProxyLine accepts valid 3proxy HTTP Basic credentials (res=%+v err=%v)", goodHTTPTest, err)

	expectSeenTCP(e, "bravo TCP via 3proxy SOCKS5+auth", "bravo", peerIP, 4)
	expectSeenUDP(e, "bravo UDP via 3proxy SOCKS5+auth", "bravo", peerIP, 4)
	expectSeenTCP(e, "charlie TCP via 3proxy HTTP CONNECT+Basic auth", "charlie", peerIP, 4)
	expectSeenHTTP(e, "charlie HTTP via 3proxy HTTP CONNECT+Basic auth", "charlie", peerIP)

	// Rotate px-3p-socks to an invalid password live: bravo fails closed while carrier b (delta) and px-3p-http (charlie) remain healthy.
	e.T.Require(ctrl.SetProxyCredentials(e.Ctx(), map[engine.LineID]engine.ProxyCredential{
		"px-3p-socks": {Username: "nsuser", Password: "wrongpassword"},
		"px-3p-http":  {Username: "nsuser", Password: "nspass"},
	}) == nil, "rotate proxy credentials")
	authFail := e.TCP("bravo", AsUser, "--to", To(topo.Server4, wire.PortWhoami), "--count", "2", "--timeout", "2000")
	e.T.Check(authFail.OK == 0, "bravo fails closed on invalid SOCKS5 password (ok=%d)", authFail.OK)
	e.ExpectTCP("delta on carrier b stays healthy during proxy auth failure", "delta", AsUser, "b", topo.Server4, 3)
	expectSeenTCP(e, "charlie on 3proxy HTTP stays healthy", "charlie", peerIP, 3)
}

func proxyMicroSocksTCPOnly(e *Env) {
	microsocks := requireTool(e, "microsocks")
	peerIP := setupPeerNetns(e)

	startPeerDaemon(e, "microsocks", microsocks, []uint16{11082},
		"-i", peerIP.String(), "-p", "11082", "-b", peerIP.String(), "-u", "nsuser", "-P", "nspass")

	pxSpec := platform.ProxyLine{
		Protocol:       "socks5",
		Server:         netip.AddrPortFrom(peerIP, 11082).String(),
		UDP:            true, // intentionally true so MicroSocks's real RFC 1928 0x07 reply is exercised live
		CredentialsRef: "px-micro",
		Carrier:        "b",
	}
	cfg := e.DefaultConfig()
	cfg.Lines = append(cfg.Lines, engine.Line{ID: "px-micro", Proxy: &pxSpec})
	cfg.ProxyCredentials = map[engine.LineID]engine.ProxyCredential{
		"px-micro": {Username: "nsuser", Password: "nspass"},
	}
	cfg.Policy.Pins = []engine.Pin{
		{App: e.App("bravo"), Line: "px-micro"},
	}
	e.StartEngine(cfg)

	_, ctrl := e.v1()
	microTest, err := ctrl.TestProxyLine(e.Ctx(), "test-micro", pxSpec, engine.ProxyCredential{Username: "nsuser", Password: "nspass"}, To(topo.ProbeTargets["cloudflare"], 443))
	e.T.Check(err == nil && microTest.OK && microTest.UDPOK != nil && !*microTest.UDPOK,
		"TestProxyLine reports MicroSocks TCP OK with UDPOK=false (res=%+v err=%v)", microTest, err)

	expectSeenTCP(e, "bravo TCP via MicroSocks", "bravo", peerIP, 4)
	expectSeenHTTP(e, "bravo HTTP via MicroSocks", "bravo", peerIP)
	expectUDPRefusedWithZeroLeak(e, "bravo UDP on TCP-only MicroSocks", "bravo", "px-micro", 4)
	expectSeenTCP(e, "bravo TCP still works after MicroSocks UDP refusal", "bravo", peerIP, 3)
}

func generateSquidCerts(dir string, ip netip.Addr, dnsName string) (caPEM []byte, certPath, keyPath string, err error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", "", err
	}
	now := time.Now().Add(-time.Hour)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Net Switch Squid Test CA"},
		NotBefore:             now,
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, "", "", err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, "", "", err
	}
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", "", err
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    now,
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{dnsName},
		IPAddresses:  []net.IP{net.IP(ip.AsSlice())},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return nil, "", "", err
	}
	srvKeyDER, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		return nil, "", "", err
	}
	certPath = filepath.Join(dir, "squid.crt")
	keyPath = filepath.Join(dir, "squid.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER}), 0o644); err != nil {
		return nil, "", "", err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: srvKeyDER}), 0o644); err != nil {
		return nil, "", "", err
	}
	return caPEM, certPath, keyPath, nil
}

func proxySquidHTTPAndTLS(e *Env) {
	squid := requireTool(e, "squid")
	peerIP := setupPeerNetns(e)

	// Squid drops privileges to user "proxy", so put its runtime files in a world-accessible temp folder.
	squidDir, err := os.MkdirTemp("", "ns-squid-*")
	e.T.Require(err == nil && os.Chmod(squidDir, 0o777) == nil, "create squid temp dir (%v)", err)
	e.T.Cleanup(func() { _ = os.RemoveAll(squidDir) })

	caPEM, certPath, keyPath, err := generateSquidCerts(squidDir, peerIP, "squid.ns.test")
	e.T.Require(err == nil, "generate squid TLS certificates (%v)", err)

	probeCAPath := filepath.Join(e.Net.InetDir(), "probe-ca.pem")
	probeCA, err := os.ReadFile(probeCAPath)
	e.T.Require(err == nil, "read probe-ca.pem (%v)", err)
	combinedCAPath := filepath.Join(squidDir, "combined-ca.pem")
	combined := append(append([]byte{}, probeCA...), '\n')
	combined = append(combined, caPEM...)
	e.T.Require(os.WriteFile(combinedCAPath, combined, 0o644) == nil, "write combined CA bundle")
	e.engineExtraEnv = []string{"SSL_CERT_FILE=" + combinedCAPath}

	confPath := filepath.Join(squidDir, "squid.conf")
	// Allow CONNECT to 443, PortWhoami (7003), and PortHTTP (8080); deny PortStream (7002) with Squid's real 403 Forbidden.
	conf := fmt.Sprintf(`pid_filename %s/squid.pid
access_log stdio:%s/access.log
cache_log %s/cache.log
coredump_dir %s
cache deny all
visible_hostname squid.ns.test
dns_nameservers %s

http_port %s:13128
https_port %s:13129 tls-cert=%s tls-key=%s

acl SSL_ports port 443 %d %d
acl CONNECT method CONNECT
http_access deny CONNECT !SSL_ports
http_access allow all
`, squidDir, squidDir, squidDir, squidDir, topo.Server4,
		peerIP, peerIP, certPath, keyPath, wire.PortWhoami, wire.PortHTTP)
	e.T.Require(os.WriteFile(confPath, []byte(conf), 0o644) == nil, "write squid.conf")

	startPeerDaemon(e, "squid-openssl", squid, []uint16{13128, 13129}, "-N", "-f", confPath)

	tlsSpec := platform.ProxyLine{
		Protocol:   "https",
		Server:     netip.AddrPortFrom(peerIP, 13129).String(),
		ServerName: "squid.ns.test",
		Carrier:    "b",
	}
	httpSpec := platform.ProxyLine{
		Protocol: "http",
		Server:   netip.AddrPortFrom(peerIP, 13128).String(),
		Carrier:  "c",
	}
	cfg := e.DefaultConfig()
	cfg.Lines = append(cfg.Lines,
		engine.Line{ID: "px-squid-tls", Proxy: &tlsSpec},
		engine.Line{ID: "px-squid-http", Proxy: &httpSpec},
	)
	cfg.Policy.Pins = []engine.Pin{
		{App: e.App("bravo"), Line: "px-squid-tls"},
		{App: e.App("charlie"), Line: "px-squid-http"},
	}
	e.StartEngine(cfg)

	_, ctrl := e.v1()
	tlsTest, err := ctrl.TestProxyLine(e.Ctx(), "test-squid-tls", tlsSpec, engine.ProxyCredential{}, To(topo.ProbeTargets["cloudflare"], 443))
	e.T.Check(err == nil && tlsTest.OK, "TestProxyLine verifies Squid HTTPS TLS certificate (res=%+v err=%v)", tlsTest, err)

	badSNISpec := tlsSpec
	badSNISpec.ServerName = "wrong.ns.test"
	badSNITest, err := ctrl.TestProxyLine(e.Ctx(), "test-squid-badsni", badSNISpec, engine.ProxyCredential{}, To(topo.ProbeTargets["cloudflare"], 443))
	e.T.Check(err == nil && !badSNITest.OK, "TestProxyLine rejects mismatched Squid TLS ServerName without InsecureSkipVerify (res=%+v err=%v)", badSNITest, err)

	expectSeenTCP(e, "bravo TCP via Squid HTTPS CONNECT", "bravo", peerIP, 4)
	expectSeenHTTP(e, "bravo HTTP via Squid HTTPS CONNECT", "bravo", peerIP)
	expectSeenTCP(e, "charlie TCP via Squid HTTP CONNECT", "charlie", peerIP, 4)

	// Squid returns 403 Forbidden for CONNECT to PortStream (7002, not in SSL_ports):
	// connection must be refused promptly, and px-squid-tls must remain healthy (non-line-fault).
	denied := e.TCP("bravo", AsUser, "--to", To(topo.Server4, wire.PortStream), "--count", "2", "--timeout", "2000")
	e.T.Check(denied.OK == 0, "Squid 403 Forbidden on disallowed port refuses the connection (ok=%d)", denied.OK)
	probeAfter403, err := ctrl.Probe(e.Ctx(), "probe-squid-after-403", "px-squid-tls", engine.ProbeRequest{Target: To(topo.ProbeTargets["cloudflare"], 443), Quick: true})
	e.T.Check(err == nil && probeAfter403.OK, "Squid 403 destination policy refusal does not fault the proxy line (probe=%+v err=%v)", probeAfter403, err)
	expectSeenTCP(e, "bravo TCP on allowed port immediately after Squid 403", "bravo", peerIP, 3)

	expectUDPRefusedWithZeroLeak(e, "bravo UDP on Squid HTTPS CONNECT", "bravo", "px-squid-tls", 4)
}

type wgKeyPair struct {
	priv, pub string
}

func genWGKeyPair(e *Env, wgBin string) wgKeyPair {
	privOut, err := exec.CommandContext(e.Ctx(), wgBin, "genkey").Output()
	e.T.Require(err == nil, "wg genkey (%v)", err)
	priv := strings.TrimSpace(string(privOut))
	cmd := exec.CommandContext(e.Ctx(), wgBin, "pubkey")
	cmd.Stdin = strings.NewReader(priv + "\n")
	pubOut, err := cmd.Output()
	e.T.Require(err == nil, "wg pubkey (%v)", err)
	return wgKeyPair{priv: priv, pub: strings.TrimSpace(string(pubOut))}
}

func setupPeerWGServer(e *Env, wgBin, linkName, cidr string, port int, srvKey wgKeyPair, clientPub, clientAllowed string) {
	ctx := e.Ctx()
	r := e.Net.R
	keyFile := filepath.Join(e.T.Dir(), linkName+"-srv.key")
	e.T.Require(os.WriteFile(keyFile, []byte(srvKey.priv+"\n"), 0o600) == nil, "write wg server key")
	e.T.Require(r.Batch(ctx, topo.CTR, []string{
		"link add " + linkName + " type wireguard",
		"addr add " + cidr + " dev " + linkName,
	}) == nil, "create %s in peer netns", linkName)
	_, err := r.In(ctx, topo.CTR, wgBin, "set", linkName,
		"private-key", keyFile,
		"listen-port", strconv.Itoa(port),
		"peer", clientPub,
		"allowed-ips", clientAllowed,
	)
	e.T.Require(err == nil, "configure %s in peer netns (%v)", linkName, err)
	_, err = r.IP(ctx, topo.CTR, "link", "set", linkName, "up")
	e.T.Require(err == nil, "bring %s up in peer netns (%v)", linkName, err)
}

func vpnWgQuickMatrix(e *Env) {
	wgBin := requireTool(e, "wg")
	wgQuick := requireTool(e, "wg-quick")
	peerIP := setupPeerNetns(e)

	// Record clean DUT snapshot before bringing up any WireGuard tunnels.
	e.Before = e.Snapshot()

	srvKey := genWGKeyPair(e, wgBin)
	cliKey := genWGKeyPair(e, wgBin)
	setupPeerWGServer(e, wgBin, "wg-srv0", "10.77.0.1/24", 51820, srvKey, cliKey.pub, "10.77.0.2/32")

	wgDir := filepath.Join(e.T.Dir(), "wg")
	e.T.Require(os.MkdirAll(wgDir, 0o700) == nil, "create wg dir")
	wgConf := filepath.Join(wgDir, "wg0.conf")

	writeWGConf := func(tableOff bool) {
		extra := ""
		if tableOff {
			extra = "Table = off\n"
		}
		text := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.77.0.2/24
%s
[Peer]
PublicKey = %s
Endpoint = %s:51820
AllowedIPs = 0.0.0.0/0
`, cliKey.priv, extra, srvKey.pub, peerIP)
		e.T.Require(os.WriteFile(wgConf, []byte(text), 0o600) == nil, "write wg0.conf")
	}

	wgUp := false
	downWG := func() {
		if wgUp {
			_, _ = e.Net.R.In(e.Ctx(), topo.DUT, wgQuick, "down", wgConf)
			wgUp = false
		}
	}
	e.T.Cleanup(func() {
		downWG()
		_, _ = e.Net.R.IP(e.Ctx(), topo.DUT, "link", "del", "wg-split")
	})

	// 1. Start order 1: full-tunnel wg-quick up BEFORE StartEngine (Exclude mode).
	writeWGConf(false)
	out, err := e.Net.R.In(e.Ctx(), topo.DUT, wgQuick, "up", wgConf)
	e.T.Require(err == nil, "wg-quick up full-tunnel before engine (%s, %v)", out, err)
	wgUp = true

	excludeLines := append([]engine.Line{{ID: "wg0", Interface: "wg0", VPN: true}}, topo.EngineLines()...)
	cfg := engine.Config{
		Lines: excludeLines,
		Policy: engine.Policy{
			Pins: []engine.Pin{
				{App: e.App("bravo"), Line: "b"},
				{App: e.App("charlie"), Line: "wg0"},
			},
		},
	}
	e.StartEngine(cfg)

	expectSeenTCP(e, "order 1 exclude mode: unpinned alpha TCP exits wg0", "alpha", peerIP, 4)
	expectSeenUDP(e, "order 1 exclude mode: unpinned alpha UDP exits wg0", "alpha", peerIP, 4)
	e.ExpectTCP("order 1 exclude mode: bravo pinned to b bypasses wg0", "bravo", AsUser, "b", topo.Server4, 4)
	e.ExpectUDP("order 1 exclude mode: bravo UDP pinned to b bypasses wg0", "bravo", AsUser, "b", topo.Server4, 4)

	// Fail-closed vs failover on VPN line wg0:
	blockedPolicy := cfg.Policy
	blockedPolicy.Blocked = []engine.LineID{"wg0"}
	e.Apply(blockedPolicy)
	from := e.Mark()
	refusedTCP := e.TCP("charlie", AsUser, "--to", To(topo.Server4, wire.PortWhoami), "--count", "3", "--timeout", "2000")
	leaked := Select(e.Records(), func(r inet.Record) bool {
		return r.T >= from && (r.Kind == "tcp" || r.Kind == "udp") && strings.HasPrefix(r.Dst, topo.Server4.String()+":")
	})
	e.T.Check(refusedTCP.OK == 0 && len(leaked) == 0,
		"fail-closed VPN line drops charlie with zero WAN leak (ok=%d leaked=%d)", refusedTCP.OK, len(leaked))

	// Restore unblocked policy and test explicit VPN failover lane wg0 -> a:
	e.Apply(cfg.Policy)
	e.SetLanes(map[engine.LineID]engine.LineID{"wg0": "a"})
	e.ExpectTCP("VPN failover lane wg0 -> a routes charlie over line a", "charlie", AsUser, "a", topo.Server4, 3)

	e.T.Require(e.StopEngine(), "stop engine after start order 1")
	downWG()

	// 2. Start order 2: StartEngine on physical lines FIRST, then wg-quick up full-tunnel live!
	physCfg := e.DefaultConfig()
	e.StartEngine(physCfg)
	e.ExpectTCP("before wg-quick up: alpha on a", "alpha", AsUser, "a", topo.Server4, 3)

	writeWGConf(false)
	out, err = e.Net.R.In(e.Ctx(), topo.DUT, wgQuick, "up", wgConf)
	e.T.Require(err == nil, "wg-quick up while engine is already capturing (%s, %v)", out, err)
	wgUp = true
	// Give Platform.monitor (250ms tick) a moment to step rule band above wg-quick's 51820 rule.
	e.Sleep(600 * time.Millisecond)

	v1, _ := e.v1()
	e.T.Require(v1.ApplyConfig(e.Ctx(), cfg) == nil, "ApplyConfig adding live wg0 as main VPN line")
	expectSeenTCP(e, "order 2 live wg-quick: unpinned alpha TCP exits wg0 without outer-UDP loop", "alpha", peerIP, 4)
	e.ExpectTCP("order 2 live wg-quick: bravo pinned to b still exits line b", "bravo", AsUser, "b", topo.Server4, 4)

	// 3. Switch wg0 to Table = off (Include mode): unpinned stays on a, pinned bravo exits wg0!
	e.T.Require(v1.ApplyConfig(e.Ctx(), physCfg) == nil, "switch back to physical lines before reconfiguring wg0")
	downWG()
	writeWGConf(true)
	out, err = e.Net.R.In(e.Ctx(), topo.DUT, wgQuick, "up", wgConf)
	e.T.Require(err == nil, "wg-quick up with Table = off (%s, %v)", out, err)
	wgUp = true

	includeLines := append(topo.EngineLines(), engine.Line{ID: "wg0", Interface: "wg0", VPN: true})
	includeCfg := engine.Config{
		Lines: includeLines,
		Policy: engine.Policy{
			Pins: []engine.Pin{
				{App: e.App("bravo"), Line: "wg0"},
				{App: e.App("charlie"), Line: "c"},
			},
		},
	}
	e.T.Require(v1.ApplyConfig(e.Ctx(), includeCfg) == nil, "ApplyConfig with Table=off wg0 in Include mode")
	e.ExpectTCP("Table=off include mode: unpinned alpha stays on physical line a", "alpha", AsUser, "a", topo.Server4, 4)
	expectSeenTCP(e, "Table=off include mode: pinned bravo TCP exits wg0", "bravo", peerIP, 4)
	expectSeenUDP(e, "Table=off include mode: pinned bravo UDP exits wg0", "bravo", peerIP, 4)

	// 4. Foreign split-tunnel VPN route (198.51.100.12/32 on unconfigured wg-split) bypasses TUN capture!
	splitSrvKey := genWGKeyPair(e, wgBin)
	splitCliKey := genWGKeyPair(e, wgBin)
	setupPeerWGServer(e, wgBin, "wg-srv1", "10.78.0.1/24", 51821, splitSrvKey, splitCliKey.pub, "10.78.0.2/32")
	splitKeyFile := filepath.Join(wgDir, "wg-split.key")
	e.T.Require(os.WriteFile(splitKeyFile, []byte(splitCliKey.priv+"\n"), 0o600) == nil, "write wg-split key")
	e.T.Require(e.Net.R.Batch(e.Ctx(), topo.DUT, []string{
		"link add wg-split type wireguard",
		"addr add 10.78.0.2/24 dev wg-split",
	}) == nil, "create wg-split in DUT")
	_, err = e.Net.R.In(e.Ctx(), topo.DUT, wgBin, "set", "wg-split",
		"private-key", splitKeyFile,
		"peer", splitSrvKey.pub,
		"endpoint", fmt.Sprintf("%s:51821", peerIP),
		"allowed-ips", "0.0.0.0/0",
	)
	e.T.Require(err == nil, "configure wg-split peer (%v)", err)
	e.T.Require(e.Net.R.Batch(e.Ctx(), topo.DUT, []string{
		"link set wg-split up",
		"route add " + topo.Third4.String() + "/32 dev wg-split",
	}) == nil, "add split-tunnel route for Third4 on wg-split")
	e.Sleep(600 * time.Millisecond)

	// Verify Third4 (198.51.100.12) bypasses Net Switch TUN and exits wg-split (seen as peerIP),
	// while Server4 (198.51.100.10) from alpha still exits physical line a!
	splitMark := e.Mark()
	splitEcho := e.UDP("alpha", AsUser, "--to", To(topo.Third4, wire.PortUDPEcho), "--count", "3", "--wait", "2000")
	echoRecords := Select(e.Records(), func(r inet.Record) bool {
		return r.T >= splitMark && r.Kind == "udp" && r.Dst == To(topo.Third4, wire.PortUDPEcho) && strings.HasPrefix(r.Src, peerIP.String()+":")
	})
	e.T.Check(splitEcho.Received == 3 && countSeenAddr(splitEcho.Seen, peerIP) == 3 && len(echoRecords) >= 3,
		"unconfigured split-VPN route %s/32 bypasses TUN capture and traverses wg-split (received=%d seen=%v records=%d)", topo.Third4, splitEcho.Received, splitEcho.Seen, len(echoRecords))
	e.ExpectTCP("non-split destination Server4 from alpha still uses physical line a", "alpha", AsUser, "a", topo.Server4, 3)

	e.T.Require(e.StopEngine(), "stop engine cleanly at end of wg-quick matrix")
	_, _ = e.Net.R.IP(e.Ctx(), topo.DUT, "link", "del", "wg-split")
	downWG()
	e.ExpectSameState("after wg-quick matrix cleanup", e.Before)
}

func vpnKillSwitchStepAside(e *Env) {
	wgBin := requireTool(e, "wg")
	wgQuick := requireTool(e, "wg-quick")
	peerIP := setupPeerNetns(e)
	e.Before = e.Snapshot()

	srvKey := genWGKeyPair(e, wgBin)
	cliKey := genWGKeyPair(e, wgBin)
	setupPeerWGServer(e, wgBin, "wg-srv0", "10.77.0.1/24", 51820, srvKey, cliKey.pub, "10.77.0.2/32")

	wgDir := filepath.Join(e.T.Dir(), "wg-ks")
	e.T.Require(os.MkdirAll(wgDir, 0o700) == nil, "create wg-ks dir")
	wgConf := filepath.Join(wgDir, "wg0.conf")
	confText := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.77.0.2/24
PostUp = nft add table ip wgkill; nft 'add chain ip wgkill output { type filter hook output priority 0; policy accept; }'; nft 'add rule ip wgkill output oifname != "%%i" meta mark != 51820 ip daddr != 127.0.0.0/8 reject'
PreDown = nft delete table ip wgkill

[Peer]
PublicKey = %s
Endpoint = %s:51820
AllowedIPs = 0.0.0.0/0
`, cliKey.priv, srvKey.pub, peerIP)
	e.T.Require(os.WriteFile(wgConf, []byte(confText), 0o600) == nil, "write wg0.conf with PostUp kill switch")

	wgUp := false
	downWG := func() {
		if wgUp {
			_, _ = e.Net.R.In(e.Ctx(), topo.DUT, wgQuick, "down", wgConf)
			wgUp = false
		}
	}
	e.T.Cleanup(func() {
		downWG()
		_, _ = e.Net.R.In(e.Ctx(), topo.DUT, "nft", "delete", "table", "inet", "mullvad")
	})

	// 1. Startup step-aside: wg-quick PostUp nftables kill switch is active BEFORE StartEngineErr.
	out, err := e.Net.R.In(e.Ctx(), topo.DUT, wgQuick, "up", wgConf)
	e.T.Require(err == nil, "wg-quick up with PostUp kill switch (%s, %v)", out, err)
	wgUp = true
	wgSnap := e.Snapshot()

	cfg := engine.Config{
		Lines: append([]engine.Line{{ID: "wg0", Interface: "wg0", VPN: true}}, topo.EngineLines()...),
	}
	startErr := e.StartEngineErr(cfg)
	e.T.Check(startErr != nil && strings.Contains(strings.ToLower(startErr.Error()), "kill switch"),
		"StartEngineErr returns kill-switch step-aside error (%v)", startErr)

	_, ctrl := e.v1()
	st, err := ctrl.Status(e.Ctx())
	e.T.Check(err == nil && st.VPNFirewall != nil && st.VPNFirewall.Blocked && st.VPNFirewall.SteppedOut && st.VPNFirewall.Blocker == "WireGuard",
		"Status reports WireGuard kill-switch step-aside (status=%+v fw=%+v err=%v)", st, st.VPNFirewall, err)

	// Zero Net Switch capture rules or TUN interfaces remain, and wg0 continues carrying traffic!
	e.ExpectSameState("DUT state unchanged while stepped aside for wg-quick kill switch", wgSnap)
	expectSeenTCP(e, "alpha continues reaching Server4 over wg0 after step-aside", "alpha", peerIP, 3)
	e.T.Require(e.StopEngine(), "stop idle stepped-aside engine")
	downWG()

	// 2. Live step-aside: engine starts cleanly on physical lines, then foreign Mullvad nftables kill switch activates!
	e.StartEngine(e.DefaultConfig())
	e.ExpectTCP("alpha on line a before live kill switch", "alpha", AsUser, "a", topo.Server4, 3)

	mullvadNft := "table inet mullvad {\n chain output {\n  type filter hook output priority 0; policy accept;\n  ip daddr 198.18.0.2 drop\n }\n}\n"
	e.T.Require(e.Net.R.Nft(e.Ctx(), topo.DUT, mullvadNft) == nil, "install live Mullvad nftables kill switch")

	_, ctrl = e.v1()
	var liveFW *platform.VPNFirewall
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		st, err := ctrl.Status(e.Ctx())
		if err == nil && st.VPNFirewall != nil && st.VPNFirewall.SteppedOut {
			liveFW = st.VPNFirewall
			break
		}
		e.Sleep(100 * time.Millisecond)
	}
	e.T.Check(liveFW != nil && liveFW.Blocked && liveFW.SteppedOut && liveFW.Blocker == "Mullvad VPN",
		"live Mullvad nftables kill switch triggers step-aside within 3s (fw=%+v)", liveFW)

	_, _ = e.Net.R.In(e.Ctx(), topo.DUT, "nft", "delete", "table", "inet", "mullvad")
	e.T.Require(e.StopEngine(), "stop engine after live step-aside")
	e.ExpectSameState("after kill-switch test cleanup", e.Before)
}
