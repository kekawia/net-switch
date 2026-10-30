package lifecycle_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	wirebinary "encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/apppath"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	winengine "github.com/AyoubAchour/net-switch/internal/engine/windows"
	"github.com/AyoubAchour/net-switch/internal/lifecycle"
	"github.com/AyoubAchour/net-switch/internal/lines"
	"github.com/AyoubAchour/net-switch/internal/service"
)

type installedISP struct {
	Index                         int `json:"index"`
	Alias, Address, Control, GUID string
	token                         string
}

func installedPowerShell(t *testing.T, script string, env ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "pwsh.exe", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop'; "+script)
	cmd.Env = append(os.Environ(), env...)
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal("installed fixture PowerShell", err, string(b))
	}
	return bytes.TrimPrefix(bytes.TrimSpace(b), []byte{0xef, 0xbb, 0xbf})
}

func startInstalledISP(t *testing.T, directory, data, role, uplink, address string) *installedISP {
	t.Helper()
	i := &installedISP{token: strings.Repeat("installed-test-", 4)}
	iface, err := net.InterfaceByName(uplink)
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(data, "isp-"+role+".json")
	cmd := exec.Command(filepath.Join(directory, "testisp.exe"), "serve", "--uplink-index", strconv.Itoa(iface.Index), "--uplink-ip", address, "--state", state, "--role", role)
	cmd.Env = append(os.Environ(), "TESTISP_TOKEN="+i.token)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Logf("INSTALLED_TESTISP role=%s %s", role, output.String())
		if i.GUID != "" {
			wait(t, "TestISP fixture removal", 30*time.Second, func() bool {
				present, _, err := winengine.LeftoverAdapterPresent(i.GUID, i.Alias)
				return err == nil && !present
			})
		}
	})
	wait(t, "TestISP ready", 30*time.Second, func() bool { return lifecycle.Read(state, i) == nil && i.Index > 0 })
	script, err := filepath.Abs("../windows/testisp/network.ps1")
	if err != nil {
		t.Fatal(err)
	}
	installedPowerShell(t, "& $env:NS_SCRIPT -Action configure", "NS_SCRIPT="+script, "TESTISP_ROLE="+role, "TESTISP_INDEX="+strconv.Itoa(i.Index))
	return i
}

func (i *installedISP) request(t *testing.T, endpoint string, body any, out any) {
	t.Helper()
	method := "GET"
	var data []byte
	if body != nil {
		method = "POST"
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	r, err := http.NewRequest(method, i.Control+"/"+endpoint, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+i.token)
	r.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(r)
	if err != nil {
		t.Fatal("TestISP", endpoint, err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		b, _ := io.ReadAll(response.Body)
		t.Fatal("TestISP", endpoint, response.StatusCode, string(b))
	}
	if out != nil {
		if err := json.NewDecoder(response.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
}

func (i *installedISP) count(t *testing.T, destination string) uint64 {
	t.Helper()
	var stats struct {
		Destinations map[string]uint64 `json:"destinations"`
	}
	i.request(t, "stats", nil, &stats)
	return stats.Destinations[destination]
}

type installedTLS struct {
	target, backend string
	config          *tls.Config
}
type installedHeld struct {
	conn   *tls.Conn
	reader *bufio.Reader
	source netip.AddrPort
	flow   flows.Record
}

func installedWirePeers(t *testing.T, address string) (string, string) {
	t.Helper()
	l, err := net.Listen("tcp4", net.JoinHostPort(address, "0"))
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, r.URL.Query().Get("nonce")) })}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(l) }()
	t.Cleanup(func() { server.Close(); <-done })
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(address)})
	if err != nil {
		t.Fatal(err)
	}
	udpDone := make(chan struct{})
	go func() {
		defer close(udpDone)
		b := make([]byte, 65536)
		for {
			n, peer, err := u.ReadFromUDP(b)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			b[2] |= 0x80 // DNS response; preserve transaction and padded query.
			if _, err := u.WriteToUDP(b[:n], peer); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { u.Close(); <-udpDone })
	return l.Addr().String(), u.LocalAddr().String()
}

func installedReuse(t *testing.T, target, local string) {
	t.Helper()
	listener, err := net.Listen("tcp4", net.JoinHostPort(local, "0"))
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	for attempt := 1; attempt <= 4; attempt++ {
		dialer := net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(local), Port: port}}
		start := nativeMeasurementNow()
		conn, err := dialer.Dial("tcp4", target)
		elapsed := nativeMeasurementNow() - start
		if err != nil {
			t.Fatal("port reuse dial", attempt, port, err)
		}
		func() {
			defer conn.Close()
			if elapsed >= 100*time.Millisecond {
				t.Fatal("native port reuse exceeded 100 ms", attempt, elapsed)
			}
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			nonce := fmt.Sprintf("reuse-%d-%d", port, attempt)
			r, _ := http.NewRequest("GET", "http://"+target+"/?nonce="+nonce, nil)
			r.Close = true
			if err := r.Write(conn); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(conn)
			response, err := http.ReadResponse(reader, r)
			if err != nil {
				t.Fatal(err)
			}
			b, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || response.StatusCode != 200 || string(b) != nonce {
				t.Fatal("reuse payload", string(b), err)
			}
			if _, err := reader.ReadByte(); err != io.EOF {
				t.Fatal("server did not close first", err)
			}
		}()
		t.Logf("INSTALLED_REUSE attempt=%d source_port=%d connect=%s", attempt, port, elapsed)
		time.Sleep(500 * time.Millisecond)
	}
}

func installedUDP(t *testing.T, target, local string, size int, inspect func(netip.AddrPort)) {
	t.Helper()
	remote, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP(local)}, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	want := make([]byte, size)
	if _, err := rand.Read(want); err != nil {
		t.Fatal(err)
	}
	// Preserve the old real DNS/EDNS padded-packet proof, including QR/rcode,
	// and additionally compare every returned byte (the padding is a nonce).
	header, _ := hex.DecodeString("123401000001000000000001")
	question, _ := hex.DecodeString("076578616d706c6503636f6d0000010001")
	copy(want, header)
	copy(want[12:], question)
	opt := want[12+len(question):]
	clear(opt[:15])
	padding := len(opt) - 15
	wirebinary.BigEndian.PutUint16(opt[1:3], 41)
	wirebinary.BigEndian.PutUint16(opt[3:5], 4096)
	wirebinary.BigEndian.PutUint16(opt[9:11], uint16(4+padding))
	wirebinary.BigEndian.PutUint16(opt[11:13], 12)
	wirebinary.BigEndian.PutUint16(opt[13:15], uint16(padding))
	if n, err := conn.Write(want); err != nil || n != size {
		t.Fatal("UDP send", n, err)
	}
	got := make([]byte, size+1)
	n, err := conn.Read(got)
	want[2] |= 0x80
	if err != nil || n != size || !bytes.Equal(got[:n], want) {
		t.Fatal("UDP payload mismatch", size, n, err)
	}
	if inspect != nil {
		inspect(netip.MustParseAddrPort(conn.LocalAddr().String()))
	}
	t.Logf("INSTALLED_UDP bytes=%d source=%s target=%s", size, conn.LocalAddr(), target)
}

func installedTLSFixture(t *testing.T, address string) installedTLS {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	root, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, IPAddresses: []net.IP{net.ParseIP("198.19.128.2")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(root)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	l, err := net.Listen("tcp4", net.JoinHostPort(address, "0"))
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, r.URL.Query().Get("nonce"))
	}), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der, root}, PrivateKey: key}}}}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.ServeTLS(l, "", "") }()
	t.Cleanup(func() { server.Close(); <-done })
	_, port, _ := net.SplitHostPort(l.Addr().String())
	return installedTLS{target: "198.19.128.2:" + port, backend: l.Addr().String(), config: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: "198.19.128.2"}}
}

func (h *installedHeld) refresh(t *testing.T, target string) {
	t.Helper()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	want := hex.EncodeToString(nonce[:])
	if err := h.conn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}
	r, err := http.NewRequest("GET", "https://"+target+"/?nonce="+want, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Write(h.conn); err != nil {
		t.Fatal("held TLS write", err)
	}
	response, err := http.ReadResponse(h.reader, r)
	if err != nil {
		t.Fatal("held TLS read", err)
	}
	b, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || string(b) != want {
		t.Fatal("verified HTTPS nonce", response.StatusCode, string(b), err)
	}
	if h.conn.LocalAddr().String() != h.source.String() {
		t.Fatal("held client tuple changed")
	}
}

func openInstalledTLS(t *testing.T, fixture installedTLS, count int) []*installedHeld {
	t.Helper()
	var held []*installedHeld
	for range count {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 20 * time.Second}, "tcp4", fixture.target, fixture.config)
		if err != nil {
			t.Fatal("verified TLS connect", err)
		}
		t.Cleanup(func() { conn.Close() })
		if len(conn.ConnectionState().VerifiedChains) == 0 {
			t.Fatal("TLS has no verified chain")
		}
		h := &installedHeld{conn: conn, reader: bufio.NewReader(conn), source: netip.MustParseAddrPort(conn.LocalAddr().String())}
		h.refresh(t, fixture.target)
		held = append(held, h)
	}
	return held
}

func (f *installedFixture) assertHeld(t *testing.T, held []*installedHeld, target, lane, line, physical string, revision uint64) {
	t.Helper()
	all := f.flows(t)
	ids := map[uint64]bool{}
	destination := netip.MustParseAddrPort(target)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range held {
		var got *flows.Record
		for n := range all {
			r := &all[n]
			if r.Protocol == "tcp" && r.Source == h.source && r.Destination == destination {
				if got != nil {
					t.Fatal("duplicate native tuple", h.source)
				}
				got = r
			}
		}
		if got == nil {
			t.Fatal("held native flow missing", h.source, destination, all)
		}
		if got.ID == 0 || ids[got.ID] {
			t.Fatal("held native IDs are not distinct", got.ID)
		}
		ids[got.ID] = true
		if got.Owner.PID != uint32(os.Getpid()) || !strings.EqualFold(got.Owner.Path, exe) || got.Owner.AppID != apppath.Key(exe) || got.Lane != lane || got.Line != line || got.PhysicalSource.String() != physical || got.Revision != revision || got.Closing || got.Handshake {
			t.Fatalf("native flow differs from independent expectation: %+v lane=%s line=%s source=%s revision=%d", *got, lane, line, physical, revision)
		}
		if h.flow.ID != 0 && (h.flow.ID != got.ID || !h.flow.Start.Equal(got.Start) || h.flow.Revision != got.Revision || h.flow.Epoch != got.Epoch || h.flow.Point != got.Point || !reflect.DeepEqual(h.flow.Owner, got.Owner)) {
			t.Fatal("held flow was replaced", h.flow, *got)
		}
		h.flow = *got
	}
}

func (f *installedFixture) change(t *testing.T, route string, body any) uint64 {
	t.Helper()
	if code, b := f.api(t, "POST", route, body); code != 200 {
		t.Fatal(route, code, string(b))
	}
	s := f.observe(t)
	desired := controlDesired(t, f.data)
	native, err := lifecycle.NativeRevision(desired)
	if err != nil || s.Applied == nil || native.N != s.Applied.N || native.Hash != s.Applied.Hash || s.Applied.Point == 0 {
		t.Fatal("Control desired revision lacks native acknowledgement", desired, s, err)
	}
	return native.N
}

func (f *installedFixture) routing(t *testing.T, on bool) {
	t.Helper()
	if code, b := f.api(t, "POST", "/api/routing", map[string]any{"on": on}); code != 200 {
		t.Fatal("routing", code, string(b))
	}
	if on {
		waitRouting(t, f.client, "installed routing on", 120*time.Second, func(s status) bool { return s.Routing == "on" && s.Instance != "" })
		f.observe(t)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := service.WaitStopped(ctx, service.Engine); err != nil {
		t.Fatal(err)
	}
	if f.observer != nil {
		f.observer.Close()
		f.observer = nil
	}
	f.instance, f.epoch = "", 0
	s, err := service.Query(service.Engine)
	if err != nil || !s.Stopped || !s.ExitKnown || s.ExitCode != 0 || s.Cleanup != "complete" {
		t.Fatal("routing off lacks completed native cleanup", s, err)
	}
}

func TestInstalledNativeTraffic(t *testing.T) {
	requireInstalledHarness(t)
	dir := os.Getenv("NETSWITCH_LIFECYCLE_DIR")
	uplink, address := primaryInterface(t)
	data := installedRoot(t)
	dnsScript, err := filepath.Abs("../../scripts/tun-test-network.ps1")
	if err != nil {
		t.Fatal(err)
	}
	var dns struct {
		Index  int      `json:"index"`
		Static string   `json:"staticDns"`
		DNS    []string `json:"dns"`
	}
	// Capture the actual uplink before the product TUN changes route lookup.
	if err := json.Unmarshal(installedPowerShell(t, "& $env:NS_SCRIPT -Action inspect", "NS_SCRIPT="+dnsScript), &dns); err != nil {
		t.Fatal(err)
	}
	// TestISP defaults remain secondary. The additional primary is confined to
	// this fixture: both public destinations are mapped by external gateways,
	// never by a production route rewrite. Each path has its own source/counters.
	primary := startInstalledISP(t, dir, data, "primary", uplink, address)
	secondary := startInstalledISP(t, dir, data, "secondary", uplink, address)
	tlsFixture := installedTLSFixture(t, address)
	_, port, _ := net.SplitHostPort(tlsFixture.backend)
	tlsPort, _ := strconv.Atoi(port)
	reuseBackend, udpBackend := installedWirePeers(t, address)
	_, reusePort, _ := net.SplitHostPort(reuseBackend)
	_, udpPort, _ := net.SplitHostPort(udpBackend)
	reuseNumber, _ := strconv.Atoi(reusePort)
	udpNumber, _ := strconv.Atoi(udpPort)
	reuseTarget, udpTarget := "198.19.128.2:"+reusePort, "198.19.128.2:"+udpPort
	for _, isp := range []*installedISP{primary, secondary} {
		isp.request(t, "targets", map[string]any{"ports": []int{tlsPort, reuseNumber, udpNumber}}, nil)
	}
	installedReuse(t, reuseTarget, secondary.Address)
	for _, size := range []int{64, 1800} {
		installedUDP(t, udpTarget, secondary.Address, size, nil)
	}
	f := newInstalledFixture(t, filepath.Join(data, "store"))
	canary := exec.Command("pwsh.exe", "-NoProfile", "-NonInteractive", "-Command", "[Console]::WriteLine('ready'); Start-Sleep -Seconds 1200")
	ready, err := canary.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := canary.Start(); err != nil {
		t.Fatal(err)
	}
	readyDeadline := time.AfterFunc(30*time.Second, func() { _ = canary.Process.Kill() })
	defer readyDeadline.Stop()
	t.Cleanup(func() { _ = canary.Process.Kill(); _ = canary.Wait() })
	if line, err := bufio.NewReader(ready).ReadString('\n'); err != nil || strings.TrimSpace(line) != "ready" {
		t.Fatal("SYSTEM canary readiness", line, err)
	}
	readyDeadline.Stop()
	canaryImage := nativeImage(t, uint32(canary.Process.Pid))
	canaryCreated := installedProcessIdentity(t, uint32(canary.Process.Pid), canaryImage)
	assertCanary := func() {
		if got := installedProcessIdentity(t, uint32(canary.Process.Pid), canaryImage); got != canaryCreated {
			t.Fatal("SYSTEM canary process incarnation changed", got, canaryCreated)
		}
	}
	assertCanary()
	stale := filepath.Join(f.data, "engine.pid")
	if err := os.WriteFile(stale, []byte(strconv.Itoa(canary.Process.Pid)), 0600); err != nil {
		t.Fatal(err)
	}
	f.start(t, map[string]any{"lines": []lines.Line{{ID: "aa", Alias: primary.Alias, Label: "Main fixture", Weight: 1}, {ID: "bb", Alias: secondary.Alias, Label: "Secondary fixture", Weight: 1}}, "ipv6": "off", "checkForUpdates": false})
	if index, routes, err := nativeTUNState(0); err != nil || index != 0 || routes != 0 {
		t.Fatal("capture existed before fixture routing", index, routes, err)
	}
	f.routing(t, true)
	assertCanary()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	closeHeld := func(held []*installedHeld) {
		for _, h := range held {
			h.conn.Close()
		}
	}
	if !t.Run("default-pinned-combined-pinned-main", func(t *testing.T) {
		r := f.change(t, "/api/app-line", map[string]any{"path": exe, "line": nil})
		h := openInstalledTLS(t, tlsFixture, 3)
		f.assertHeld(t, h, tlsFixture.target, "aa", "aa", primary.Address, r)
		closeHeld(h)
		r = f.change(t, "/api/app-line", map[string]any{"path": exe, "line": "bb"})
		h = openInstalledTLS(t, tlsFixture, 3)
		f.assertHeld(t, h, tlsFixture.target, "bb", "bb", secondary.Address, r)
		closeHeld(h)
		f.change(t, "/api/app-line", map[string]any{"path": exe, "line": nil})
		r = f.change(t, "/api/combine", map[string]any{"on": true, "mode": "manual", "weights": map[string]float64{"aa": 1, "bb": 1}})
		var shares struct {
			Lines []struct {
				Share float64 `json:"share"`
			} `json:"lines"`
		}
		code, body := f.api(t, "GET", "/api/state", nil)
		if err := json.Unmarshal(body, &shares); err != nil || code != 200 || len(shares.Lines) != 2 || shares.Lines[0].Share != .5 || shares.Lines[1].Share != .5 {
			t.Fatal("manual shares must both be one half", string(body), err)
		}
		h = openInstalledTLS(t, tlsFixture, 12)
		all := f.flows(t)
		counts := map[string]int{}
		for _, held := range h {
			for _, row := range all {
				if row.Source == held.source && row.Destination.String() == tlsFixture.target {
					counts[row.Line]++
					physical := primary.Address
					if row.Line == "bb" {
						physical = secondary.Address
					}
					f.assertHeld(t, []*installedHeld{held}, tlsFixture.target, row.Line, row.Line, physical, r)
				}
			}
		}
		if counts["aa"] < 3 || counts["bb"] < 3 || counts["aa"]+counts["bb"] != 12 {
			t.Fatal("combined distribution", counts)
		}
		closeHeld(h)
		r = f.change(t, "/api/app-line", map[string]any{"path": exe, "line": "aa"})
		before := secondary.count(t, tlsFixture.target)
		h = openInstalledTLS(t, tlsFixture, 6)
		f.assertHeld(t, h, tlsFixture.target, "aa", "aa", primary.Address, r)
		if secondary.count(t, tlsFixture.target) != before {
			t.Fatal("pinned-main traffic crossed secondary while combining")
		}
		closeHeld(h)
		f.change(t, "/api/combine", map[string]any{"on": false})
	}) {
		return
	}
	if !t.Run("verified-public-https", func(t *testing.T) {
		r := f.change(t, "/api/app-line", map[string]any{"path": exe, "line": "aa"})
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 20 * time.Second}, "tcp4", "1.1.1.1:443", &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "one.one.one.one"})
		if err != nil {
			t.Fatal("single public TLS attempt", err)
		}
		defer conn.Close()
		if len(conn.ConnectionState().VerifiedChains) == 0 {
			t.Fatal("public TLS verification missing")
		}
		h := &installedHeld{conn: conn, reader: bufio.NewReader(conn), source: netip.MustParseAddrPort(conn.LocalAddr().String())}
		f.assertHeld(t, []*installedHeld{h}, "1.1.1.1:443", "aa", "aa", primary.Address, r)
		conn.SetDeadline(time.Now().Add(20 * time.Second))
		request, _ := http.NewRequest("GET", "https://1.1.1.1/cdn-cgi/trace", nil)
		if err := request.Write(conn); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(h.reader, request)
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(io.LimitReader(response.Body, 16384))
		response.Body.Close()
		if err != nil || response.StatusCode != 200 || !strings.Contains(string(b), "ip=") {
			t.Fatal("public HTTPS trace", response.StatusCode, string(b), err)
		}
	}) {
		return
	}
	if !t.Run("udp-64-1800-and-port-reuse", func(t *testing.T) {
		r := f.change(t, "/api/app-line", map[string]any{"path": exe, "line": "bb"})
		for _, size := range []int{64, 1800} {
			installedUDP(t, udpTarget, "", size, func(source netip.AddrPort) {
				matched := 0
				for _, flow := range f.flows(t) {
					if flow.Protocol != "udp" || flow.Source != source {
						continue
					}
					matched++
					if flow.Owner.PID != uint32(os.Getpid()) || !strings.EqualFold(flow.Owner.Path, exe) || flow.Owner.AppID != apppath.Key(exe) || flow.Lane != "bb" || flow.Line != "bb" || flow.PhysicalSource.String() != secondary.Address || flow.Revision != r {
						t.Fatal("UDP native evidence", flow)
					}
				}
				if matched != 1 {
					t.Fatal("UDP native tuple count", source, matched)
				}
			})
		}
		installedReuse(t, reuseTarget, "")
	}) {
		return
	}
	if !t.Run("held-lane-change-and-independent-path-counters", func(t *testing.T) {
		r := f.change(t, "/api/app-line", map[string]any{"path": exe, "line": "bb"})
		before := secondary.count(t, tlsFixture.target)
		first := openInstalledTLS(t, tlsFixture, 3)
		f.assertHeld(t, first, tlsFixture.target, "bb", "bb", secondary.Address, r)
		if got := secondary.count(t, tlsFixture.target) - before; got != 3 {
			t.Fatal("initial secondary TLS count", got)
		}
		r = f.change(t, "/api/app-line", map[string]any{"path": exe, "line": "aa"})
		for _, h := range first {
			h.refresh(t, tlsFixture.target)
		}
		f.assertHeld(t, first, tlsFixture.target, "bb", "bb", secondary.Address, first[0].flow.Revision)
		closeHeld(first)
		before = secondary.count(t, tlsFixture.target)
		many := openInstalledTLS(t, tlsFixture, 100)
		f.assertHeld(t, many, tlsFixture.target, "aa", "aa", primary.Address, r)
		if secondary.count(t, tlsFixture.target) != before {
			t.Fatal("100 primary connections crossed secondary")
		}
		// Explicit handoff: suspend Control before attach, and retire this whole
		// instance before resuming it. DNS and lifecycle cases run with Control
		// fully active again. No hidden epoch theft or competing policy writer.
		priorEpoch := f.epoch
		suspendAdapter(t, f.control.PID)
		resumed := false
		defer func() {
			if !resumed {
				resumeNative(t, f.control.PID)
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		var attached struct {
			Epoch uint64 `json:"epoch"`
		}
		if err := f.observer.Call(ctx, map[string]any{"method": "attach", "engineInstanceId": f.instance}, &attached); err != nil || attached.Epoch <= priorEpoch {
			t.Fatal("explicit handoff", attached, err)
		}
		f.epoch = attached.Epoch
		client := &nativeClient{rpc: f.observer, instance: f.instance, epoch: f.epoch}
		client.renewUntilStopped(5 * time.Second)
		defer client.stopLease()
		t.Logf("INSTALLED_HANDOFF control_pid=%d instance=%s old_epoch=%d new_epoch=%d", f.control.PID, f.instance, priorEpoch, f.epoch)
		rev, err := lifecycle.NativeRevision(controlDesired(t, f.data))
		if err != nil {
			t.Fatal(err)
		}
		rev.N++
		rev.Config.Lanes["aa"] = "bb"
		rev.Hash = policy.Hash(rev.Config)
		var ack policy.Applied
		started := nativeMeasurementNow()
		nativeMust(t, client, "apply", map[string]any{"revision": rev}, &ack)
		elapsed := nativeMeasurementNow() - started
		if elapsed >= time.Second || ack.N != rev.N || ack.Hash != rev.Hash || ack.Point == 0 {
			t.Fatal("subsecond acknowledged lane update", elapsed, ack)
		}
		f.assertHeld(t, many, tlsFixture.target, "aa", "aa", primary.Address, r)
		for _, h := range many {
			h.refresh(t, tlsFixture.target)
		}
		before = secondary.count(t, tlsFixture.target)
		fresh := openInstalledTLS(t, tlsFixture, 3)
		f.assertHeld(t, fresh, tlsFixture.target, "aa", "bb", secondary.Address, rev.N)
		if got := secondary.count(t, tlsFixture.target) - before; got != 3 {
			t.Fatal("redirected secondary TLS count", got)
		}
		closeHeld(many)
		closeHeld(fresh)
		nativeMust(t, client, "stop", map[string]any{"opId": "installed-handoff-stop"}, nil)
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer stopCancel()
		if err := service.WaitStopped(stopCtx, service.Engine); err != nil {
			t.Fatal(err)
		}
		oldInstance := f.instance
		f.observer = nil
		f.instance = ""
		f.epoch = 0
		resumeNative(t, f.control.PID)
		resumed = true
		waitRouting(t, f.client, "Control owns a replacement after explicit handoff", 120*time.Second, func(s status) bool { return s.Routing == "on" && s.Instance != "" && s.Instance != oldInstance })
		f.routing(t, false)
		f.routing(t, true)
		t.Logf("INSTALLED_PATH_COUNTS secondary=+3/+0/+3 held=100 lane_apply=%s", elapsed)
	}) {
		return
	}
	if !t.Run("dns-five-held-survive-and-new-traffic", func(t *testing.T) {
		r := f.change(t, "/api/app-line", map[string]any{"path": exe, "line": "bb"})
		held := openInstalledTLS(t, tlsFixture, 5)
		f.assertHeld(t, held, tlsFixture.target, "bb", "bb", secondary.Address, r)
		for _, h := range held {
			h.refresh(t, tlsFixture.target)
		}
		env := []string{"NS_SCRIPT=" + dnsScript, "NETSWITCH_TEST_ADAPTER=" + strconv.Itoa(dns.Index), "NETSWITCH_TEST_STATIC_DNS=" + dns.Static}
		restore := func() {
			var got []string
			b := installedPowerShell(t, "$r=@(& $env:NS_SCRIPT -Action dns-restore | ConvertFrom-Json); ConvertTo-Json -InputObject $r -Compress", env...)
			if err := json.Unmarshal(b, &got); err != nil || !reflect.DeepEqual(got, dns.DNS) {
				t.Fatal("DNS restoration", string(b), dns.DNS, err)
			}
		}
		defer restore()
		var changed []string
		b := installedPowerShell(t, "$r=@(& $env:NS_SCRIPT -Action dns-change | ConvertFrom-Json); ConvertTo-Json -InputObject $r -Compress", env...)
		if err := json.Unmarshal(b, &changed); err != nil || reflect.DeepEqual(changed, dns.DNS) {
			t.Fatal("DNS did not change", string(b), err)
		}
		time.Sleep(3 * time.Second)
		f.assertHeld(t, held, tlsFixture.target, "bb", "bb", secondary.Address, r)
		for _, h := range held {
			h.refresh(t, tlsFixture.target)
		}
		restore()
		freshRevision := f.observe(t).Applied.N
		fresh := openInstalledTLS(t, tlsFixture, 1)
		f.assertHeld(t, fresh, tlsFixture.target, "bb", "bb", secondary.Address, freshRevision)
		closeHeld(held)
		closeHeld(fresh)
	}) {
		return
	}
	t.Run("twenty-clean-cycles", func(t *testing.T) {
		f.routing(t, false)
		for cycle := 1; cycle <= 20; cycle++ {
			f.routing(t, true)
			index, routes, err := nativeTUNState(0)
			if err != nil || index == 0 || routes == 0 {
				t.Fatal("capture absent before cleanup", cycle, index, routes, err)
			}
			f.routing(t, false)
			wait(t, "cycle native adapter/routes removed", 10*time.Second, func() bool { i, r, e := nativeTUNState(index); return e == nil && i == 0 && r == 0 })
			state, err := winengine.FirewallState()
			if err != nil || state["sublayer"] != false || len(state["filters"].([]map[string]any)) != 0 {
				t.Fatal("cycle WFP leftovers", cycle, state, err)
			}
			t.Logf("INSTALLED_CLEAN_CYCLE %d/20", cycle)
		}
	})
	f.quit(t)
	assertCanary()
	if b, err := os.ReadFile(stale); err != nil || string(b) != strconv.Itoa(canary.Process.Pid) {
		t.Fatal("native services touched an unowned legacy PID sentinel", string(b), err)
	}
}
