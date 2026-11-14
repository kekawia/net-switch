package protocol

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/proxy"
)

type proxyRuntimeFake struct {
	*runtimeFake
	mu         sync.Mutex
	creds      map[string]proxy.Credentials
	lastTest   platform.ProxyLine
	lastTestCr proxy.Credentials
	lastTarget string
	firewall   *platform.VPNFirewall
}

func (p *proxyRuntimeFake) SetProxyCredentials(creds map[string]proxy.Credentials) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.creds = creds
}

func (p *proxyRuntimeFake) TestProxyLine(_ context.Context, cfg platform.ProxyLine, creds proxy.Credentials, target string) (platform.ProxyTestResult, error) {
	p.mu.Lock()
	p.lastTest = cfg
	p.lastTestCr = creds
	p.lastTarget = target
	p.mu.Unlock()
	udpOK := cfg.Protocol == "socks5" && cfg.UDP
	v6OK := true
	lat := 14.0
	return platform.ProxyTestResult{
		OK:        true,
		LatencyMS: &lat,
		UDPOK:     &udpOK,
		IPv6OK:    &v6OK,
	}, nil
}

func (p *proxyRuntimeFake) VPNFirewall() *platform.VPNFirewall {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.firewall == nil {
		return nil
	}
	cp := *p.firewall
	return &cp
}

func TestProxyProtocolFencingZeroLeakAndVPNFirewallStatus(t *testing.T) {
	f := flows.New(flows.Defaults(), nil)
	rt := &proxyRuntimeFake{runtimeFake: &runtimeFake{table: f}}
	s := New(rt, f, nil)

	helloReply := call(t, s, Request{ID: "h-1", Method: "hello"})
	var hello struct {
		Capabilities []string `json:"capabilities"`
	}
	rawHello, err := json.Marshal(helloReply.Result)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rawHello, &hello); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(hello.Capabilities, "proxy-lines") {
		t.Fatalf("missing proxy-lines capability: %v", hello.Capabilities)
	}

	attachReply := call(t, s, Request{ID: "att-1", Method: "attach", Instance: s.Instance})
	var attached struct {
		Epoch uint64 `json:"epoch"`
	}
	rawAttach, err := json.Marshal(attachReply.Result)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rawAttach, &attached); err != nil {
		t.Fatal(err)
	}

	secretValue := strings.Repeat("x", 10) + "-unit"
	var wireCred ProxyCredential
	wireCred.Username = "alice"
	wireCred.Password = secretValue
	credMap := map[string]ProxyCredential{"cred-1": wireCred}

	// Unfenced / stale epoch must be rejected.
	bad := s.Handle(context.Background(), Request{
		ID: "set-bad", Method: "setProxyCredentials", Instance: s.Instance, Epoch: 0, Credentials: credMap,
	})
	if bad.Error == "" {
		t.Fatal("expected unfenced setProxyCredentials to fail")
	}

	// Valid epoch stores credentials without leaking secret into status, stats, or operation cache.
	call(t, s, Request{
		ID: "set-ok", Method: "setProxyCredentials", Instance: s.Instance, Epoch: attached.Epoch, Credentials: credMap,
	})
	rt.mu.Lock()
	gotCred, ok := rt.creds["cred-1"]
	rt.mu.Unlock()
	if !ok || gotCred.Username != "alice" || gotCred.Password != secretValue {
		t.Fatalf("unexpected stored credential metadata: ok=%v user=%q", ok, gotCred.Username)
	}

	var spec ProxyTestSpec
	spec.Line = platform.ProxyLine{Protocol: "socks5", Server: "127.0.0.1:1080", Carrier: "local", UDP: true}
	spec.Username = "alice"
	spec.Password = secretValue
	testReply := call(t, s, Request{
		ID: "test-proxy", Method: "testProxyLine", Instance: s.Instance, Epoch: attached.Epoch, ProxyTest: &spec,
	})
	rawTest, err := json.Marshal(testReply.Result)
	if err != nil {
		t.Fatal(err)
	}
	var parsedTest platform.ProxyTestResult
	if err := json.Unmarshal(rawTest, &parsedTest); err != nil {
		t.Fatal(err)
	}
	if !parsedTest.OK || parsedTest.UDPOK == nil || !*parsedTest.UDPOK || parsedTest.LatencyMS == nil || *parsedTest.LatencyMS != 14 {
		t.Fatalf("unexpected testProxyLine result: %+v", parsedTest)
	}

	rt.mu.Lock()
	rt.firewall = &platform.VPNFirewall{
		Blocked:    true,
		SteppedOut: true,
		Blocker:    "Proton VPN",
		Reason:     "WFP block filter prevents Net Switch TUN egress",
	}
	rt.mu.Unlock()

	statusReply := call(t, s, Request{ID: "st-1", Method: "status", Instance: s.Instance, Epoch: attached.Epoch})
	rawStatus, err := json.Marshal(statusReply)
	if err != nil {
		t.Fatal(err)
	}
	statsReply := call(t, s, Request{ID: "stats-1", Method: "stats", Instance: s.Instance, Epoch: attached.Epoch})
	rawStats, err := json.Marshal(statsReply)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawStatus), secretValue) || strings.Contains(string(rawStats), secretValue) {
		t.Fatal("proxy secret leaked in status or stats reply")
	}
	var st Status
	buf, _ := json.Marshal(statusReply.Result)
	if err := json.Unmarshal(buf, &st); err != nil {
		t.Fatal(err)
	}
	if st.VPNFirewall == nil || !st.VPNFirewall.Blocked || !st.VPNFirewall.SteppedOut || st.VPNFirewall.Blocker != "Proton VPN" {
		t.Fatalf("expected VPNFirewall in status, got %+v", st.VPNFirewall)
	}
}
