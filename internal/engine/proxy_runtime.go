package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flowapi"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/probe"
	"github.com/AyoubAchour/net-switch/internal/engine/proxy"
)

func osLines(lines []platform.Line) []platform.Line {
	out := make([]platform.Line, 0, len(lines))
	for _, l := range lines {
		if l.Proxy != nil {
			continue
		}
		out = append(out, l)
	}
	return out
}

// SetProxyCredentials atomically replaces the engine's in-memory proxy credentials map.
func (e *Engine) SetProxyCredentials(creds map[string]proxy.Credentials) {
	if e.proxy != nil {
		e.proxy.SetCredentials(creds)
	}
}

// SetVPNFirewall publishes bounded foreign VPN firewall state for status polling.
func (e *Engine) SetVPNFirewall(fw *platform.VPNFirewall) {
	if fw == nil {
		e.vpnFirewall.Store(nil)
		return
	}
	cp := *fw
	cp.Blocker = Clip(cp.Blocker, 128)
	cp.Reason = Clip(cp.Reason, 256)
	e.vpnFirewall.Store(&cp)
}

func (e *Engine) VPNFirewall() *platform.VPNFirewall {
	fw := e.vpnFirewall.Load()
	if fw == nil {
		return nil
	}
	cp := *fw
	return &cp
}

// StepAsideForVPNFirewall tears down capture routes and TUN cleanly when a foreign
// VPN kill switch blocks TUN capture, leaving normal OS/VPN traffic unimpeded.
func (e *Engine) StepAsideForVPNFirewall(ctx context.Context, fw platform.VPNFirewall) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	fw.Blocked = true
	fw.SteppedOut = true
	e.SetVPNFirewall(&fw)
	msg := fw.Reason
	if msg == "" {
		msg = "VPN kill switch blocks Net Switch capture"
	}
	e.lastError = errors.New(msg)
	err := e.stopLocked(context.WithoutCancel(ctx))
	e.Table.Emit(flowapi.Event{Type: "vpnFirewall", Message: Clip(msg, 256)})
	return err
}

// WrapProber returns a ConfiguredProber that probes proxy lines through e.proxy
// while delegating physical and VPN lines to base.
func (e *Engine) WrapProber(base platform.Prober) platform.Prober {
	if base == nil && e.proxy == nil {
		return nil
	}
	return &engineProber{engine: e, base: base}
}

type engineProber struct {
	engine *Engine
	base   platform.Prober
}

func (p *engineProber) Probe(ctx context.Context, line, operator string) (platform.ProbeResult, error) {
	return p.ProbeConfigured(ctx, line, platform.ProbeRequest{Operator: operator})
}

func (p *engineProber) ProbeConfigured(ctx context.Context, line string, req platform.ProbeRequest) (platform.ProbeResult, error) {
	if p.engine.proxy != nil {
		if cfg, isProxy := p.engine.proxy.LineConfig(line); isProxy {
			return p.probeProxyLine(ctx, line, cfg, req)
		}
	}
	if p.base == nil {
		return platform.ProbeResult{}, platform.ErrNotYet
	}
	if configured, ok := p.base.(platform.ConfiguredProber); ok {
		return configured.ProbeConfigured(ctx, line, req)
	}
	if req.Target != "" || req.Quick || req.Custom {
		return platform.ProbeResult{}, errors.New("configured probes unavailable")
	}
	return p.base.Probe(ctx, line, req.Operator)
}

func (p *engineProber) probeProxyLine(ctx context.Context, line string, cfg platform.ProxyLine, req platform.ProbeRequest) (platform.ProbeResult, error) {
	res, err := probe.Run(ctx, req, probe.Options{
		TLS: p.engine.deps.ProbeTLS,
		Dial: func(dialCtx context.Context, dst netip.AddrPort) (net.Conn, error) {
			state, _ := p.engine.LiveState()
			if state != "on" {
				return nil, probe.ErrUnavailable
			}
			return p.engine.proxy.DialTCP(dialCtx, line, dst)
		},
	})
	if err != nil || !res.OK {
		return res, err
	}
	if cfg.Protocol == "socks5" && cfg.UDP {
		uCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		uConn, uErr := p.engine.proxy.OpenUDP(uCtx, line, false)
		cancel()
		udpOK := uErr == nil
		if uConn != nil {
			_ = uConn.Close()
		}
		res.UDPOK = &udpOK
	}
	return res, nil
}

// TestProxyLine executes an isolated connectivity check against a candidate proxy
// without mutating compiled policy or saved secrets.
func (e *Engine) TestProxyLine(ctx context.Context, spec platform.ProxyLine, creds proxy.Credentials, target string) (platform.ProxyTestResult, error) {
	if spec.Carrier == "" {
		spec.Carrier = proxy.CarrierLocal
	}
	if spec.Carrier != proxy.CarrierLocal {
		state, _ := e.LiveState()
		if state != "on" {
			return platform.ProxyTestResult{
				OK:        false,
				ErrorKind: "engineOff",
				Error:     "Turn on routing first to test a proxy through another line.",
			}, nil
		}
	}
	const testID = "_proxy_test"
	const credID = "_proxy_test_cred"
	if !creds.Empty() {
		spec.CredentialsRef = credID
	} else {
		spec.CredentialsRef = ""
	}
	d := proxy.NewDialer(e.deps.Dialer, proxy.Options{
		MaxHandshakes:      4,
		MaxUDPAssociations: 4,
		TLSConfig:          e.deps.ProbeTLS,
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
		TLS: e.deps.ProbeTLS,
		Dial: func(dialCtx context.Context, dst netip.AddrPort) (net.Conn, error) {
			c, dErr := d.DialTCP(dialCtx, testID, dst)
			if dErr != nil {
				dialErr = dErr
			}
			return c, dErr
		},
	})
	if err != nil {
		return platform.ProxyTestResult{}, err
	}
	out := platform.ProxyTestResult{
		OK:        pr.OK,
		LatencyMS: pr.LatencyMS,
	}
	if !pr.OK {
		out.Error = Clip(pr.Error, 256)
		out.ErrorKind = "unreachable"
		var pe *proxy.Error
		if errors.As(dialErr, &pe) {
			out.ErrorKind = pe.Kind.String()
		}
		return out, nil
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
	return out, nil
}
