//go:build windows

package winengine

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"golang.org/x/sys/windows"
)

var (
	wfpLayerALEConnectV4    = mustGUID("{C38D57D1-05A7-4C33-904F-7FBCEEE60E82}")
	wfpLayerALEConnectV6    = mustGUID("{4A72393B-319F-44BC-84C3-BA54DCB3B6B4}")
	wfpLayerOutboundTransV4 = mustGUID("{09E61AEA-D214-46E2-9B21-B26B0B2F28C8}")
	wfpLayerOutboundTransV6 = mustGUID("{E1735BDE-013F-46C9-B351-A4995E570F8A}")
	wfpLayerOutboundIPPktV4 = mustGUID("{1E5C9FAE-8A84-4135-A331-950B54229ECD}")
	wfpLayerOutboundIPPktV6 = mustGUID("{A3B3AB6B-3564-488C-9117-F34E82142763}")

	wfpCondALEAppID      = mustGUID("{D78E1E87-8644-4EA5-9437-D809ECEFC971}")
	wfpCondALEUserID     = mustGUID("{AF043A0A-B34D-4F86-979C-C90371AF6E66}")
	wfpCondRemoteAddr    = mustGUID("{B235AE9A-1D64-49B8-A44C-5FF3D9095045}")
	wfpCondRemotePort    = mustGUID("{C35A604D-D22B-4E1A-91B4-68F674EE674B}")
	wfpOwnedSubLayerGUID = mustGUID(wfpSubLayerKey)
)

const (
	fwpActionBlock           = 0x1001
	fwpmFilterFlagClearRight = 0x0008
	fwpmFilterFlagDisabled   = 0x0020
	vpnProbeChallengeTimeout = 45 * time.Millisecond
)

var vpnProbeSerial atomic.Uint64

type wfpFilterSummary struct {
	Layer          windows.GUID
	SubLayer       windows.GUID
	SubLayerWeight uint16
	SubLayerName   string
	FilterName     string
	FilterDesc     string
	ActionType     uint32
	Flags          uint32
	Conditions     []windows.GUID
}

func isOutboundKillSwitchLayer(layer windows.GUID) bool {
	switch layer {
	case wfpLayerALEConnectV4, wfpLayerALEConnectV6,
		wfpLayerOutboundTransV4, wfpLayerOutboundTransV6,
		wfpLayerOutboundIPPktV4, wfpLayerOutboundIPPktV6:
		return true
	}
	return false
}

// classifyKillSwitchFilter determines whether an outbound WFP filter is a
// system/interface-wide hard block (such as WireGuard's "Block untunneled
// traffic", Mullvad, or Proton VPN kill switch) rather than a per-app, per-port,
// per-destination, disabled, or soft-veto Windows Firewall rule.
func classifyKillSwitchFilter(f wfpFilterSummary) (blocker string, matched bool) {
	if !isOutboundKillSwitchLayer(f.Layer) {
		return "", false
	}
	if f.SubLayer == wfpOwnedSubLayerGUID {
		return "", false
	}
	if f.ActionType != fwpActionBlock {
		return "", false
	}
	if f.Flags&fwpmFilterFlagDisabled != 0 {
		return "", false
	}
	// Soft block filters (CLEAR_ACTION_RIGHT) yield to permit rules in lower
	// sublayers (e.g. default Windows Defender Firewall base rules) unless the
	// sublayer itself sits at maximum priority weight (0xFFFF) with a VPN name.
	if f.Flags&fwpmFilterFlagClearRight != 0 && f.SubLayerWeight < 0xFFFF {
		return "", false
	}
	for _, c := range f.Conditions {
		switch c {
		case wfpCondALEAppID, wfpCondALEUserID, wfpCondRemoteAddr, wfpCondRemotePort:
			return "", false
		}
	}
	name := cleanVPNBlockerName(f.SubLayerName, f.FilterName, f.FilterDesc)
	if f.Flags&fwpmFilterFlagClearRight != 0 && name == "VPN firewall" {
		return "", false
	}
	return name, true
}

var knownVPNNames = [...]struct {
	needle, display string
}{
	{"wireguard", "WireGuard"},
	{"proton", "Proton VPN"},
	{"mullvad", "Mullvad VPN"},
	{"ivpn", "IVPN"},
	{"windscribe", "Windscribe"},
	{"nordvpn", "NordVPN"},
	{"nordlynx", "NordVPN"},
	{"surfshark", "Surfshark"},
	{"tailscale", "Tailscale"},
	{"expressvpn", "ExpressVPN"},
	{"private internet access", "Private Internet Access"},
	{"mozilla vpn", "Mozilla VPN"},
	{"cloudflare", "Cloudflare WARP"},
	{"warp", "Cloudflare WARP"},
}

func cleanVPNBlockerName(parts ...string) string {
	joined := strings.ToLower(strings.Join(parts, " "))
	for _, k := range knownVPNNames {
		if strings.Contains(joined, k.needle) {
			return k.display
		}
	}
	for _, p := range parts {
		s := strings.TrimSpace(p)
		if s == "" {
			continue
		}
		lower := strings.ToLower(s)
		if strings.HasPrefix(lower, "@") || strings.Contains(lower, "firewallapi.dll") || strings.Contains(lower, "microsoft") {
			continue
		}
		if len(s) > 64 {
			s = s[:64]
		}
		return s
	}
	return "VPN firewall"
}

func formatVPNFirewallReason(blocker string) string {
	if blocker == "" {
		blocker = "VPN firewall"
	}
	return fmt.Sprintf("%s's kill switch blocks Net Switch. Routing is paused so your VPN keeps working.", blocker)
}

// inspectForeignVPNKillSwitch performs a read-only WFP enumeration for foreign
// catch-all hard-block filters on outbound ALE/transport/packet layers.
func inspectForeignVPNKillSwitch() (blocker string, found bool, err error) {
	h, err := openWFP()
	if err != nil {
		return "", false, err
	}
	defer wfpCall("FwpmEngineClose0", uintptr(h))

	var enumHandle windows.Handle
	if err := wfpCall("FwpmFilterCreateEnumHandle0", uintptr(h), 0, uintptr(unsafe.Pointer(&enumHandle))); err != nil {
		return "", false, err
	}
	defer wfpCall("FwpmFilterDestroyEnumHandle0", uintptr(h), uintptr(enumHandle))

	type subInfo struct {
		name   string
		weight uint16
	}
	sublayers := make(map[windows.GUID]subInfo)
	lookupSubLayer := func(key windows.GUID) subInfo {
		if info, ok := sublayers[key]; ok {
			return info
		}
		var row *wfpSubLayer
		var info subInfo
		if err := wfpCall("FwpmSubLayerGetByKey0", uintptr(h), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&row))); err == nil && row != nil {
			info.name = strings.TrimSpace(windows.UTF16PtrToString(row.Display.Name) + " " + windows.UTF16PtrToString(row.Display.Description))
			info.weight = row.Weight
			wfpDLL.NewProc("FwpmFreeMemory0").Call(uintptr(unsafe.Pointer(&row)))
		}
		sublayers[key] = info
		return info
	}

	bestBlocker := ""
	bestWeight := int(-1)
	for {
		var entries **wfpFilter
		var count uint32
		if err := wfpCall("FwpmFilterEnum0", uintptr(h), uintptr(enumHandle), 256, uintptr(unsafe.Pointer(&entries)), uintptr(unsafe.Pointer(&count))); err != nil {
			return "", false, err
		}
		if count == 0 || entries == nil {
			if entries != nil {
				wfpDLL.NewProc("FwpmFreeMemory0").Call(uintptr(unsafe.Pointer(&entries)))
			}
			break
		}
		func() {
			defer wfpDLL.NewProc("FwpmFreeMemory0").Call(uintptr(unsafe.Pointer(&entries)))
			for _, row := range unsafe.Slice(entries, int(count)) {
				if row == nil || !isOutboundKillSwitchLayer(row.Layer) || row.Action.Type != fwpActionBlock {
					continue
				}
				var conds []windows.GUID
				if row.Count > 0 && row.Conditions != nil {
					conds = make([]windows.GUID, 0, int(row.Count))
					for _, c := range unsafe.Slice(row.Conditions, int(row.Count)) {
						conds = append(conds, c.Field)
					}
				}
				sub := lookupSubLayer(row.SubLayer)
				summary := wfpFilterSummary{
					Layer:          row.Layer,
					SubLayer:       row.SubLayer,
					SubLayerWeight: sub.weight,
					SubLayerName:   sub.name,
					FilterName:     windows.UTF16PtrToString(row.Display.Name),
					FilterDesc:     windows.UTF16PtrToString(row.Display.Description),
					ActionType:     row.Action.Type,
					Flags:          row.Flags,
					Conditions:     conds,
				}
				if name, ok := classifyKillSwitchFilter(summary); ok {
					w := int(sub.weight)
					if name != "VPN firewall" {
						w += 100000
					}
					if w > bestWeight {
						bestWeight = w
						bestBlocker = name
						found = true
					}
				}
			}
		}()
	}
	return bestBlocker, found, nil
}

// probeLocalTUN sends one authenticated 40-byte UDP challenge bound to tunIndex
// toward the child netstack's private 198.18.0.2:tunPort responder. No WAN
// traffic is emitted. Returns blockedByWFP=true immediately on WSAEACCES.
func probeLocalTUN(ctx context.Context, tunIndex int, tunPort uint16, healthKey []byte, timeout time.Duration) (blockedByWFP bool, timedOut bool, err error) {
	sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return false, false, err
	}
	defer sock.Close()

	raw, err := sock.SyscallConn()
	if err != nil {
		return false, false, err
	}
	var bindErr error
	if err := raw.Control(func(fd uintptr) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(tunIndex))
		bindErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIf, int(binary.LittleEndian.Uint32(b[:])))
		if bindErr == nil {
			bindErr = windows.Connect(windows.Handle(fd), &windows.SockaddrInet4{Addr: [4]byte{198, 18, 0, 2}, Port: int(tunPort)})
		}
	}); err != nil {
		return false, false, err
	}
	if bindErr != nil {
		if errors.Is(bindErr, windows.WSAEACCES) {
			return true, false, nil
		}
		return false, false, bindErr
	}

	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = sock.SetDeadline(deadline)

	var req [40]byte
	copy(req[:32], healthKey[:32])
	seq := vpnProbeSerial.Add(1)
	binary.BigEndian.PutUint64(req[32:], seq)

	if _, err := sock.Write(req[:]); err != nil {
		if errors.Is(err, windows.WSAEACCES) {
			return true, false, nil
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return false, true, nil
		}
		return false, false, err
	}

	var resp [41]byte
	for range 8 {
		n, _, err := sock.ReadFrom(resp[:])
		if err != nil {
			if errors.Is(err, windows.WSAEACCES) {
				return true, false, nil
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return false, true, nil
			}
			return false, false, err
		}
		if n == 40 && bytes.Equal(resp[:40], req[:]) {
			return false, false, nil
		}
	}
	return false, true, nil
}

// CheckVPNFirewall runs before Capture installs 0.0.0.0/1 and 128.0.0.0/1 so a
// foreign VPN kill switch blocking Wintun causes an immediate fail-open step-aside
// without touching live system routes.
func (r *Routes) CheckVPNFirewall(ctx context.Context, tunIndex int, tunPort uint16, healthKey []byte) (*platform.VPNFirewall, error) {
	if tunIndex <= 0 || tunPort == 0 || len(healthKey) != 32 {
		return nil, nil
	}
	r.fwMu.Lock()
	r.fwIndex = tunIndex
	r.fwPort = tunPort
	copy(r.fwKey[:], healthKey[:32])
	r.fwTimeouts = 0
	r.fwStepped = false
	r.fwMu.Unlock()

	var blocked, timedOut bool
	for attempt := range 2 {
		b, to, err := probeLocalTUN(ctx, tunIndex, tunPort, healthKey, vpnProbeChallengeTimeout)
		if err != nil {
			// Non-WFP transient error (e.g. context cancelled during shutdown).
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, nil
		}
		if b {
			blocked = true
			break
		}
		if !to {
			return nil, nil
		}
		timedOut = true
		if attempt == 0 {
			continue
		}
	}
	if !blocked && !timedOut {
		return nil, nil
	}
	blocker, found, _ := inspectForeignVPNKillSwitch()
	if !blocked && !found {
		return nil, nil
	}
	if blocker == "" {
		blocker = "VPN firewall"
	}
	return &platform.VPNFirewall{
		Blocked:    true,
		SteppedOut: true,
		Blocker:    blocker,
		Reason:     formatVPNFirewallReason(blocker),
	}, nil
}

func (r *Routes) checkLiveVPNFirewall(ctx context.Context) *platform.VPNFirewall {
	r.fwMu.Lock()
	idx, port, stepped := r.fwIndex, r.fwPort, r.fwStepped
	key := r.fwKey
	r.fwMu.Unlock()
	if stepped || idx <= 0 || port == 0 {
		return nil
	}
	blocked, timedOut, err := probeLocalTUN(ctx, idx, port, key[:], vpnProbeChallengeTimeout)
	if err != nil {
		return nil
	}
	if !blocked && !timedOut {
		r.fwMu.Lock()
		r.fwTimeouts = 0
		r.fwMu.Unlock()
		return nil
	}
	if timedOut && !blocked {
		r.fwMu.Lock()
		r.fwTimeouts++
		streak := r.fwTimeouts
		r.fwMu.Unlock()
		if streak < 2 {
			return nil
		}
	}
	blocker, found, _ := inspectForeignVPNKillSwitch()
	if !blocked && !found {
		return nil
	}
	if blocker == "" {
		blocker = "VPN firewall"
	}
	r.fwMu.Lock()
	if r.fwStepped {
		r.fwMu.Unlock()
		return nil
	}
	r.fwStepped = true
	r.fwMu.Unlock()
	return &platform.VPNFirewall{
		Blocked:    true,
		SteppedOut: true,
		Blocker:    blocker,
		Reason:     formatVPNFirewallReason(blocker),
	}
}
