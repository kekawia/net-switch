//go:build linux

package linux

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

	"github.com/kekawia/net-switch/internal/engine/platform"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	vpnProbeChallengeTimeout = 25 * time.Millisecond
	nlaTypeMask              = 0x3fff
	nftTableAttrName         = 1
	nftTableAttrFlags        = 2
	nftTableFlagDormant      = 0x1
)

var vpnProbeSerial atomic.Uint64

var knownLinuxVPNNames = [...]struct {
	needle, display string
}{
	{"mullvad", "Mullvad VPN"},
	{"proton", "Proton VPN"},
	{"pvpn", "Proton VPN"},
	{"ivpn", "IVPN"},
	{"windscribe", "Windscribe"},
	{"nordvpn", "NordVPN"},
	{"nordlynx", "NordVPN"},
	{"nordtun", "NordVPN"},
	{"surfshark", "Surfshark"},
	{"tailscale", "Tailscale"},
	{"wg-quick", "WireGuard"},
	{"wireguard", "WireGuard"},
	{"expressvpn", "ExpressVPN"},
	{"private internet access", "Private Internet Access"},
	{"mozilla vpn", "Mozilla VPN"},
	{"mozillavpn", "Mozilla VPN"},
	{"cloudflare", "Cloudflare WARP"},
	{"warp", "Cloudflare WARP"},
}

func matchKnownLinuxVPNName(parts ...string) string {
	joined := strings.ToLower(strings.Join(parts, " "))
	for _, k := range knownLinuxVPNNames {
		if strings.Contains(joined, k.needle) {
			return k.display
		}
	}
	for _, p := range parts {
		lower := strings.ToLower(strings.TrimSpace(p))
		if lower == "wg" || strings.HasPrefix(lower, "wg") {
			if len(lower) == 2 || (len(lower) > 2 && (lower[2] >= '0' && lower[2] <= '9' || lower[2] == '-' || lower[2] == '_')) {
				return "WireGuard"
			}
		}
	}
	return ""
}

func isSystemNftTableName(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "filter", "nat", "mangle", "raw", "security", "ufw", "firewalld", "docker", "kube", "cni", "libvirt", "lxd", "incus", "fail2ban", "crowdsec":
		return true
	}
	return false
}

func cleanLinuxVPNBlockerName(parts ...string) string {
	if vpn := matchKnownLinuxVPNName(parts...); vpn != "" {
		return vpn
	}
	for _, p := range parts {
		s := strings.TrimSpace(p)
		if s == "" || isSystemNftTableName(s) {
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

func isLinuxFirewallBlockErr(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, unix.EPERM) ||
		errors.Is(err, unix.EACCES) ||
		errors.Is(err, unix.ECONNREFUSED) ||
		errors.Is(err, unix.EHOSTUNREACH) ||
		errors.Is(err, unix.ENETUNREACH)
}

func isProbeTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// parseNftTableMsg extracts the table name from one NFT_MSG_NEWTABLE payload
// (beginning with the 4-byte nfgenmsg header). Dormant tables are ignored.
func parseNftTableMsg(data []byte) (name string, active bool) {
	if len(data) < 4 {
		return "", false
	}
	attrs := data[4:]
	dormant := false
	for len(attrs) >= 4 {
		nlaLen := int(binary.NativeEndian.Uint16(attrs[0:2]))
		nlaType := binary.NativeEndian.Uint16(attrs[2:4]) & nlaTypeMask
		if nlaLen < 4 || nlaLen > len(attrs) {
			break
		}
		val := attrs[4:nlaLen]
		switch nlaType {
		case nftTableAttrName:
			if idx := bytes.IndexByte(val, 0); idx >= 0 {
				name = string(val[:idx])
			} else {
				name = string(val)
			}
		case nftTableAttrFlags:
			if len(val) >= 4 && binary.BigEndian.Uint32(val[:4])&nftTableFlagDormant != 0 {
				dormant = true
			}
		}
		step := (nlaLen + 3) &^ 3
		if step >= len(attrs) {
			break
		}
		attrs = attrs[step:]
	}
	if dormant || name == "" {
		return "", false
	}
	return name, true
}

// listActiveNftTables performs a read-only NETLINK_NETFILTER dump of active
// nftables tables without shelling out to nft.
func listActiveNftTables() []string {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil
	}
	defer unix.Close(fd)

	tv := unix.Timeval{Usec: 50_000}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv)

	var req [unix.NLMSG_HDRLEN + 4]byte
	binary.NativeEndian.PutUint32(req[0:4], uint32(len(req)))
	binary.NativeEndian.PutUint16(req[4:6], (uint16(unix.NFNL_SUBSYS_NFTABLES)<<8)|uint16(unix.NFT_MSG_GETTABLE))
	binary.NativeEndian.PutUint16(req[6:8], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(req[8:12], 1)
	req[unix.NLMSG_HDRLEN] = unix.NFPROTO_UNSPEC
	req[unix.NLMSG_HDRLEN+1] = unix.NFNETLINK_V0

	if err := unix.Sendto(fd, req[:], 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil
	}

	buf := make([]byte, 16384)
	var names []string
	seen := make(map[string]bool)
	for range 32 {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil || n <= 0 {
			break
		}
		raw := buf[:n]
		done := false
		for len(raw) >= unix.NLMSG_HDRLEN {
			msgLen := int(binary.NativeEndian.Uint32(raw[0:4]))
			msgType := binary.NativeEndian.Uint16(raw[4:6])
			if msgLen < unix.NLMSG_HDRLEN || msgLen > len(raw) {
				done = true
				break
			}
			switch msgType {
			case unix.NLMSG_DONE, unix.NLMSG_ERROR:
				done = true
			default:
				if (msgType>>8) == unix.NFNL_SUBSYS_NFTABLES && (msgType&0xff) == unix.NFT_MSG_NEWTABLE {
					if name, ok := parseNftTableMsg(raw[unix.NLMSG_HDRLEN:msgLen]); ok && !seen[name] {
						seen[name] = true
						names = append(names, name)
					}
				}
			}
			if done {
				break
			}
			step := (msgLen + 3) &^ 3
			if step >= len(raw) {
				break
			}
			raw = raw[step:]
		}
		if done {
			break
		}
	}
	return names
}

func inspectForeignVPNKillSwitch(ownTunIndex int) string {
	tables := listActiveNftTables()
	for _, t := range tables {
		if vpn := matchKnownLinuxVPNName(t); vpn != "" {
			return vpn
		}
	}
	if links, err := netlink.LinkList(); err == nil {
		var fallbackTunnel string
		for _, link := range links {
			attrs := link.Attrs()
			if attrs == nil || attrs.Index == ownTunIndex || strings.HasPrefix(attrs.Alias, "netswitch:") {
				continue
			}
			if attrs.Flags&(net.FlagLoopback|net.FlagUp) != net.FlagUp {
				continue
			}
			if strings.EqualFold(link.Type(), "wireguard") {
				if vpn := matchKnownLinuxVPNName(attrs.Name); vpn != "" {
					return vpn
				}
				return "WireGuard"
			}
			if !isTunnelLink(link, false) {
				continue
			}
			if vpn := matchKnownLinuxVPNName(attrs.Name); vpn != "" {
				return vpn
			}
			if fallbackTunnel == "" {
				fallbackTunnel = attrs.Name
			}
		}
		if fallbackTunnel != "" {
			return cleanLinuxVPNBlockerName(fallbackTunnel)
		}
	}
	for _, t := range tables {
		if !isSystemNftTableName(t) {
			return cleanLinuxVPNBlockerName(t)
		}
	}
	return "VPN firewall"
}

// probeLocalTUN sends one authenticated 40-byte UDP challenge bound to tunIndex
// toward the netstack's private 198.18.0.2:tunPort responder. No WAN traffic is
// emitted. Returns blocked=true only when Netfilter or an explicit prohibit rule
// rejects or drops local egress to our TUN; a missing route on Connect or a read
// deadline without an explicit block error is NOT treated as a VPN firewall block.
func probeLocalTUN(ctx context.Context, tunIndex int, tunPort uint16, healthKey []byte, timeout time.Duration) (blocked bool, err error) {
	return probeLocalTUNAddr(ctx, tunIndex, [4]byte{198, 18, 0, 2}, tunPort, healthKey, timeout)
}

func probeLocalTUNAddr(ctx context.Context, tunIndex int, dst [4]byte, tunPort uint16, healthKey []byte, timeout time.Duration) (blocked bool, err error) {
	sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return false, err
	}
	defer sock.Close()

	raw, err := sock.SyscallConn()
	if err != nil {
		return false, err
	}
	var bindErr error
	if err := raw.Control(func(fd uintptr) {
		bindErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX, tunIndex)
		if bindErr == nil {
			bindErr = unix.Connect(int(fd), &unix.SockaddrInet4{Addr: dst, Port: int(tunPort)})
		}
	}); err != nil {
		return false, err
	}
	if bindErr != nil {
		if errors.Is(bindErr, unix.EPERM) || errors.Is(bindErr, unix.EACCES) {
			return true, nil
		}
		return false, bindErr
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
		if isLinuxFirewallBlockErr(err) {
			return true, nil
		}
		if isProbeTimeoutErr(err) {
			return false, nil
		}
		return false, err
	}

	var resp [41]byte
	for range 4 {
		n, _, err := sock.ReadFrom(resp[:])
		if err != nil {
			if isLinuxFirewallBlockErr(err) {
				return true, nil
			}
			if isProbeTimeoutErr(err) {
				return false, nil
			}
			return false, err
		}
		if n == 40 && bytes.Equal(resp[:40], req[:]) {
			return false, nil
		}
	}
	return false, nil
}

// CheckVPNFirewall runs before Capture installs ip rules so a foreign VPN kill
// switch blocking our TUN causes an immediate fail-open step-aside without
// capturing live host traffic.
func (p *Platform) CheckVPNFirewall(ctx context.Context, tunIndex int, tunPort uint16, healthKey []byte) (*platform.VPNFirewall, error) {
	if tunIndex <= 0 || tunPort == 0 || len(healthKey) != 32 {
		return nil, nil
	}
	p.fwMu.Lock()
	p.fwIndex = tunIndex
	p.fwPort = tunPort
	copy(p.fwKey[:], healthKey[:32])
	p.fwStepped = false
	p.fwMu.Unlock()

	blocked, err := probeLocalTUN(ctx, tunIndex, tunPort, healthKey, vpnProbeChallengeTimeout)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, nil
	}
	if !blocked {
		return nil, nil
	}
	blocker := inspectForeignVPNKillSwitch(tunIndex)
	return &platform.VPNFirewall{
		Blocked:    true,
		SteppedOut: true,
		Blocker:    blocker,
		Reason:     formatVPNFirewallReason(blocker),
	}, nil
}

func (p *Platform) checkLiveVPNFirewall(ctx context.Context) *platform.VPNFirewall {
	p.fwMu.Lock()
	idx, port, stepped := p.fwIndex, p.fwPort, p.fwStepped
	key := p.fwKey
	p.fwMu.Unlock()
	if stepped || idx <= 0 || port == 0 {
		return nil
	}
	blocked, err := probeLocalTUN(ctx, idx, port, key[:], vpnProbeChallengeTimeout)
	if err != nil || !blocked {
		return nil
	}
	blocker := inspectForeignVPNKillSwitch(idx)
	p.fwMu.Lock()
	if p.fwStepped {
		p.fwMu.Unlock()
		return nil
	}
	p.fwStepped = true
	p.fwMu.Unlock()
	return &platform.VPNFirewall{
		Blocked:    true,
		SteppedOut: true,
		Blocker:    blocker,
		Reason:     formatVPNFirewallReason(blocker),
	}
}
