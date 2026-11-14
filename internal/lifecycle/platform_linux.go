package lifecycle

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/AyoubAchour/net-switch/internal/desktop/xdg"
	"github.com/AyoubAchour/net-switch/internal/platform"
	linuxplatform "github.com/AyoubAchour/net-switch/internal/platform/linux"
	"github.com/AyoubAchour/net-switch/internal/platform/worker"
)

type linuxPlatform struct {
	workers    worker.Supervisor
	enginePath string
}

func nativePlatform(c Config, log func(string)) platform.System {
	exe := filepath.Join(c.Directory, "netswitch-engine")
	return &linuxPlatform{
		workers:    worker.Supervisor{Executable: exe, Log: func(err error) { log(err.Error()) }},
		enginePath: exe,
	}
}
func (p *linuxPlatform) Call(ctx context.Context, op string, args map[string]any) (any, error) {
	return p.workers.Once(ctx, op, args)
}
func (p *linuxPlatform) Stream(ctx context.Context, mode string, emit func([]byte), report func(error)) {
	var args []string
	if mode == "outside" {
		args = []string{"--engine", p.enginePath}
	}
	p.workers.Stream(ctx, mode, args, emit, report)
}
func linuxCall(op string, args map[string]any) (any, error) {
	switch op {
	case "elevated":
		return os.Geteuid() == 0, nil
	case "architecture":
		return runtime.GOARCH, nil
	case "policy":
		return nil, nil
	case "meters":
		interfaces, err := net.Interfaces()
		if err != nil {
			return nil, err
		}
		adapters := []any{}
		for _, nic := range interfaces {
			if nic.Flags&net.FlagLoopback != 0 || isOwnCaptureInterface(nic.Name) {
				continue
			}
			read := func(name string) (uint64, error) {
				b, err := os.ReadFile(filepath.Join("/sys/class/net", nic.Name, "statistics", name))
				if err != nil {
					return 0, err
				}
				return strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
			}
			rx, rxErr := read("rx_bytes")
			tx, txErr := read("tx_bytes")
			if rxErr != nil || txErr != nil {
				return nil, fmt.Errorf("read %s counters: %w", nic.Name, errors.Join(rxErr, txErr))
			}
			adapters = append(adapters, map[string]any{"alias": nic.Name, "rx": rx, "tx": tx})
		}
		return map[string]any{"adapters": adapters}, nil
	case "network":
		interfaces, err := net.Interfaces()
		if err != nil {
			return nil, err
		}
		adapters := []any{}
		vpnAdapters := []map[string]any{}
		routes := []any{}
		defaults := map[string]string{}
		b, err := os.ReadFile("/proc/net/route")
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 8 && f[1] == "00000000" && f[7] == "00000000" {
				gateway, err := strconv.ParseUint(f[2], 16, 32)
				if err == nil {
					defaults[f[0]] = net.IPv4(byte(gateway), byte(gateway>>8), byte(gateway>>16), byte(gateway>>24)).String()
				}
			}
		}
		vpnDefaultIfs := linuxVPNDefaultRouteIfs()
		for _, nic := range interfaces {
			if nic.Flags&net.FlagLoopback != 0 || isOwnCaptureInterface(nic.Name) {
				continue
			}
			addresses, err := nic.Addrs()
			if err != nil {
				continue
			}
			ips := []any{}
			ipv6 := false
			for _, address := range addresses {
				ip, _, err := net.ParseCIDR(address.String())
				if err != nil {
					continue
				}
				if ip.To4() != nil {
					ips = append(ips, ip.String())
					if defaults[nic.Name] != "" {
						routes = append(routes, map[string]any{"interfaceAddress": ip.String(), "alias": nic.Name, "index": nic.Index})
					}
				} else if !ip.IsLinkLocalUnicast() {
					ipv6 = true
				}
			}
			status := "Down"
			if nic.Flags&net.FlagUp != 0 {
				status = "Up"
			}
			isVPN := isLinuxVPNInterface(nic)
			media := "Ethernet"
			if _, err := os.Stat(filepath.Join("/sys/class/net", nic.Name, "wireless")); err == nil {
				media = "Wireless"
			}
			entry := map[string]any{"alias": nic.Name, "name": nic.Name, "index": nic.Index, "ipv4s": ips, "ipv6": ipv6, "status": status, "mediaType": media, "gateway": defaults[nic.Name]}
			if isVPN {
				entry["virtual"] = true
				var primary any
				if len(ips) > 0 {
					primary = ips[0]
				}
				vpnAdapters = append(vpnAdapters, map[string]any{
					"alias":           nic.Name,
					"index":           nic.Index,
					"status":          status,
					"ipv4":            primary,
					"ipv4s":           ips,
					"ipv6":            ipv6,
					"hasDefaultRoute": vpnDefaultIfs[nic.Index] || defaults[nic.Name] != "",
				})
			}
			adapters = append(adapters, entry)
		}
		slices.SortFunc(vpnAdapters, func(a, b map[string]any) int {
			sa, _ := a["alias"].(string)
			sb, _ := b["alias"].(string)
			return strings.Compare(sa, sb)
		})
		out := map[string]any{"adapters": adapters, "defaultRoutes": routes, "readAt": time.Now().UnixMilli(), "policy": nil}
		if len(vpnAdapters) > 0 {
			out["vpnAdapters"] = vpnAdapters
		}
		return out, nil
	case "line-check":
		return map[string]any{"outcome": "engineUnavailable", "delay": nil}, nil
	case "close-tcp":
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return linuxplatform.CloseTCP(ctx, args)
	case "stop-process":
		// Guarded adapter children cannot survive the engine service on Linux.
		// Never kill a PID from a previous boot or a legacy untrusted PID file.
		return nil, errors.New("legacy PID cleanup is not used by the service adapter")
	}
	return nil, fmt.Errorf("Linux operation %q is not available", op)
}
func Worker(args []string) int {
	if len(args) == 2 && args[0] == "query" {
		var input map[string]any
		err := json.NewDecoder(os.Stdin).Decode(&input)
		var value any
		if err == nil {
			value, err = linuxCall(args[1], input)
		}
		out := map[string]any{"value": value}
		if err != nil {
			out["error"] = err.Error()
		}
		if json.NewEncoder(os.Stdout).Encode(out) != nil {
			return 1
		}
		return 0
	}
	if len(args) >= 1 && args[0] == "outside" {
		return linuxplatform.RunOutside(args[1:])
	}
	if len(args) == 1 && (args[0] == "network" || args[0] == "meters") {
		go linuxplatform.WatchStdinEOF()
		for {
			value, err := linuxCall(args[0], nil)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			if json.NewEncoder(os.Stdout).Encode(value) != nil {
				return 0
			}
			time.Sleep(2 * time.Second)
		}
	}
	fmt.Fprintln(os.Stderr, "unknown worker mode")
	return 2
}
func DesktopCall(_ context.Context, op string, args map[string]any) (any, error) {
	switch op {
	case "app-info":
		return xdg.AppInfo(xdg.ExtractStrings(args["paths"]), xdg.DefaultOptions()), nil
	case "installed-apps":
		return xdg.InstalledApps(xdg.DefaultOptions()), nil
	case "autostart":
		return desktopAutostart(nil)
	case "autostart-set":
		value, _ := args["on"].(bool)
		return desktopAutostart(&value)
	case "autostart-upgrade":
		return "unchanged", nil
	}
	return nil, fmt.Errorf("desktop operation %q refused", op)
}

func isOwnCaptureInterface(name string) bool {
	lower := strings.ToLower(name)
	return lower == "netswitch" || lower == "netswitch0"
}

var linuxExcludedPrefixes = []string{
	"docker", "br-", "veth", "virbr", "vnet", "cni", "flannel", "cali", "kube", "testisp",
}

var linuxKernelFallbackDevices = map[string]bool{
	"tunl0": true, "sit0": true, "gre0": true, "gretap0": true,
	"erspan0": true, "ip6tnl0": true, "ip6gre0": true, "ip_vti0": true, "ip6_vti0": true,
}

func isLinuxVPNInterface(nic net.Interface) bool {
	lower := strings.ToLower(nic.Name)
	if isOwnCaptureInterface(lower) || linuxKernelFallbackDevices[lower] {
		return false
	}
	for _, prefix := range linuxExcludedPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return false
		}
	}
	sysDir := filepath.Join("/sys/class/net", nic.Name)
	if _, err := os.Stat(filepath.Join(sysDir, "master")); err == nil {
		return false
	}
	if uevent, err := os.ReadFile(filepath.Join(sysDir, "uevent")); err == nil {
		for _, line := range strings.Split(string(uevent), "\n") {
			if line == "DEVTYPE=wireguard" || line == "DEVTYPE=ppp" {
				return true
			}
		}
	}
	if _, err := os.Stat(filepath.Join(sysDir, "tun_flags")); err == nil {
		return true
	}
	if rawType, err := os.ReadFile(filepath.Join(sysDir, "type")); err == nil {
		switch strings.TrimSpace(string(rawType)) {
		case "65534", "512", "768", "769", "776", "778":
			return true
		}
	}
	return nic.Flags&net.FlagPointToPoint != 0
}

func linuxVPNDefaultRouteIfs() map[int]bool {
	out := map[int]bool{}
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_INET)
	if err != nil {
		return out
	}
	msgs, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return out
	}
	const rtaTable = 15
	hasFull := map[int]bool{}
	hasLower := map[int]bool{}
	hasUpper := map[int]bool{}
	for _, msg := range msgs {
		if msg.Header.Type != syscall.RTM_NEWROUTE || len(msg.Data) < syscall.SizeofRtMsg {
			continue
		}
		dstLen := msg.Data[1]
		table := uint32(msg.Data[4])
		rtmType := msg.Data[7]
		if rtmType != syscall.RTN_UNICAST || dstLen > 1 {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&msg)
		if err != nil {
			continue
		}
		var oif int
		var dstFirstByte byte
		var priority uint32
		for _, attr := range attrs {
			switch attr.Attr.Type {
			case rtaTable:
				if len(attr.Value) >= 4 {
					table = binary.NativeEndian.Uint32(attr.Value[:4])
				}
			case syscall.RTA_OIF:
				if len(attr.Value) >= 4 {
					oif = int(binary.NativeEndian.Uint32(attr.Value[:4]))
				}
			case syscall.RTA_DST:
				if len(attr.Value) >= 1 {
					dstFirstByte = attr.Value[0]
				}
			case syscall.RTA_PRIORITY:
				if len(attr.Value) >= 4 {
					priority = binary.NativeEndian.Uint32(attr.Value[:4])
				}
			}
		}
		if oif <= 0 || table == syscall.RT_TABLE_LOCAL || (table >= 20100 && table <= 20355) {
			continue
		}
		if dstLen == 0 {
			if table != syscall.RT_TABLE_MAIN || priority < 4096 {
				hasFull[oif] = true
			}
		} else if dstLen == 1 {
			if dstFirstByte == 0 {
				hasLower[oif] = true
			} else if dstFirstByte == 128 {
				hasUpper[oif] = true
			}
		}
	}
	for idx := range hasFull {
		out[idx] = true
	}
	for idx := range hasLower {
		if hasUpper[idx] {
			out[idx] = true
		}
	}
	return out
}
