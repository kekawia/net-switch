package lifecycle_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/host"
	"github.com/AyoubAchour/net-switch/internal/service"
	"github.com/AyoubAchour/net-switch/tests/linux/topo"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// relayConn is a stream the namespace relay opened on the suite's behalf. The
// engine attributes it to the relay process and the socket the relay opened,
// which the relay reports on its acknowledgement line.
type relayConn struct {
	net.Conn
	pid    uint32
	source netip.AddrPort
}

// fixtureLine is the DUT interface the suite's line a1 binds to.
const fixtureLine = "eth-a"

func prepareTUN(t *testing.T, _, data string) tunFixture {
	t.Helper()
	ctx := context.Background()
	dir := filepath.Join(data, "tun-fixture")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	n, err := topo.Up(ctx, hostedTestExecutable(), dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"netswitch.service", "netswitch-engine.service"} {
		dir := filepath.Join("/run/systemd/system", name+".d")
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "namespace.conf"), []byte("[Service]\nNetworkNamespacePath=/run/netns/"+topo.DUT+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := n.R.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop, cancel := context.WithTimeout(ctx, 40*time.Second)
		defer cancel()
		_ = service.Stop(stop, service.Control)
		_ = service.Stop(stop, service.Engine)
		for _, name := range []string{"netswitch.service", "netswitch-engine.service"} {
			_ = os.Remove(filepath.Join("/run/systemd/system", name+".d", "namespace.conf"))
		}
		_, _ = n.R.Run(ctx, "systemctl", "daemon-reload")
		if err := n.Down(ctx); err != nil {
			t.Error(err)
		}
	})
	// Empty but referenced tables belong to other policies too. Keep these
	// foreign rules across start/cleanup and require a different allocation.
	for _, args := range [][]string{
		{"-4", "rule", "add", "pref", "100", "fwmark", "1", "lookup", "3110"},
		{"-4", "rule", "add", "pref", "110", "fwmark", "1", "prohibit"},
		{"-4", "rule", "add", "pref", "9100", "fwmark", "2", "prohibit"},
	} {
		if _, err := n.R.IP(ctx, topo.DUT, args...); err != nil {
			t.Fatal(err)
		}
	}
	beforeNumeric := map[string]bool{}
	for _, family := range []string{"-4", "-6"} {
		text, err := n.R.IP(ctx, topo.DUT, "-N", family, "rule", "show")
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(text, "\n") {
			beforeNumeric[family+" "+strings.Join(strings.Fields(line), " ")] = true
		}
	}
	before, err := n.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "traffic.sock")
	relay := exec.Command("ip", "netns", "exec", topo.DUT, hostedTestExecutable(), "tun-relay", socket)
	if err := relay.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = relay.Process.Kill(); _ = relay.Wait() })
	wait(t, "namespace traffic relay", 5*time.Second, func() bool { _, err := os.Stat(socket); return err == nil })
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
		if err != nil {
			return nil, err
		}
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err = fmt.Fprintln(conn, address); err != nil {
			conn.Close()
			return nil, err
		}
		// The acknowledgement is read byte by byte: nothing may be buffered
		// past it, since the stream's own bytes follow on the same connection.
		var ack []byte
		for len(ack) == 0 || ack[len(ack)-1] != '\n' {
			var b [1]byte
			if _, err = io.ReadFull(conn, b[:]); err != nil || len(ack) > 128 {
				conn.Close()
				return nil, fmt.Errorf("namespace dial %s: %v %q", address, err, ack)
			}
			ack = append(ack, b[0])
		}
		fields := strings.Fields(string(ack))
		if len(fields) != 3 || fields[0] != "OK" {
			conn.Close()
			return nil, fmt.Errorf("namespace dial %s: %q", address, ack)
		}
		pid, pidErr := strconv.ParseUint(fields[1], 10, 32)
		source, sourceErr := netip.ParseAddrPort(fields[2])
		if pidErr != nil || sourceErr != nil {
			conn.Close()
			return nil, fmt.Errorf("namespace dial %s: relay origin %q: %v %v", address, ack, pidErr, sourceErr)
		}
		conn.SetDeadline(time.Time{})
		return &relayConn{Conn: conn, pid: uint32(pid), source: source}, nil
	}
	// The installed services run inside this namespace, so the suite's own
	// HTTP requests and every actor process must join it too.
	apiDialer, actorNamespace = dial, topo.DUT
	t.Cleanup(func() { apiDialer, actorNamespace = nil, "" })
	return tunFixture{
		line: fixtureLine, target: "198.51.100.10:7002", dial: dial,
		origin: func(t *testing.T, c net.Conn) (uint32, netip.AddrPort) {
			t.Helper()
			relayed, ok := c.(*relayConn)
			if !ok {
				t.Fatalf("stream %T was not opened by the namespace relay", c)
			}
			return relayed.pid, relayed.source
		},
		churnLine: "eth-b", seen: topo.Lines[0].Public4.String(), churnSeen: topo.Lines[1].Public4.String(),
		probe: func(t *testing.T, data string) nativeProbeFixture { return linuxNativeProbe(t, data, n.InetDir()) },
		exchange: func(t *testing.T, c net.Conn) {
			c.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := fmt.Fprint(c, "ping lifecycle\n"); err != nil {
				t.Fatal(err)
			}
			line, err := bufio.NewReader(c).ReadString('\n')
			if err != nil || !strings.HasPrefix(line, "pong lifecycle ") {
				t.Fatal(line, err)
			}
		},
		installed: func(t *testing.T) {
			now, err := n.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			diff := now.Diff(before)
			// The native engine names its TUN after its instance ("ns" plus
			// the first ten characters, alias "netswitch:<instance>"), not
			// "NetSwitch" like the stand-in, and gives it the 198.18.0.1/30
			// address the capture routes point at.
			state, err := host.ReadRecord(filepath.Join(data, "engine-state.json"))
			if err != nil {
				t.Fatal(err)
			}
			tunName := "ns" + state.Instance[:10]
			changes := strings.Join(diff, "\n")
			if len(diff) == 0 || !strings.Contains(changes, tunName+" inet 198.18.0.1/30") {
				t.Fatalf("no real TUN objects for instance %s (device %s): %v", state.Instance, tunName, diff)
			}
			t.Logf("TUN %s installed %d adapter/address/route/rule changes", tunName, len(diff))
			// Ownership: every policy rule the kernel now holds beyond the
			// baseline is one the native engine journaled before creating it
			// (an intent or created "rule" record of the live instance), read
			// from the journal file without touching it, and compared with
			// the kernel's own `ip rule` listing field by field.
			owned := map[string]string{}
			for _, record := range nativeLiveRecords(t, data, state.Instance) {
				if record.Kind != "rule" {
					continue
				}
				key, err := nativeRuleKey(record.Fingerprint["object"])
				if err != nil {
					t.Fatal(err)
				}
				owned[key] = record.Phase
			}
			exercised := 0
			for _, family := range []struct {
				flag   string
				number int
			}{{"-4", unix.AF_INET}, {"-6", unix.AF_INET6}} {
				text, err := n.R.IP(ctx, topo.DUT, "-N", family.flag, "rule", "show")
				if err != nil {
					t.Fatal(err)
				}
				for _, line := range strings.Split(text, "\n") {
					normalized := strings.Join(strings.Fields(line), " ")
					if normalized == "" || beforeNumeric[family.flag+" "+normalized] {
						continue
					}
					key, err := liveRuleKey(family.number, normalized)
					if err != nil {
						t.Fatal(err)
					}
					if _, ok := owned[key]; !ok {
						t.Fatalf("live rule %q (%s) has no native ownership record; owned: %v", normalized, key, owned)
					}
					exercised++
				}
			}
			// The complete native rule contract for one line with IPv6 (the
			// fixture line has a global IPv6 address, so the engine captures
			// both families): per family the bypass selectors (9 IPv4, 4 IPv6),
			// the loopback capture selector and the line's mark selector, plus
			// one source selector per usable address the kernel holds on the
			// line, read from the kernel here rather than assumed. Every owned
			// record is live and every live rule is owned.
			text, err := n.R.IP(ctx, topo.DUT, "-o", "addr", "show", "dev", fixtureLine)
			if err != nil {
				t.Fatal(err)
			}
			addresses := 0
			for _, line := range strings.Split(text, "\n") {
				if strings.TrimSpace(line) != "" && !strings.Contains(line, "tentative") && !strings.Contains(line, "dadfailed") {
					addresses++
				}
			}
			want := 9 + 4 + 2 + 2 + addresses
			if exercised != want || len(owned) != want {
				t.Fatalf("native rule contract: live=%d owned=%d want %d (13 bypass, 2 loopback capture, 2 line mark, %d line addresses): %v", exercised, len(owned), want, addresses, owned)
			}
			t.Logf("native engine owns all %d policy rules the kernel holds beyond the baseline (%d line addresses)", exercised, addresses)
		},
		clean: func(t *testing.T) {
			now, err := n.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if diff := now.Diff(before); len(diff) != 0 {
				t.Fatal("TUN cleanup left routing state", diff)
			}
		},
	}
}

// The namespace stays in this disposable subprocess. Entering it on a Go
// thread of the harness can make ip netns pids identify the harness itself,
// which would invalidate the cleanup test by killing its own observer.
// policyRule is the comparable shape of one policy rule: every selector and
// the action the native engine's rules can carry. The journaled netlink rule
// and the kernel's `ip rule` text both normalize to it, and a rule with any
// other selector set is refused rather than compared on a subset.
type policyRule struct {
	Family, Pref, Table int
	Src, Dst, Iif, Oif  string
	Mark, Mask          uint32
	Tos                 uint
	Invert              bool
	Protocol            uint8
	Type                uint8 // the fib rule action (RTN_UNICAST is "lookup")
}

func (r policyRule) key() string { return fmt.Sprintf("%+v", r) }

// nativeRuleKey decodes the netlink rule the engine journaled (the "object" of
// a "rule" ownership record, written by linux.ObjectJSON) and normalizes it.
func nativeRuleKey(object string) (string, error) {
	var r netlink.Rule
	if err := json.Unmarshal([]byte(object), &r); err != nil {
		return "", fmt.Errorf("native rule record %q: %w", object, err)
	}
	// netlink.NewRule's defaults are the unset values of these selectors.
	if r.TunID != 0 || r.Goto != -1 || r.Flow != -1 || r.SuppressIfgroup != -1 || r.SuppressPrefixlen != -1 || r.Dport != nil || r.Sport != nil || r.IPProto != 0 || r.UIDRange != nil {
		return "", fmt.Errorf("native rule record carries a selector this comparison does not support: %s", object)
	}
	cidr := func(n *net.IPNet) string {
		if n == nil {
			return ""
		}
		return n.String()
	}
	p := policyRule{Family: r.Family, Pref: r.Priority, Table: r.Table, Src: cidr(r.Src), Dst: cidr(r.Dst), Iif: r.IifName, Oif: r.OifName, Mark: r.Mark, Mask: ^uint32(0), Tos: r.Tos, Invert: r.Invert, Protocol: r.Protocol, Type: r.Type}
	if r.Mask != nil {
		p.Mask = *r.Mask
	}
	if r.Mark == 0 {
		p.Mask = 0
	}
	return p.key(), nil
}

// liveRuleKey normalizes one line of `ip -N <family> rule show`, such as
// "11001: from 192.168.1.2 lookup 2110 proto 186". Every token must be one the
// comparison understands; an unknown selector or action is an error, never
// silently skipped.
func liveRuleKey(family int, line string) (string, error) {
	fields := strings.Fields(line)
	if len(fields) == 0 || !strings.HasSuffix(fields[0], ":") {
		return "", fmt.Errorf("unexpected rule line %q", line)
	}
	pref, err := strconv.Atoi(strings.TrimSuffix(fields[0], ":"))
	if err != nil {
		return "", fmt.Errorf("rule line %q: %w", line, err)
	}
	cidr := func(value string) (string, error) {
		if strings.Contains(value, "/") {
			p, err := netip.ParsePrefix(value)
			return p.String(), err
		}
		a, err := netip.ParseAddr(value)
		if err != nil {
			return "", err
		}
		return netip.PrefixFrom(a, a.BitLen()).String(), nil
	}
	r := policyRule{Family: family, Pref: pref}
	number := func(value string, bits int) (uint64, error) {
		return strconv.ParseUint(strings.TrimPrefix(value, "0x"), 16, bits)
	}
	for i := 1; i < len(fields); i++ {
		token := fields[i]
		value := ""
		if i+1 < len(fields) {
			value = fields[i+1]
		}
		switch token {
		case "not":
			r.Invert = true
			continue
		case "prohibit", "unreachable", "blackhole":
			r.Type = map[string]uint8{"prohibit": unix.RTN_PROHIBIT, "unreachable": unix.RTN_UNREACHABLE, "blackhole": unix.RTN_BLACKHOLE}[token]
			continue
		case "from":
			if value != "all" {
				r.Src, err = cidr(value)
			}
		case "to":
			r.Dst, err = cidr(value)
		case "iif":
			r.Iif = value
		case "oif":
			r.Oif = value
		case "tos", "dsfield":
			var v uint64
			v, err = number(value, 8)
			r.Tos = uint(v)
		case "fwmark":
			mark, mask, masked := strings.Cut(value, "/")
			var v uint64
			v, err = number(mark, 32)
			r.Mark, r.Mask = uint32(v), ^uint32(0)
			if err == nil && masked {
				v, err = number(mask, 32)
				r.Mask = uint32(v)
			}
		case "lookup", "table":
			r.Table, err = tableNumber(value)
			r.Type = unix.RTN_UNICAST
		case "proto", "protocol":
			var v int
			v, err = protocolNumber(value)
			r.Protocol = uint8(v)
		default:
			return "", fmt.Errorf("rule line %q: selector or action %q is not one this comparison supports", line, token)
		}
		if err != nil {
			return "", fmt.Errorf("rule line %q: %w", line, err)
		}
		i++
	}
	return r.key(), nil
}

func tableNumber(value string) (int, error) {
	switch value {
	case "local":
		return unix.RT_TABLE_LOCAL, nil
	case "main":
		return unix.RT_TABLE_MAIN, nil
	case "default":
		return unix.RT_TABLE_DEFAULT, nil
	}
	return strconv.Atoi(value)
}

func protocolNumber(value string) (int, error) {
	switch value {
	case "kernel":
		return unix.RTPROT_KERNEL, nil
	case "boot":
		return unix.RTPROT_BOOT, nil
	case "static":
		return unix.RTPROT_STATIC, nil
	case "bgp":
		return unix.RTPROT_BGP, nil
	}
	return strconv.Atoi(value)
}

func tunRelay(path string) error {
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	defer l.Close()
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			reader := bufio.NewReader(c)
			target, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			out, err := net.DialTimeout("tcp4", strings.TrimSpace(target), 5*time.Second)
			if err != nil {
				fmt.Fprint(c, "NO\n")
				return
			}
			defer out.Close()
			// The engine attributes this stream to the relay and its socket.
			if _, err := fmt.Fprintf(c, "OK %d %s\n", os.Getpid(), out.LocalAddr()); err != nil {
				return
			}
			done := make(chan struct{})
			go func() { _, _ = io.Copy(out, reader); out.Close(); close(done) }()
			_, _ = io.Copy(c, out)
			c.Close()
			<-done
		}()
	}
}
