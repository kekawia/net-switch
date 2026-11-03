package linuxplatform

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/platform"
	"github.com/AyoubAchour/net-switch/internal/platform/outside"
)

func buildInetDiagMsg(family byte, state byte, local, remote netip.AddrPort, ifindex uint32, cookie uint64, uid, inode uint32, padAttr bool, tcpInfo []byte) []byte {
	msg := make([]byte, 72)
	msg[0] = family
	msg[1] = state
	binary.BigEndian.PutUint16(msg[4:6], local.Port())
	binary.BigEndian.PutUint16(msg[6:8], remote.Port())
	if family == linuxAFInet {
		s4 := local.Addr().As4()
		d4 := remote.Addr().As4()
		copy(msg[8:12], s4[:])
		copy(msg[24:28], d4[:])
	} else {
		s16 := local.Addr().As16()
		d16 := remote.Addr().As16()
		copy(msg[8:24], s16[:])
		copy(msg[24:40], d16[:])
	}
	binary.LittleEndian.PutUint32(msg[40:44], ifindex)
	binary.LittleEndian.PutUint32(msg[44:48], uint32(cookie))
	binary.LittleEndian.PutUint32(msg[48:52], uint32(cookie>>32))
	binary.LittleEndian.PutUint32(msg[64:68], uid)
	binary.LittleEndian.PutUint32(msg[68:72], inode)
	if padAttr {
		var pad [4]byte
		binary.LittleEndian.PutUint16(pad[0:2], 4)
		binary.LittleEndian.PutUint16(pad[2:4], 9) // INET_DIAG_PAD
		msg = append(msg, pad[:]...)
	}
	if tcpInfo != nil {
		attrLen := 4 + len(tcpInfo)
		padded := (attrLen + 3) &^ 3
		attr := make([]byte, padded)
		binary.LittleEndian.PutUint16(attr[0:2], uint16(attrLen))
		binary.LittleEndian.PutUint16(attr[2:4], linuxInetDiagInfo)
		copy(attr[4:], tcpInfo)
		msg = append(msg, attr...)
	}
	return msg
}

func TestParseInetDiagMsg(t *testing.T) {
	info := make([]byte, 248)
	binary.LittleEndian.PutUint64(info[tcpInfoBytesAckedOffset:], 1111)
	binary.LittleEndian.PutUint64(info[tcpInfoBytesReceivedOffset:], 8192)
	binary.LittleEndian.PutUint64(info[tcpInfoBytesSentOffset:], 4096)

	local := netip.MustParseAddrPort("192.168.1.2:54321")
	remote := netip.MustParseAddrPort("198.51.100.10:443")
	cookie := uint64(0xfeedfacecafebeef)

	got, err := parseInetDiagMsg(buildInetDiagMsg(linuxAFInet, linuxTCPEstablished, local, remote, 7, cookie, 1000, 98765, true, info))
	if err != nil {
		t.Fatal(err)
	}
	if got.family != linuxAFInet || got.state != linuxTCPEstablished || got.local != local || got.remote != remote ||
		got.ifindex != 7 || got.cookie != cookie || got.uid != 1000 || got.inode != 98765 ||
		!got.measured || got.down != 8192 || got.up != 4096 {
		t.Fatalf("unexpected parsed AF_INET diagSocket: %+v", got)
	}

	mappedLocal := netip.AddrPortFrom(netip.AddrFrom16(local.Addr().As16()), local.Port())
	mappedRemote := netip.AddrPortFrom(netip.AddrFrom16(remote.Addr().As16()), remote.Port())
	got6, err := parseInetDiagMsg(buildInetDiagMsg(linuxAFInet6, linuxTCPEstablished, mappedLocal, mappedRemote, 3, cookie, 1000, 555, false, info[:136]))
	if err != nil {
		t.Fatal(err)
	}
	if got6.family != linuxAFInet6 || got6.local != local || got6.remote != remote || !got6.measured || got6.down != 8192 || got6.up != 1111 {
		t.Fatalf("unexpected parsed AF_INET6 mapped diagSocket: %+v", got6)
	}

	unmeasured, err := parseInetDiagMsg(buildInetDiagMsg(linuxAFInet, linuxTCPEstablished, local, remote, 0, cookie, 0, 1, false, info[:64]))
	if err != nil || unmeasured.measured {
		t.Fatalf("short tcp_info should stay unmeasured: %+v %v", unmeasured, err)
	}

	if _, err := parseInetDiagMsg(make([]byte, 71)); err == nil {
		t.Fatal("accepted truncated inet_diag_msg")
	}
	badAttr := buildInetDiagMsg(linuxAFInet, linuxTCPEstablished, local, remote, 0, cookie, 0, 1, false, nil)
	badAttr = append(badAttr, 12, 0, linuxInetDiagInfo, 0)
	if _, err := parseInetDiagMsg(badAttr); err == nil {
		t.Fatal("accepted truncated netlink attribute")
	}
}

func TestParseSocketLinkAndProcessStat(t *testing.T) {
	if inode, ok := parseSocketLink([]byte("socket:[424242]")); !ok || inode != 424242 {
		t.Fatalf("parseSocketLink valid = (%d, %v)", inode, ok)
	}
	for _, invalid := range []string{"", "socket:[]", "socket:[0]", "pipe:[42]", "socket:[42", "socket:[99999999999]"} {
		if inode, ok := parseSocketLink([]byte(invalid)); ok {
			t.Errorf("parseSocketLink(%q) = %d, want rejected", invalid, inode)
		}
	}

	stat := "4321 (my (weird) app) S 1 4321 4321 0 -1 4194304 10 0 0 0 5 2 0 0 20 0 4 0 987654321 123456 100\n"
	start, err := parseProcessStatStart([]byte(stat))
	if err != nil || start != 987654321 {
		t.Fatalf("parseProcessStatStart = (%d, %v), want 987654321", start, err)
	}
	if _, err := parseProcessStatStart([]byte("4321 (short) S 1 2 3\n")); err == nil {
		t.Fatal("accepted truncated /proc/pid/stat")
	}

	encoded := formatProcessStarted(987654321, 0x1234abcd5678ef90)
	gotStart, gotCookie, hasCookie, ok := parseProcessStarted(encoded)
	if !ok || !hasCookie || gotStart != 987654321 || gotCookie != 0x1234abcd5678ef90 {
		t.Fatalf("parseProcessStarted(%q) = (%d, %#x, %v, %v)", encoded, gotStart, gotCookie, hasCookie, ok)
	}
	if s, c, has, ok := parseProcessStarted("555"); !ok || has || s != 555 || c != 0 {
		t.Fatalf("parseProcessStarted bare ticks = (%d, %#x, %v, %v)", s, c, has, ok)
	}
	for _, bad := range []string{"", "0:abc", "123:", "123:0", "abc:123", "123:zz"} {
		if _, _, _, ok := parseProcessStarted(bad); ok {
			t.Errorf("parseProcessStarted(%q) accepted", bad)
		}
	}
}

func TestLinuxWatcherStepsAndCookieIdentity(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 123456700, time.UTC)
	rows := []diagSocket{
		{
			family: linuxAFInet, state: linuxTCPEstablished,
			local: netip.MustParseAddrPort("192.168.1.2:41001"), remote: netip.MustParseAddrPort("198.51.100.10:443"),
			cookie: 0x101, inode: 11, down: 5000, up: 300, measured: true,
		},
		{
			// Case-different path on Linux is a distinct executable and must NOT be excluded.
			family: linuxAFInet, state: linuxTCPEstablished,
			local: netip.MustParseAddrPort("192.168.1.2:41002"), remote: netip.MustParseAddrPort("198.51.100.10:443"),
			cookie: 0x102, inode: 12, down: 100, up: 50, measured: true,
		},
		{
			// Exact engine executable path: excluded.
			family: linuxAFInet, state: linuxTCPEstablished,
			local: netip.MustParseAddrPort("192.168.1.2:41003"), remote: netip.MustParseAddrPort("198.51.100.10:443"),
			cookie: 0x103, inode: 13, down: 900, up: 900, measured: true,
		},
		{
			// Private LAN remote: ignored before /proc owner lookup.
			family: linuxAFInet, state: linuxTCPEstablished,
			local: netip.MustParseAddrPort("192.168.1.2:41004"), remote: netip.MustParseAddrPort("192.168.1.1:80"),
			cookie: 0x104, inode: 14, down: 10, up: 10, measured: true,
		},
	}
	ownersMap := map[uint32]procOwner{
		11: {pid: 50, start: 777, path: "/app/bin/game", appID: "flatpak:org.example.Game"},
		12: {pid: 60, start: 888, path: "/opt/netswitch/NETSWITCH-ENGINE"},
		13: {pid: 70, start: 999, path: "/opt/netswitch/netswitch-engine"},
	}
	var dumpCalls, ownerCalls, readOneCalls int
	failDump := false
	liveCounters := map[uint64][2]uint64{
		0x101: {9000, 700},
	}

	w := newLinuxWatcher("/opt/netswitch/netswitch-engine", linuxSource{
		now: func() time.Time { return now },
		dump: func() ([]diagSocket, error) {
			dumpCalls++
			if failDump {
				return nil, errors.New("netlink busy")
			}
			return rows, nil
		},
		owners: func(inodes map[uint32]struct{}) map[uint32]procOwner {
			ownerCalls++
			if _, lanAsked := inodes[14]; lanAsked {
				t.Error("ignored LAN socket inode was requested from /proc")
			}
			return ownersMap
		},
		readOne: func(s diagSocket) (uint64, uint64, bool) {
			readOneCalls++
			v, ok := liveCounters[s.cookie]
			return v[0], v[1], ok
		},
	})

	// Second 1 (tick 0): full dump + /proc scan; dump's tcp_info is fresh so readOne is not called.
	line := w.Sample()
	if dumpCalls != 1 || ownerCalls != 1 || readOneCalls != 0 {
		t.Fatalf("tick 0 calls: dump=%d owners=%d readOne=%d, want 1, 1, 0", dumpCalls, ownerCalls, readOneCalls)
	}
	if !line.Estats || len(line.Outside) != 2 {
		t.Fatalf("tick 0 line: %+v", line)
	}
	first := line.Outside[0]
	if first.PID != 50 || first.Path != "/app/bin/game" || first.AppID != "flatpak:org.example.Game" || first.ProcessStarted != "777:101" ||
		first.Created != "2026-11-03T12:00:00.1234567Z" || first.Down == nil || *first.Down != 5000 || *first.Up != 300 {
		t.Fatalf("tick 0 first entry: %+v", first)
	}
	firstID := first.ID

	// Seconds 2..5 (ticks 1..4): no dump or /proc scan; per-socket readOne runs each second.
	for second := 2; second <= outside.RescanEvery; second++ {
		now = now.Add(time.Second)
		line = w.Sample()
	}
	if dumpCalls != 1 || ownerCalls != 1 || readOneCalls != 8 {
		t.Fatalf("ticks 1..4 calls: dump=%d owners=%d readOne=%d, want 1, 1, 8", dumpCalls, ownerCalls, readOneCalls)
	}
	if *line.Outside[0].Down != 9000 || *line.Outside[0].Up != 700 {
		t.Fatalf("tick 4 counters not refreshed: %+v", line.Outside[0])
	}
	if line.Outside[1].Down != nil || line.Outside[1].Up != nil {
		t.Fatalf("unreadable socket must report null counters: %+v", line.Outside[1])
	}

	// Second 6 (tick 5): rescan. Cookie 0x101 stays open (must keep Created & ID);
	// port 41002 is reopened with a new cookie 0x202 (must get a new Created & ID).
	now = now.Add(time.Second)
	rows = []diagSocket{
		{
			family: linuxAFInet, state: linuxTCPEstablished,
			local: netip.MustParseAddrPort("192.168.1.2:41001"), remote: netip.MustParseAddrPort("198.51.100.10:443"),
			cookie: 0x101, inode: 11, down: 12000, up: 900, measured: true,
		},
		{
			family: linuxAFInet, state: linuxTCPEstablished,
			local: netip.MustParseAddrPort("192.168.1.2:41002"), remote: netip.MustParseAddrPort("198.51.100.10:443"),
			cookie: 0x202, inode: 12, down: 40, up: 20, measured: true,
		},
	}
	line = w.Sample()
	if dumpCalls != 2 || ownerCalls != 2 || readOneCalls != 8 {
		t.Fatalf("tick 5 calls: dump=%d owners=%d readOne=%d, want 2, 2, 8", dumpCalls, ownerCalls, readOneCalls)
	}
	if line.Outside[0].ID != firstID || *line.Outside[0].Down != 12000 {
		t.Fatalf("same cookie changed ID or missed fresh dump bytes: %+v, want ID %s", line.Outside[0], firstID)
	}
	if line.Outside[1].Created == first.Created || line.Outside[1].ProcessStarted != "888:202" {
		t.Fatalf("reopened 4-tuple with new cookie kept old timestamp: %+v", line.Outside[1])
	}

	// Failed dump preserves tracked entries.
	failDump = true
	for i := 0; i < outside.RescanEvery; i++ {
		line = w.Sample()
	}
	if dumpCalls != 3 || len(line.Outside) != 2 {
		t.Fatalf("failed dump dropped tracked state: calls=%d entries=%+v", dumpCalls, line.Outside)
	}

	// Empty dump skips /proc scan completely.
	failDump = false
	rows = nil
	for i := 0; i < outside.RescanEvery; i++ {
		line = w.Sample()
	}
	if ownerCalls != 2 || len(line.Outside) != 0 {
		t.Fatalf("empty dump should skip /proc scan and clear entries: ownerCalls=%d entries=%+v", ownerCalls, line.Outside)
	}
	b, _ := json.Marshal(line)
	if string(b) != `{"estats":true,"outside":[]}` {
		t.Fatalf("unexpected empty JSON: %s", b)
	}
}

func TestCloseConnectionsRevalidationAndUnsupported(t *testing.T) {
	var calls int
	empty, err := closeConnections(nil, closeOps{
		processStart: func(uint32) (uint64, error) { calls++; return 0, nil },
	})
	if err != nil || calls != 0 || empty["closed"] != 0 || empty["failed"] != 0 || empty["gone"] != 0 {
		t.Fatalf("empty closeConnections: %+v %v calls=%d", empty, err, calls)
	}
	if _, hasReason := empty["reason"]; hasReason {
		t.Fatalf("unexpected reason on empty result: %+v", empty)
	}

	selector := outsideSelector("192.168.1.2", 41001, "198.51.100.10", 443, 50, "777:101")
	live := diagSocket{
		family: linuxAFInet, state: linuxTCPEstablished,
		local: netip.MustParseAddrPort("192.168.1.2:41001"), remote: netip.MustParseAddrPort("198.51.100.10:443"),
		ifindex: 2, cookie: 0x101, inode: 11,
	}

	// Valid match closes once and omits "reason".
	destroyed := 0
	res, err := closeConnections([]platform.TCPSelector{selector}, closeOps{
		processStart: func(pid uint32) (uint64, error) { return 777, nil },
		findSocket: func(local, remote netip.AddrPort, cookie uint64) (diagSocket, bool, error) {
			if cookie != 0x101 {
				t.Fatalf("want cookie 0x101, got %#x", cookie)
			}
			return live, true, nil
		},
		pidHoldsInode: func(pid, inode uint32) (bool, error) { return pid == 50 && inode == 11, nil },
		destroy:       func(s diagSocket) error { destroyed++; return nil },
	})
	if err != nil || destroyed != 1 || res["closed"] != 1 || res["failed"] != 0 || res["gone"] != 0 {
		t.Fatalf("valid closeConnections: %+v %v destroyed=%d", res, err, destroyed)
	}
	if _, hasReason := res["reason"]; hasReason {
		t.Fatalf("normal closeConnections must omit reason: %+v", res)
	}

	// Process start time mismatch (PID reused before fd check) -> gone, never destroyed.
	res, err = closeConnections([]platform.TCPSelector{selector}, closeOps{
		processStart: func(uint32) (uint64, error) { return 778, nil },
		destroy:      func(diagSocket) error { t.Fatal("destroyed mismatched PID"); return nil },
	})
	if err != nil || res["gone"] != 1 || res["closed"] != 0 {
		t.Fatalf("start mismatch: %+v %v", res, err)
	}

	// PID recycled between fd scan and post-scan stat check -> gone, never destroyed.
	statStep := 0
	res, err = closeConnections([]platform.TCPSelector{selector}, closeOps{
		processStart: func(uint32) (uint64, error) {
			statStep++
			if statStep == 1 {
				return 777, nil
			}
			return 999, nil
		},
		findSocket:    func(netip.AddrPort, netip.AddrPort, uint64) (diagSocket, bool, error) { return live, true, nil },
		pidHoldsInode: func(uint32, uint32) (bool, error) { return true, nil },
		destroy:       func(diagSocket) error { t.Fatal("destroyed after PID recycle race"); return nil },
	})
	if err != nil || res["gone"] != 1 || res["closed"] != 0 {
		t.Fatalf("post-fd PID recycle: %+v %v", res, err)
	}

	// Kernel without CONFIG_INET_DIAG_DESTROY (EOPNOTSUPP) reports "not supported here" and stops.
	errUnsupported := errors.New("operation not supported")
	destroyCalls := 0
	res, err = closeConnections([]platform.TCPSelector{selector, selector}, closeOps{
		processStart:  func(uint32) (uint64, error) { return 777, nil },
		findSocket:    func(netip.AddrPort, netip.AddrPort, uint64) (diagSocket, bool, error) { return live, true, nil },
		pidHoldsInode: func(uint32, uint32) (bool, error) { return true, nil },
		destroy:       func(diagSocket) error { destroyCalls++; return errUnsupported },
		isUnsupported: func(err error) bool { return errors.Is(err, errUnsupported) },
	})
	if err != nil || destroyCalls != 1 || res["closed"] != 0 || res["failed"] != 2 || res["gone"] != 0 || res["reason"] != "not supported here" {
		t.Fatalf("unsupported SOCK_DESTROY: %+v %v calls=%d", res, err, destroyCalls)
	}
}

func outsideSelector(local string, lport float64, remote string, rport, pid float64, processStarted string) platform.TCPSelector {
	var sel platform.TCPSelector
	sel.Local = local
	sel.LPort = lport
	sel.Remote = remote
	sel.RPort = rport
	sel.PID = pid
	sel.Created = "2026-11-03T12:00:00.0000000Z"
	sel.ProcessStarted = processStarted
	return sel
}
