//go:build lifecycle_test && linux && (amd64 || arm64)

package lifecycle

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/AyoubAchour/net-switch/internal/engine/linux/ownerbpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type ebpfCapabilityEvidence struct {
	CapEff              string `json:"capEff"`
	CapBnd              string `json:"capBnd"`
	HasCapBPF           bool   `json:"hasCapBPF"`
	HasCapPerfmon       bool   `json:"hasCapPerfmon"`
	HasCapSysAdmin      bool   `json:"hasCapSysAdmin"`
	MemlockInfinity     bool   `json:"memlockInfinity"`
	LockdownMode        string `json:"lockdownMode"`
	PerfEventParanoid   string `json:"perfEventParanoid"`
	TunName             string `json:"tunName"`
	TunIfindex          int    `json:"tunIfindex"`
	TunTxQLen           int    `json:"tunTxQLen"`
	NetNSInode          uint32 `json:"netNSInode"`
	PacketSlots         uint64 `json:"packetSlots"`
	SocketSlots         int    `json:"socketSlots"`
	CapturedActorEvents int    `json:"capturedActorEvents"`
	CapturedCookie      uint64 `json:"capturedCookie"`
	CapturedTGID        uint32 `json:"capturedTGID"`
	PeerHitsBefore      uint64 `json:"peerHitsBefore"`
	PeerHitsDuring      uint64 `json:"peerHitsDuring"`
	PeerHitsAfter       uint64 `json:"peerHitsAfter"`
	BPFPerfFDsBefore    int    `json:"bpfPerfFDsBefore"`
	BPFPerfFDsDuring    int    `json:"bpfPerfFDsDuring"`
	BPFPerfFDsAfter     int    `json:"bpfPerfFDsAfter"`
	TotalFDsBefore      int    `json:"totalFDsBefore"`
	TotalFDsAfter       int    `json:"totalFDsAfter"`
}

func readSelfCapMasks() (capEffHex string, capBndHex string, capEff uint64, capBnd uint64, err error) {
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return "", "", 0, 0, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if v, ok := strings.CutPrefix(line, "CapEff:"); ok {
			capEffHex = strings.TrimSpace(v)
		} else if v, ok := strings.CutPrefix(line, "CapBnd:"); ok {
			capBndHex = strings.TrimSpace(v)
		}
	}
	if capEffHex == "" || capBndHex == "" {
		return "", "", 0, 0, errors.New("missing CapEff/CapBnd in /proc/self/status")
	}
	capEff, err = strconv.ParseUint(capEffHex, 16, 64)
	if err != nil {
		return "", "", 0, 0, fmt.Errorf("parse CapEff %q: %w", capEffHex, err)
	}
	capBnd, err = strconv.ParseUint(capBndHex, 16, 64)
	if err != nil {
		return "", "", 0, 0, fmt.Errorf("parse CapBnd %q: %w", capBndHex, err)
	}
	return capEffHex, capBndHex, capEff, capBnd, nil
}

func countSelfBPFAndTotalFDs() (bpfPerf int, total int, err error) {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, 0, err
	}
	for _, e := range entries {
		target, lErr := os.Readlink("/proc/self/fd/" + e.Name())
		if lErr != nil {
			// Skip the transient directory fd opened by os.ReadDir itself.
			continue
		}
		total++
		if strings.HasPrefix(target, "anon_inode:bpf-") || strings.HasPrefix(target, "anon_inode:[perf_event]") {
			bpfPerf++
		}
	}
	return bpfPerf, total, nil
}

func nativeEBPFCapabilityEvidence(instance string) (_ any, retErr error) {
	if len(instance) != 32 {
		return nil, errors.New("Linux eBPF capability proof requires a live 32-char engine instance")
	}
	capEffHex, capBndHex, capEff, capBnd, err := readSelfCapMasks()
	if err != nil {
		return nil, err
	}
	hasCapBPF := (capEff&(uint64(1)<<unix.CAP_BPF)) != 0 && (capBnd&(uint64(1)<<unix.CAP_BPF)) != 0
	hasCapPerfmon := (capEff&(uint64(1)<<unix.CAP_PERFMON)) != 0 && (capBnd&(uint64(1)<<unix.CAP_PERFMON)) != 0
	hasCapSysAdmin := (capEff&(uint64(1)<<unix.CAP_SYS_ADMIN)) != 0 || (capBnd&(uint64(1)<<unix.CAP_SYS_ADMIN)) != 0
	if !hasCapBPF || !hasCapPerfmon || hasCapSysAdmin {
		return nil, fmt.Errorf("unexpected engine capability mask CapEff=%s CapBnd=%s (bpf=%v perfmon=%v sys_admin=%v)",
			capEffHex, capBndHex, hasCapBPF, hasCapPerfmon, hasCapSysAdmin)
	}

	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rl); err != nil {
		return nil, fmt.Errorf("getrlimit RLIMIT_MEMLOCK: %w", err)
	}
	memlockInf := rl.Cur == unix.RLIM_INFINITY && rl.Max == unix.RLIM_INFINITY
	if !memlockInf {
		return nil, fmt.Errorf("RLIMIT_MEMLOCK not infinity: cur=%d max=%d", rl.Cur, rl.Max)
	}

	lockdownMode := "absent"
	if lb, lErr := os.ReadFile("/sys/kernel/security/lockdown"); lErr == nil {
		parsed := ownerbpf.ParseLockdownMode(string(lb))
		lockdownMode = string(parsed)
		if parsed == ownerbpf.LockdownConfidentiality {
			return nil, errors.New("kernel lockdown is confidentiality")
		}
	} else if !os.IsNotExist(lErr) {
		return nil, fmt.Errorf("read lockdown: %w", lErr)
	}

	paranoid := "absent"
	if pb, pErr := os.ReadFile("/proc/sys/kernel/perf_event_paranoid"); pErr == nil {
		paranoid = strings.TrimSpace(string(pb))
	} else if !os.IsNotExist(pErr) {
		return nil, fmt.Errorf("read perf_event_paranoid: %w", pErr)
	}

	tunName := "ns" + instance[:10]
	nlLink, err := netlink.LinkByName(tunName)
	if err != nil {
		return nil, fmt.Errorf("locate live TUN %s: %w", tunName, err)
	}
	attrs := nlLink.Attrs()
	if attrs.Alias != "netswitch:"+instance || attrs.TxQLen <= 0 {
		return nil, fmt.Errorf("unexpected TUN metadata alias=%q txqlen=%d", attrs.Alias, attrs.TxQLen)
	}
	var nsStat unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &nsStat); err != nil {
		return nil, fmt.Errorf("stat netns: %w", err)
	}
	netns := uint32(nsStat.Ino)
	if netns == 0 {
		return nil, errors.New("zero netns inode")
	}

	runtime.GC()
	runtime.GC()
	bpfBefore, totalBefore, err := countSelfBPFAndTotalFDs()
	if err != nil {
		return nil, err
	}

	peer, err := ownerbpf.AttachPeerCgroupEgressFilter("/sys/fs/cgroup")
	if err != nil {
		return nil, fmt.Errorf("attach peer root-cgroup filter: %w", err)
	}
	defer func() {
		if peer != nil {
			_ = peer.Close()
		}
	}()

	preConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("open pre-probe loopback UDP socket: %w", err)
	}
	defer func() {
		if preConn != nil {
			_ = preConn.Close()
		}
	}()
	if _, err := preConn.WriteTo([]byte{0x11}, preConn.LocalAddr()); err != nil {
		return nil, fmt.Errorf("pre-probe loopback send: %w", err)
	}
	peerHitsBefore, err := peer.HitCount()
	if err != nil || peerHitsBefore == 0 {
		return nil, fmt.Errorf("peer filter pre-load hits=%d err=%v", peerHitsBefore, err)
	}

	slots, err := ownerbpf.NewMmapSocketSlotTable(ownerbpf.DefaultEngineMaxSocketSlots)
	if err != nil {
		return nil, fmt.Errorf("NewMmapSocketSlotTable: %w", err)
	}
	defer func() {
		if slots != nil {
			_ = slots.Close()
		}
	}()

	bridge, err := ownerbpf.LoadEngineBridge(uint32(attrs.Index), netns, 99, uint64(attrs.TxQLen))
	if err != nil {
		return nil, fmt.Errorf("LoadEngineBridge: %w", err)
	}
	defer func() {
		if bridge != nil {
			_ = bridge.Close()
		}
	}()

	probe, err := ownerbpf.LoadEngineSenderProbe("/sys/fs/cgroup", ownerbpf.DefaultEngineMaxActors, ownerbpf.DefaultEngineActorEventQueue)
	if err != nil {
		return nil, fmt.Errorf("LoadEngineSenderProbe: %w", err)
	}
	defer func() {
		if probe != nil {
			_ = probe.Disable()
			_ = probe.Close()
		}
	}()

	bpfDuring, _, err := countSelfBPFAndTotalFDs()
	if err != nil {
		return nil, err
	}

	bridgeErrCh := make(chan error, 1)
	go func() {
		reader, rErr := bridge.Register()
		if rErr != nil {
			bridgeErrCh <- fmt.Errorf("bridge.Register: %w", rErr)
			return
		}
		if eErr := bridge.Enable(uint64(attrs.TxQLen)); eErr != nil {
			_ = reader.Close()
			bridgeErrCh <- fmt.Errorf("bridge.Enable: %w", eErr)
			return
		}
		if _, sErr := bridge.Sample(); sErr != nil {
			_ = bridge.Stop()
			_ = reader.Close()
			bridgeErrCh <- fmt.Errorf("bridge.Sample: %w", sErr)
			return
		}
		sErr := bridge.Stop()
		cErr := reader.Close()
		bridgeErrCh <- errors.Join(sErr, cErr)
	}()
	if gErr := <-bridgeErrCh; gErr != nil {
		return nil, gErr
	}

	if err := probe.Enable(); err != nil {
		return nil, fmt.Errorf("probe.Enable: %w", err)
	}

	// Open a fresh socket after initialize_cookie is attached so skc_cookie != 0
	// when observe_send fires on accepted UDP transmission.
	postConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("open post-probe loopback UDP socket: %w", err)
	}
	_, sendErr := postConn.WriteTo([]byte{0x22}, postConn.LocalAddr())
	closePostErr := postConn.Close()
	if err := errors.Join(sendErr, closePostErr); err != nil {
		return nil, fmt.Errorf("post-probe loopback send: %w", err)
	}

	peerHitsDuring, err := peer.HitCount()
	if err != nil || peerHitsDuring <= peerHitsBefore {
		return nil, fmt.Errorf("peer filter hits did not advance during active eBPF hooks: before=%d during=%d err=%v",
			peerHitsBefore, peerHitsDuring, err)
	}
	if probe.IsPoisoned() {
		return nil, errors.New("sender probe poisoned during capability check")
	}
	if !probe.HasPendingNewActors() {
		return nil, errors.New("sender probe did not signal pending new actor after loopback send")
	}
	events, err := probe.DrainNewActors(nil)
	if err != nil || len(events) == 0 {
		return nil, fmt.Errorf("DrainNewActors len=%d err=%v", len(events), err)
	}
	selfTGID := uint32(os.Getpid())
	var capturedCookie uint64
	var capturedTGID uint32
	for _, ev := range events {
		if ev.Key.TGID == selfTGID && ev.Key.Cookie != 0 {
			capturedCookie = ev.Key.Cookie
			capturedTGID = ev.Key.TGID
			break
		}
	}
	if capturedCookie == 0 {
		return nil, fmt.Errorf("no actor event matched self TGID %d in %d drained events", selfTGID, len(events))
	}

	packetSlots := bridge.PacketSlots()
	socketSlots := slots.MaxSlots

	if err := errors.Join(probe.Disable(), probe.Close()); err != nil {
		probe = nil
		return nil, fmt.Errorf("probe teardown: %w", err)
	}
	probe = nil
	if err := bridge.Close(); err != nil {
		bridge = nil
		return nil, fmt.Errorf("bridge teardown: %w", err)
	}
	bridge = nil
	if err := slots.Close(); err != nil {
		slots = nil
		return nil, fmt.Errorf("slots teardown: %w", err)
	}
	slots = nil

	if _, err := preConn.WriteTo([]byte{0x33}, preConn.LocalAddr()); err != nil {
		return nil, fmt.Errorf("post-teardown peer loopback send: %w", err)
	}
	peerHitsAfter, err := peer.HitCount()
	if err != nil || peerHitsAfter <= peerHitsDuring {
		return nil, fmt.Errorf("peer root-cgroup filter disrupted by teardown: during=%d after=%d err=%v",
			peerHitsDuring, peerHitsAfter, err)
	}

	if err := preConn.Close(); err != nil {
		preConn = nil
		return nil, err
	}
	preConn = nil
	if err := peer.Close(); err != nil {
		peer = nil
		return nil, err
	}
	peer = nil

	runtime.GC()
	runtime.GC()
	bpfAfter, totalAfter, err := countSelfBPFAndTotalFDs()
	if err != nil {
		return nil, err
	}
	if bpfAfter != bpfBefore {
		return nil, fmt.Errorf("BPF/perf FDs leaked after teardown: before=%d during=%d after=%d", bpfBefore, bpfDuring, bpfAfter)
	}

	return ebpfCapabilityEvidence{
		CapEff:              capEffHex,
		CapBnd:              capBndHex,
		HasCapBPF:           hasCapBPF,
		HasCapPerfmon:       hasCapPerfmon,
		HasCapSysAdmin:      hasCapSysAdmin,
		MemlockInfinity:     memlockInf,
		LockdownMode:        lockdownMode,
		PerfEventParanoid:   paranoid,
		TunName:             tunName,
		TunIfindex:          attrs.Index,
		TunTxQLen:           attrs.TxQLen,
		NetNSInode:          netns,
		PacketSlots:         packetSlots,
		SocketSlots:         socketSlots,
		CapturedActorEvents: len(events),
		CapturedCookie:      capturedCookie,
		CapturedTGID:        capturedTGID,
		PeerHitsBefore:      peerHitsBefore,
		PeerHitsDuring:      peerHitsDuring,
		PeerHitsAfter:       peerHitsAfter,
		BPFPerfFDsBefore:    bpfBefore,
		BPFPerfFDsDuring:    bpfDuring,
		BPFPerfFDsAfter:     bpfAfter,
		TotalFDsBefore:      totalBefore,
		TotalFDsAfter:       totalAfter,
	}, nil
}
