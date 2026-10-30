//go:build linux && ownerbpfproof && (amd64 || arm64)

package ownerbpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type bridgeFixture struct {
	fd    int
	b     *Bridge
	r     *BridgeReader
	cpu   int
	epoch uint64
}

func newBridgeFixture(t *testing.T, fault bool, receiveFlags ...uint16) *bridgeFixture {
	t.Helper()
	if os.Geteuid() != 0 || os.Getenv("NS_OWNERBPF_PROOF") != "1" {
		t.Fatal("hosted root proof required")
	}
	self, e := os.Readlink("/proc/self/ns/net")
	if e != nil {
		t.Fatal(e)
	}
	host, e := os.Readlink("/proc/1/ns/net")
	if e != nil || self == host {
		t.Fatal("private network namespace required", e)
	}
	if e = unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: 32 << 20, Max: 32 << 20}); e != nil {
		t.Fatal(e)
	}
	runtime.LockOSThread()
	var old unix.CPUSet
	if e = unix.SchedGetaffinity(0, &old); e != nil {
		t.Fatal(e)
	}
	cpu := -1
	for i := 0; i < 1024; i++ {
		if old.IsSet(i) {
			cpu = i
			break
		}
	}
	if cpu < 0 {
		t.Fatal("no available CPU")
	}
	var pinned unix.CPUSet
	pinned.Set(cpu)
	if e = unix.SchedSetaffinity(0, &pinned); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := unix.SchedSetaffinity(0, &old); e != nil {
			t.Error(e)
		}
		runtime.UnlockOSThread()
	})
	f := &bridgeFixture{fd: -1, cpu: cpu}
	t.Cleanup(func() {
		if f.fd >= 0 {
			_ = unix.Close(f.fd)
			f.fd = -1
		}
		if f.r != nil {
			if e := f.r.Close(); e != nil {
				t.Error(e)
			}
			f.r = nil
		}
		if f.b != nil {
			if e := f.b.Close(); e != nil {
				t.Error(e)
			}
			f.b = nil
		}
	})
	f.openDeviceAndCollection(t, fault, receiveFlags...)
	return f
}

func (f *bridgeFixture) openDeviceAndCollection(t *testing.T, fault bool, receiveFlags ...uint16) {
	t.Helper()
	f.epoch = uint64(time.Now().UnixNano())
	var e error
	f.fd, e = unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		t.Fatal(e)
	}
	ifr, e := unix.NewIfreq("nsbridge0")
	if e != nil {
		t.Fatal(e)
	}
	flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_TUN_EXCL)
	for _, extra := range receiveFlags {
		flags |= extra
	}
	ifr.SetUint16(flags)
	if e = unix.IoctlIfreq(f.fd, unix.TUNSETIFF, ifr); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile("/proc/sys/net/ipv6/conf/nsbridge0/disable_ipv6", []byte("1"), 0600); e != nil {
		t.Fatal(e)
	}
	l, e := netlink.LinkByName("nsbridge0")
	if e != nil {
		t.Fatal(e)
	}
	if e = netlink.LinkSetTxQLen(l, 500); e != nil {
		t.Fatal(e)
	}
	l, e = netlink.LinkByName("nsbridge0")
	if e != nil || l.Attrs().TxQLen != 500 {
		t.Fatal("queue readback", e)
	}
	addr, e := netlink.ParseAddr("198.18.0.1/24")
	if e != nil {
		t.Fatal(e)
	}
	if e = netlink.AddrAdd(l, addr); e != nil {
		t.Fatal(e)
	}
	var ns unix.Stat_t
	if e = unix.Stat("/proc/self/ns/net", &ns); e != nil {
		t.Fatal(e)
	}
	object := os.Getenv("NS_BRIDGE_OBJECT")
	if fault {
		object = os.Getenv("NS_BRIDGE_FAULT_OBJECT")
	}
	if object == "" {
		t.Fatal("generated bridge object required")
	}
	f.b, e = LoadBridge(object, BridgeConfig{ABI: ProvenanceABI, Epoch: f.epoch, Ifindex: uint32(l.Attrs().Index), NetNS: uint32(ns.Ino), CPUs: uint32(runtime.NumCPU()), Readers: ReaderLimit})
	if e != nil {
		t.Fatal(e)
	}
	if f.b.Faults() != 0 || f.b.stopped {
		t.Fatal("new collection started unhealthy", f.epoch, f.b.Faults(), f.b.stopped)
	}
	var initialKey uint64
	var initialPacket PacketRecord
	initial := f.b.Collection.Maps["packets"].Iterate()
	if initial.Next(&initialKey, &initialPacket) || initial.Err() != nil {
		t.Fatal("new collection packet map is not empty", initial.Err())
	}
	t.Logf("P2_START epoch=%d fresh_collection=true health=0 packet_map_empty=true", f.epoch)
	f.r, e = f.b.Register()
	if e != nil {
		t.Fatal(e)
	}
	if e = f.b.Enable(uint64(l.Attrs().TxQLen)); e != nil {
		t.Fatal(e)
	}
	if e = netlink.LinkSetUp(l); e != nil {
		t.Fatal(e)
	}
	var uts unix.Utsname
	if e = unix.Uname(&uts); e != nil {
		t.Fatal(e)
	}
	t.Logf("BRIDGE kernel=%s arch=%s epoch=%d queue=500 cpu=%d offloads=0 abi=3 mode=raw_tracepoint", unix.ByteSliceToString(uts.Release[:]), runtime.GOARCH, f.epoch, f.cpu)
	var programs []string
	for name := range f.b.VerifierStats {
		programs = append(programs, name)
	}
	slices.Sort(programs)
	for _, name := range programs {
		t.Logf("VERIFIER fault=%t program=%s %s", fault, name, f.b.VerifierStats[name])
	}
}

func bridgeSocket(t *testing.T, port int) (int, int) {
	t.Helper()
	s, e := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = unix.Close(s) })
	if e = unix.Bind(s, &unix.SockaddrInet4{Addr: [4]byte{198, 18, 0, 1}, Port: port}); e != nil {
		t.Fatal(e)
	}
	if e = unix.SetsockoptInt(s, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO); e != nil {
		t.Fatal(e)
	}
	a, e := unix.Getsockname(s)
	if e != nil {
		t.Fatal(e)
	}
	return s, a.(*unix.SockaddrInet4).Port
}

func bridgeSend(t *testing.T, s int, payload []byte) uint64 {
	t.Helper()
	if e := unix.Sendto(s, payload, 0, &unix.SockaddrInet4{Addr: [4]byte{198, 18, 0, 2}, Port: 9000}); e != nil {
		t.Fatal(e)
	}
	// Query only AFTER the send, so the initializer must have done its job.
	c, e := unix.GetsockoptUint64(s, unix.SOL_SOCKET, unix.SO_COOKIE)
	if e != nil || c == 0 {
		t.Fatal("cookie oracle", e)
	}
	return c
}

func bridgeRead(t *testing.T, f *bridgeFixture, n int) []ReadFrame {
	t.Helper()
	out, e := f.r.ReadBurst(f.fd, n)
	if e != nil {
		t.Fatal(e)
	}
	if len(out) != n {
		t.Fatalf("expected %d queued frames, got %d", n, len(out))
	}
	return out
}

func TestBridgeQueuedPair(t *testing.T) {
	for _, distinct := range []bool{false, true} {
		t.Run(strconv.FormatBool(distinct), func(t *testing.T) {
			f := newBridgeFixture(t, false)
			s, port := bridgeSocket(t, 0)
			p1, p2 := []byte("identical"), []byte("identical")
			if distinct {
				p2 = []byte("different")
			}
			c1 := bridgeSend(t, s, p1)
			if e := unix.Close(s); e != nil {
				t.Fatal(e)
			}
			if _, e := unix.GetsockoptUint64(s, unix.SOL_SOCKET, unix.SO_COOKIE); !errors.Is(e, unix.EBADF) {
				t.Fatal("A not closed", e)
			}
			s2, _ := bridgeSocket(t, port)
			c2 := bridgeSend(t, s2, p2)
			if c1 == c2 {
				t.Fatal("cookies not distinct")
			}
			frames := bridgeRead(t, f, 2)
			for i, c := range []uint64{c1, c2} {
				if frames[i].Decision.Status != ReadCookie || frames[i].Decision.Packet.Cookie != c {
					t.Fatalf("wrong generation %d: %+v want=%d", i, frames[i].Decision, c)
				}
			}
			if !bytes.Equal(frames[0].Data[28:], p1) || !bytes.Equal(frames[1].Data[28:], p2) {
				t.Fatal("independent payload oracle mismatch")
			}
			if !distinct && !bytes.Equal(frames[0].Data, frames[1].Data) {
				t.Fatal("byte-identical precondition not met")
			}
			t.Logf("P1_PAIR distinct_payload=%t known_cookies=2/2 complete_identities=0/2", distinct)
		})
	}
}

func TestBridgeConcurrentDrops(t *testing.T) {
	f := newBridgeFixture(t, false)
	initialLink, err := netlink.LinkByName("nsbridge0")
	if err != nil || initialLink.Attrs().Statistics == nil {
		t.Fatal("kernel drop counter precondition", err)
	}
	initialDrops := initialLink.Attrs().Statistics.TxDropped
	const senders = 2
	var sockets [senders]int
	var cookies [senders]uint64
	for i := range sockets {
		sockets[i], _ = bridgeSocket(t, 0)
		c, e := unix.GetsockoptUint64(sockets[i], unix.SOL_SOCKET, unix.SO_COOKIE)
		if e != nil {
			t.Fatal(e)
		}
		cookies[i] = c
	}
	var wg sync.WaitGroup
	var startSpin, midSpin atomic.Int32
	var started, ended [senders]time.Time
	errCh := make(chan error, senders)
	for i := range senders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			// Sender threads inherit affinity. Choose a verified available CPU
			// from the machine list explicitly; failure is not skipped.
			var set unix.CPUSet
			set.Set(i)
			if e := unix.SchedSetaffinity(0, &set); e != nil {
				startSpin.Add(-10)
				midSpin.Add(-10)
				errCh <- e
				return
			}
			// Two-phase atomic spin barrier: both pinned sender threads must be
			// actively running on CPUs 0 and 1 before either records started[i],
			// and both must rendezvous mid-burst (after 300 sends, once the
			// 500-packet TUN ring is already dropping) before either finishes.
			startSpin.Add(1)
			for startSpin.Load() < senders {
				if startSpin.Load() < 0 {
					return
				}
			}
			started[i] = time.Now()
			defer func() { ended[i] = time.Now() }()
			for j := range 600 {
				if j == 300 {
					midSpin.Add(1)
					for midSpin.Load() < senders {
						if midSpin.Load() < 0 {
							return
						}
					}
				}
				var p [8]byte
				binary.BigEndian.PutUint32(p[:4], uint32(i))
				binary.BigEndian.PutUint32(p[4:], uint32(j))
				if e := unix.Sendto(sockets[i], p[:], 0, &unix.SockaddrInet4{Addr: [4]byte{198, 18, 0, 2}, Port: 9000}); e != nil {
					midSpin.Add(-10)
					errCh <- e
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for e := range errCh {
		t.Fatal(e)
	}
	if !started[0].Before(ended[1]) || !started[1].Before(ended[0]) {
		t.Fatal("sender execution intervals did not overlap", started, ended)
	}
	var states []CPUState
	if e := f.b.Collection.Maps["cpu_state"].Lookup(uint32(0), &states); e != nil {
		t.Fatal(e)
	}
	var captured, dropped uint64
	for _, s := range states {
		captured += s.Captures
		dropped += s.Frees
	}
	if captured != 1200 || dropped == 0 {
		t.Fatalf("drop precondition captured=%d dropped=%d", captured, dropped)
	}
	for i := range senders {
		if i >= len(states) || states[i].Captures != 600 || states[i].Frees == 0 {
			t.Fatalf("kernel per-CPU concurrency/drop evidence missing on cpu %d: %+v", i, states)
		}
	}
	afterLink, err := netlink.LinkByName("nsbridge0")
	if err != nil || afterLink.Attrs().Statistics == nil {
		t.Fatal("kernel drop counter readback", err)
	}
	kernelDrops := afterLink.Attrs().Statistics.TxDropped - initialDrops
	if kernelDrops != dropped {
		t.Fatalf("independent kernel drop counter=%d BPF frees=%d", kernelDrops, dropped)
	}
	delivered := 0
	var seen [senders][600]bool
	for {
		frames, e := f.r.ReadBurst(f.fd, BurstLimit)
		if e != nil {
			t.Fatal(e)
		}
		if len(frames) == 0 {
			break
		}
		for _, fr := range frames {
			if len(fr.Data) < 36 {
				t.Fatal("short packet")
			}
			i := binary.BigEndian.Uint32(fr.Data[28:32])
			sequence := binary.BigEndian.Uint32(fr.Data[32:36])
			if i >= senders || fr.Decision.Status != ReadCookie || fr.Decision.Packet.Cookie != cookies[i] {
				t.Fatalf("payload/cookie swap: sender=%d result=%+v", i, fr.Decision)
			}
			if sequence >= 600 || seen[i][sequence] {
				t.Fatal("invalid or duplicate independently labelled datagram", i, sequence)
			}
			seen[i][sequence] = true
			delivered++
		}
	}
	// A fresh packet AFTER observed drops defeats a capture-cookie FIFO which
	// failed to retire dropped entries: it must not borrow one of their cookies.
	s, _ := bridgeSocket(t, 0)
	c := bridgeSend(t, s, []byte("after-drop"))
	fr := bridgeRead(t, f, 1)[0]
	if fr.Decision.Status != ReadCookie || fr.Decision.Packet.Cookie != c {
		t.Fatal("drop shifted subsequent association")
	}
	if uint64(delivered)+dropped != captured {
		t.Fatalf("independent sent/read/drop accounting: read=%d drop=%d sent=%d", delivered, dropped, captured)
	}
	t.Logf("P1_DROP sent=1200 read=%d dropped=%d kernel_dropped=%d unique_payloads=true post_drop_cookie=correct", delivered, dropped, kernelDrops)
}

func TestBridgePointerReuse(t *testing.T) {
	f := newBridgeFixture(t, true)
	s, _ := bridgeSocket(t, 0)
	seen := map[uint64]uint64{}
	deadline := time.Now().Add(10 * time.Second)
	for i := 0; i < 100000 && time.Now().Before(deadline); i++ {
		c := bridgeSend(t, s, []byte("fixed-size"))
		var states []CPUState
		if e := f.b.Collection.Maps["cpu_state"].Lookup(uint32(0), &states); e != nil {
			t.Fatal(e)
		}
		st := states[f.cpu]
		var before PacketRecord
		if e := f.b.Collection.Maps["packets"].Lookup(st.Address, &before); e != nil || before.Cookie != c || before.Serial != st.SeenSerial {
			t.Fatal("deletion precondition: actual packet record missing/mismatched before read", e, before)
		}
		fr := bridgeRead(t, f, 1)[0]
		if fr.Decision.Status != ReadCookie || fr.Decision.Packet.Cookie != c {
			t.Fatal("ping-pong attribution", fr.Decision)
		}
		var p PacketRecord
		if e := f.b.Collection.Maps["packets"].Lookup(st.Address, &p); !errors.Is(e, ebpf.ErrKeyNotExist) {
			t.Fatal("terminal did not delete", e)
		}
		if old, ok := seen[st.Address]; ok {
			if old == st.SeenSerial {
				t.Fatal("capture generation reused")
			}
			fctl := BridgeFault{Epoch: f.epoch, CPU: uint32(f.cpu), Mode: 1, Address: st.Address}
			if e := f.b.Collection.Maps["faults"].Update(uint32(0), fctl, ebpf.UpdateAny); e != nil {
				t.Fatal(e)
			}
			for j := 0; j < 100000 && time.Now().Before(deadline); j++ {
				bridgeSend(t, s, []byte("fixed-size"))
				if e := f.b.Collection.Maps["faults"].Lookup(uint32(0), &fctl); e != nil {
					t.Fatal(e)
				}
				var observed []CPUState
				if e := f.b.Collection.Maps["cpu_state"].Lookup(uint32(0), &observed); e != nil {
					t.Fatal(e)
				}
				if fctl.Hits != 0 && observed[f.cpu].Address != st.Address {
					t.Fatal("suppression hit without independently observed pointer recurrence")
				}
				frames, e := f.r.ReadBurst(f.fd, 1)
				if fctl.Hits != 0 {
					if !errors.Is(e, ErrEpochRebuild) || len(frames) != 1 || frames[0].Decision.Status == ReadCookie || f.b.DeliveredWithoutRecord.Load() != 1 {
						t.Fatal("suppressed recurrent address accepted", e, frames)
					}
					t.Logf("P2_REUSE iterations=%d same_cookie=%d address=%x generations=%d/%d recurrence_suppressed=1 unknown=1", i+1, c, st.Address, old, st.SeenSerial)
					return
				}
				if e != nil {
					t.Fatal(e)
				}
			}
			t.Fatal("known pointer did not recur for suppression control")
		}
		seen[st.Address] = st.SeenSerial
	}
	t.Fatal("actual pointer reuse not observed within 10s/100000 iterations")
}

func TestBridgeInfoLayout(t *testing.T) {
	// Real program query exercises the UAPI path; compile-time offsets are also
	// checked against linux/bpf.h by the hosted compiler fixture.
	f := newBridgeFixture(t, false)
	c, e := f.b.Sample()
	if e != nil {
		t.Fatal(e)
	}
	wantPresent := !verifiedFloor58Profile()
	for _, v := range c {
		if v.Present != wantPresent || v.ProgramID == 0 {
			t.Fatalf("counter ABI mismatch (wantPresent=%t): %+v", wantPresent, v)
		}
	}
	t.Log(fmt.Sprintf("BRIDGE_COUNTERS programs=%d field_present=%t floor58=%t", len(c), wantPresent, !wantPresent))
}

func TestBridgeRelocations(t *testing.T) {
	for _, variable := range []string{"NS_BRIDGE_OBJECT", "NS_BRIDGE_FAULT_OBJECT"} {
		path := os.Getenv(variable)
		if path == "" {
			t.Fatalf("required generated object: %s", variable)
		}
		spec, err := ebpf.LoadCollectionSpec(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkBridgeSpec(spec); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"capture", "consume", "freed"} {
			clockCalls := 0
			for _, ins := range spec.Programs[name].Instructions {
				if ins.IsBuiltinCall() && ins.Constant == int64(asm.FnKtimeGetNs) {
					clockCalls++
				}
			}
			want := 0
			if variable == "NS_BRIDGE_FAULT_OBJECT" {
				want = 33
			}
			if clockCalls != want {
				t.Fatalf("%s %s compiled hold shape: clock sites=%d want=%d", variable, name, clockCalls, want)
			}
			t.Logf("HOLD_SHAPE object=%s program=%s clock_call_sites=%d", variable, name, clockCalls)
		}
		kernelRelocations := 0
		for _, ins := range spec.Programs["perf_consume"].Instructions {
			if r := btf.CORERelocationMetadata(&ins); r != nil {
				t.Logf("PERF_CORE object=%s relocation=%s", variable, r)
				kernelRelocations++
			}
		}
		if kernelRelocations == 0 {
			t.Fatal("kernel field relocations disappeared along with context relocation")
		}
		t.Logf("PERF_CORE object=%s local_context_relocations=0 kernel_relocations=%d", variable, kernelRelocations)
	}
}

func TestBridgePerfCounterBaseline(t *testing.T) {
	f := newBridgeFixture(t, false)
	counts := func() (uint64, uint64) {
		var states []CPUState
		if err := f.b.Collection.Maps["cpu_state"].Lookup(uint32(0), &states); err != nil {
			t.Fatal(err)
		}
		var raw, perf uint64
		for _, state := range states {
			raw += state.Consumes
			perf += state.PerfConsumes
		}
		return raw, perf
	}
	beforeRaw, beforePerf := counts()
	s, _ := bridgeSocket(t, 0)
	for range 32 {
		cookie := bridgeSend(t, s, []byte("perf-baseline"))
		frame := bridgeRead(t, f, 1)[0]
		if frame.Decision.Status != ReadCookie || frame.Decision.Packet.Cookie != cookie {
			t.Fatal("baseline traffic did not have correct evidence", frame.Decision)
		}
	}
	afterRaw, afterPerf := counts()
	if afterRaw-beforeRaw != 32 || afterPerf-beforePerf != 32 {
		t.Fatalf("unstressed counter baseline differs: raw=%d perf=%d want=32/32", afterRaw-beforeRaw, afterPerf-beforePerf)
	}
	t.Log("P2_PERF_BASELINE raw=32 perf=32 scope=unstressed stress_control=TestBridgePerfSkippedConsumes")
}

func TestBridgePreLoaderSocket(t *testing.T) {
	// Create socket BEFORE LoadBridge and never call SO_COOKIE before sending.
	s, e := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = unix.Close(s) })
	f := newBridgeFixture(t, false)
	if e = unix.SetsockoptInt(s, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO); e != nil {
		t.Fatal(e)
	}
	var beforeHealth [8]uint64
	if e = f.b.Collection.Maps["health"].Lookup(uint32(0), &beforeHealth); e != nil {
		t.Fatal(e)
	}
	payload := []byte("pre-loader-socket")
	c := bridgeSend(t, s, payload)
	var afterHealth [8]uint64
	if e = f.b.Collection.Maps["health"].Lookup(uint32(0), &afterHealth); e != nil {
		t.Fatal(e)
	}
	if afterHealth[1] <= beforeHealth[1] || afterHealth[2] != beforeHealth[2] {
		t.Fatalf("root-cgroup initializer did not initialize pre-loader socket cookie: before=%v after=%v", beforeHealth[:3], afterHealth[:3])
	}
	fr := bridgeRead(t, f, 1)[0]
	if fr.Decision.Status != ReadCookie || fr.Decision.Packet.Cookie != c || !bytes.Equal(fr.Data[28:], payload) {
		t.Fatalf("pre-loader socket attribution failed: %+v", fr.Decision)
	}
	t.Logf("P1_PRE_LOADER cookie=%d init_calls_delta=%d init_zero=%d", c, afterHealth[1]-beforeHealth[1], afterHealth[2])
}

func TestBridgeReadLifetimes(t *testing.T) {
	if runtime.NumCPU() < 2 {
		t.Fatal("two CPUs required for cross-CPU capture and nested-terminal controls")
	}
	f := newBridgeFixture(t, true)
	s, _ := bridgeSocket(t, 0)

	// 1. Empty read (EAGAIN), EINTR and zero-length read do not dequeue or fault.
	emptyFrames, err := f.r.ReadBurst(f.fd, 4)
	if err != nil || len(emptyFrames) != 0 || f.b.Faults() != 0 {
		t.Fatalf("empty EAGAIN burst failed: frames=%d err=%v faults=%d", len(emptyFrames), err, f.b.Faults())
	}
	eintrFrames, eintrErr := f.r.readBurst(f.fd, 1, func(int, []byte) (int, error) {
		return -1, unix.EINTR
	})
	if eintrErr != nil || len(eintrFrames) != 0 || f.b.Faults() != 0 || f.b.stopped {
		t.Fatalf("EINTR burst failed or poisoned epoch: frames=%d err=%v faults=%d stopped=%t", len(eintrFrames), eintrErr, f.b.Faults(), f.b.stopped)
	}
	c1 := bridgeSend(t, s, []byte("queued-for-zero-read"))
	zeroFrames, err := f.r.readBurst(f.fd, 1, func(fd int, _ []byte) (int, error) {
		return unix.Read(fd, nil)
	})
	if err != nil || len(zeroFrames) != 0 || f.b.Faults() != 0 {
		t.Fatalf("zero-length read failed or dequeued packet: frames=%d err=%v faults=%d", len(zeroFrames), err, f.b.Faults())
	}
	fr1 := bridgeRead(t, f, 1)[0]
	if fr1.Decision.Status != ReadCookie || fr1.Decision.Packet.Cookie != c1 || !bytes.Equal(fr1.Data[28:], []byte("queued-for-zero-read")) {
		t.Fatalf("packet after zero-length read corrupted: %+v", fr1.Decision)
	}

	// 2. Truncated read retains packet provenance while returning truncated bytes.
	c2 := bridgeSend(t, s, []byte("0123456789abcdef0123456789abcdef"))
	truncFrames, err := f.r.readBurst(f.fd, 1, func(fd int, dst []byte) (int, error) {
		return unix.Read(fd, dst[:32])
	})
	if err != nil || len(truncFrames) != 1 || len(truncFrames[0].Data) != 32 || truncFrames[0].Decision.Status != ReadCookie || truncFrames[0].Decision.Packet.Cookie != c2 || truncFrames[0].Decision.Packet.Length <= 32 {
		t.Fatalf("truncated read failed: len=%d err=%v decision=%+v", len(truncFrames), err, truncFrames)
	}

	// 3. Cross-CPU capture and one-read cross-CPU health observation bound:
	// sender pinned to otherCPU, reader on f.cpu.
	otherCPU := (f.cpu + 1) % 2
	sendCrossCPU := func(payload []byte) uint64 {
		type sendRes struct {
			cookie uint64
			err    error
		}
		ch := make(chan sendRes, 1)
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			var mask unix.CPUSet
			mask.Set(otherCPU)
			if err := unix.SchedSetaffinity(0, &mask); err != nil {
				ch <- sendRes{err: err}
				return
			}
			if err := unix.Sendto(s, payload, 0, &unix.SockaddrInet4{Addr: [4]byte{198, 18, 0, 2}, Port: 9000}); err != nil {
				ch <- sendRes{err: err}
				return
			}
			c, err := unix.GetsockoptUint64(s, unix.SOL_SOCKET, unix.SO_COOKIE)
			ch <- sendRes{cookie: c, err: err}
		}()
		res := <-ch
		if res.err != nil || res.cookie == 0 {
			t.Fatal("cross-CPU send failed:", res.err)
		}
		return res.cookie
	}
	cCross := sendCrossCPU([]byte("cross-cpu-packet"))
	frCross := bridgeRead(t, f, 1)[0]
	if frCross.Decision.Status != ReadCookie || frCross.Decision.Packet.Cookie != cCross || int(frCross.Decision.Packet.CPU) != otherCPU {
		t.Fatalf("cross-CPU capture failed: got=%+v want_cpu=%d", frCross.Decision, otherCPU)
	}

	// 3b. One-read cross-CPU health observation bound: a capture fault raised on
	// otherCPU updates shared health.epoch_faults and must cause the very next read
	// on f.cpu to return ReadEpochFault with Rebuild=true.
	_ = bridgeSend(t, s, []byte("queued-before-cross-cpu-fault"))
	var states []CPUState
	if err := f.b.Collection.Maps["cpu_state"].Lookup(uint32(0), &states); err != nil {
		t.Fatal(err)
	}
	states[otherCPU].Serial = ^uint64(0)
	if err := f.b.Collection.Maps["cpu_state"].Update(uint32(0), states, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	_ = sendCrossCPU([]byte("cross-cpu-serial-overflow-fault"))
	if f.b.Faults() == 0 {
		t.Fatal("cross-CPU capture fault did not increment shared health.epoch_faults")
	}
	crossHealthFrames, crossHealthErr := f.r.ReadBurst(f.fd, 1)
	if !errors.Is(crossHealthErr, ErrEpochRebuild) || !f.b.stopped || (len(crossHealthFrames) != 0 && (len(crossHealthFrames) != 1 || crossHealthFrames[0].Decision.Status != ReadEpochFault || !crossHealthFrames[0].Decision.Rebuild)) {
		t.Fatalf("one-read cross-CPU health bound failed on reader CPU %d: err=%v stopped=%t frames=%+v", f.cpu, crossHealthErr, f.b.stopped, crossHealthFrames)
	}
	reloadBridgeFixture(t, f, true)

	// 3c. Uninitialized AF_PACKET skb (cookie_missing) and shared-skb rejection (users != 1):
	// First, an AF_PACKET TPACKET_V2 PACKET_TX_RING send bypasses INET cgroup egress
	// cookie initialization, so capture observes p.cookie == 0 (state->cookie_missing > 0,
	// p.status = 0) and CheckRead refuses attribution with ReadUnknown and Rebuild=false
	// without tearing down the epoch.
	ethPIP := binary.BigEndian.Uint16([]byte{byte(unix.ETH_P_IP >> 8), byte(unix.ETH_P_IP & 0xff)})
	pktFD, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, int(ethPIP))
	if err != nil {
		t.Fatal("AF_PACKET socket:", err)
	}
	t.Cleanup(func() {
		if pktFD >= 0 {
			_ = unix.Close(pktFD)
		}
	})
	if err := unix.SetsockoptInt(pktFD, unix.SOL_PACKET, unix.PACKET_VERSION, unix.TPACKET_V2); err != nil {
		t.Fatal("PACKET_VERSION TPACKET_V2:", err)
	}
	req := unix.TpacketReq{
		Block_size: 4096,
		Block_nr:   1,
		Frame_size: 2048,
		Frame_nr:   2,
	}
	if err := unix.SetsockoptTpacketReq(pktFD, unix.SOL_PACKET, unix.PACKET_TX_RING, &req); err != nil {
		t.Fatal("PACKET_TX_RING:", err)
	}
	ringMem, err := unix.Mmap(pktFD, 0, int(req.Block_size*req.Block_nr), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		t.Fatal("mmap PACKET_TX_RING:", err)
	}
	t.Cleanup(func() {
		if ringMem != nil {
			_ = unix.Munmap(ringMem)
		}
	})
	sll := &unix.SockaddrLinklayer{
		Protocol: ethPIP,
		Ifindex:  int(f.b.config.Ifindex),
	}
	if err := unix.Bind(pktFD, sll); err != nil {
		t.Fatal("bind AF_PACKET:", err)
	}
	const tpacket2DataOff = 32
	ipUDP := []byte{
		0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00,
		198, 18, 0, 1, 198, 18, 0, 2,
		0x23, 0x28, 0x23, 0x28, 0x00, 0x08, 0x00, 0x00,
	}
	copy(ringMem[tpacket2DataOff:], ipUDP)
	*(*uint32)(unsafe.Pointer(&ringMem[0])) = unix.TP_STATUS_SEND_REQUEST
	*(*uint32)(unsafe.Pointer(&ringMem[4])) = uint32(len(ipUDP))
	*(*uint32)(unsafe.Pointer(&ringMem[8])) = uint32(len(ipUDP))
	if err := unix.Sendto(pktFD, nil, 0, nil); err != nil {
		t.Fatal("AF_PACKET TX_RING send:", err)
	}
	if err := f.b.Collection.Maps["cpu_state"].Lookup(uint32(0), &states); err != nil {
		t.Fatal(err)
	}
	if states[f.cpu].CookieMissing == 0 {
		t.Fatalf("AF_PACKET TPACKET_V2 TX_RING did not record cookie_missing on CPU %d: state=%+v", f.cpu, states[f.cpu])
	}
	noCookieFrames, noCookieErr := f.r.ReadBurst(f.fd, 1)
	if noCookieErr != nil || f.b.stopped || len(noCookieFrames) != 1 || noCookieFrames[0].Decision.Status != ReadUnknown || noCookieFrames[0].Decision.Rebuild {
		t.Fatalf("uninitialized AF_PACKET skb (cookie == 0) was not classified as ReadUnknown with Rebuild=false: err=%v stopped=%t frames=%+v", noCookieErr, f.b.stopped, noCookieFrames)
	}
	_ = unix.Munmap(ringMem)
	ringMem = nil
	_ = unix.Close(pktFD)
	pktFD = -1

	// Next, verify shared-skb rejection (users != 1) when an skb has users == 2 at capture
	// (mode 64): capture increments state->shared and sets p.status = 0, and CheckRead
	// refuses attribution with ReadUnknown and Rebuild=false in the same live epoch.
	sharedCtl := BridgeFault{Epoch: f.epoch, CPU: uint32(f.cpu), Mode: 64}
	if err := f.b.Collection.Maps["faults"].Update(uint32(0), sharedCtl, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	_ = bridgeSend(t, s, []byte("shared-skb-users-2"))
	if err := f.b.Collection.Maps["cpu_state"].Lookup(uint32(0), &states); err != nil {
		t.Fatal(err)
	}
	sharedCount := states[f.cpu].Shared
	if sharedCount == 0 {
		t.Fatalf("shared-skb fault control did not record shared skb (users != 1) on CPU %d: state=%+v", f.cpu, states[f.cpu])
	}
	sharedFrames, sharedErr := f.r.ReadBurst(f.fd, 1)
	if sharedErr != nil || f.b.stopped || len(sharedFrames) != 1 || sharedFrames[0].Decision.Status != ReadUnknown || sharedFrames[0].Decision.Rebuild {
		t.Fatalf("shared skb (users != 1) was not classified as ReadUnknown with Rebuild=false: err=%v stopped=%t frames=%+v", sharedErr, f.b.stopped, sharedFrames)
	}
	if err := f.b.Collection.Maps["faults"].Update(uint32(0), BridgeFault{}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}

	// 4. Publication suppression (mode 2) on a multi-packet burst (4 datagrams):
	// retires all dequeued packet records while refusing the whole 4-packet burst,
	// stopping the epoch and fencing another reader's uncommitted batch at Publish.
	f.b.config.Enabled = 0
	if err := f.b.Collection.Maps["config"].Update(uint32(0), f.b.config, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	r2Ready := make(chan error, 1)
	r2Done := make(chan struct{})
	r2Close := make(chan struct{})
	go func() {
		defer close(r2Done)
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		r2, err := f.b.Register()
		if err != nil {
			r2Ready <- err
			return
		}
		r2Ready <- nil
		<-r2Close
		if err := r2.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := <-r2Ready; err != nil {
		t.Fatal(err)
	}
	if err := f.b.Enable(500); err != nil {
		t.Fatal(err)
	}
	var c3 uint64
	for idx := range 4 {
		c3 = bridgeSend(t, s, []byte(fmt.Sprintf("multi-burst-%d", idx)))
	}
	if err := f.b.Collection.Maps["cpu_state"].Lookup(uint32(0), &states); err != nil {
		t.Fatal(err)
	}
	st := states[f.cpu]
	// Arm publication suppression on the 4th packet (st.Address, st.SeenSerial)
	// so the first 3 reads in the burst succeed and the 4th triggers ReadMissing + Rebuild,
	// invalidating all 4 frames in the burst at the post-burst gate.
	ctl := BridgeFault{Epoch: f.epoch, CPU: uint32(f.cpu), Mode: 2, Address: st.Address, Serial: st.SeenSerial}
	if err := f.b.Collection.Maps["faults"].Update(uint32(0), ctl, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	oldEpoch := f.epoch
	pubFrames, pubErr := f.r.ReadBurst(f.fd, 4)
	if !errors.Is(pubErr, ErrEpochRebuild) || len(pubFrames) != 4 || f.b.DeliveredWithoutRecord.Load() != 1 {
		t.Fatalf("multi-packet burst fault misclassified: err=%v len=%d missing=%d frames=%+v", pubErr, len(pubFrames), f.b.DeliveredWithoutRecord.Load(), pubFrames)
	}
	for idx, pf := range pubFrames {
		if pf.Decision.Status == ReadCookie || !pf.Decision.Rebuild {
			t.Fatalf("frame %d in faulted multi-packet burst was not invalidated: %+v", idx, pf.Decision)
		}
	}
	published := false
	if err := f.b.Publish(oldEpoch, func() { published = true }); !errors.Is(err, ErrEpochRebuild) || published {
		t.Fatalf("uncommitted second-reader batch was not fenced by stopped epoch: err=%v published=%t", err, published)
	}
	var retired PacketRecord
	if err := f.b.Collection.Maps["packets"].Lookup(st.Address, &retired); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("publication fault did not retire packet record: %v", err)
	}
	close(r2Close)
	<-r2Done
	reloadBridgeFixture(t, f, true)

	// 5. Positive control: nested_terminal > 0 during an armed read on f.cpu.
	// While f.r is armed in consume_skb (held via mode 8), netem's pinned hrtimer
	// fires on f.cpu and drops queued background packets into the full ring,
	// invoking terminal(skb, NS_TERMINAL_FREE) in softirq on the same armed task
	// and incrementing s->completion.count > 1 (ReadAmbiguous) and state->nested > 0.
	sRead, _ := bridgeSocket(t, 0)
	sBg, _ := bridgeSocket(t, 0)
	bgCookie := bridgeSend(t, sBg, []byte("bg-init"))
	_ = bridgeRead(t, f, 1)
	f.b.config.BackgroundCookie = bgCookie
	if err := f.b.Collection.Maps["config"].Update(uint32(0), f.b.config, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	for range 500 {
		bridgeSend(t, sRead, []byte("fill-for-nested-terminal"))
	}
	l, err := netlink.LinkByName("nsbridge0")
	if err != nil {
		t.Fatal(err)
	}
	q := netlink.NewNetem(netlink.QdiscAttrs{LinkIndex: l.Attrs().Index, Handle: netlink.MakeHandle(1, 0), Parent: netlink.HANDLE_ROOT}, netlink.NetemQdiscAttrs{Latency: 2000, Limit: 100})
	if err := netlink.QdiscReplace(q); err != nil {
		t.Fatal(err)
	}
	holdCtl := BridgeFault{Epoch: f.epoch, CPU: uint32(f.cpu), Mode: 8}
	if err := f.b.Collection.Maps["faults"].Update(uint32(0), holdCtl, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	var bgSendErr error
	nestedFrames, nestedErr := f.r.readBurst(f.fd, 1, func(fd int, dst []byte) (int, error) {
		atomic.StoreUint64(&f.r.slot.Control.Armed, 0)
		for range 8 {
			if err := unix.Sendto(sBg, []byte("bg-nested-drop"), 0, &unix.SockaddrInet4{Addr: [4]byte{198, 18, 0, 2}, Port: 9000}); err != nil {
				bgSendErr = err
				return -1, err
			}
		}
		atomic.StoreUint64(&f.r.slot.Control.Armed, 1)
		return unix.Read(fd, dst)
	})
	if bgSendErr != nil {
		t.Fatal(bgSendErr)
	}
	_ = netlink.QdiscDel(netlink.NewNetem(netlink.QdiscAttrs{LinkIndex: l.Attrs().Index, Handle: netlink.MakeHandle(1, 0), Parent: netlink.HANDLE_ROOT}, netlink.NetemQdiscAttrs{}))
	if len(nestedFrames) != 1 || nestedFrames[0].Decision.Status != ReadAmbiguous || nestedErr != nil {
		t.Fatalf("nested terminal during armed read did not produce ReadAmbiguous: err=%v frames=%+v", nestedErr, nestedFrames)
	}
	if err := f.b.Collection.Maps["cpu_state"].Lookup(uint32(0), &states); err != nil {
		t.Fatal(err)
	}
	nestedCount := states[f.cpu].Nested
	if nestedCount == 0 {
		t.Fatalf("positive control nested_terminal was 0 on reader CPU %d", f.cpu)
	}

	// 6. Queue resize and link-down/close retirement: remaining 499 queued packets
	// are freed by the kernel and retired by the kfree_skb raw tracepoint leaving packets empty.
	if err := netlink.LinkSetTxQLen(l, 250); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetDown(l); err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(f.fd); err != nil {
		t.Fatal(err)
	}
	f.fd = -1
	deadline := time.Now().Add(2 * time.Second)
	for {
		var k uint64
		var v PacketRecord
		it := f.b.Collection.Maps["packets"].Iterate()
		if !it.Next(&k, &v) && it.Err() == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("queued packets survived link down and close: key=%x err=%v", k, it.Err())
		}
		time.Sleep(time.Millisecond)
	}
	if err := f.b.Collection.Maps["cpu_state"].Lookup(uint32(0), &states); err != nil {
		t.Fatal(err)
	}
	var deleted uint64
	for _, cpuState := range states {
		deleted += cpuState.Deleted
	}
	if deleted < 500 {
		t.Fatalf("expected >=500 deleted records after close purge, got %d", deleted)
	}
	t.Logf("P2_LIFETIMES empty=pass zero_read=pass eintr=pass truncated=%d cross_cpu=%d cross_cpu_health_bound=1_read shared_skb_rejected=%d multi_burst_refused=4 nested_terminal=%d ambiguous_reads=1 pub_fault_cookie=%d purge_deleted=%d packet_map_empty=true", truncFrames[0].Decision.Packet.Length, otherCPU, sharedCount, nestedCount, c3, deleted)
}


