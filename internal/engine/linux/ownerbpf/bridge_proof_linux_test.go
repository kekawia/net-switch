//go:build linux && ownerbpfproof && (amd64 || arm64)

package ownerbpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
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

func newBridgeFixture(t *testing.T, fault bool) *bridgeFixture {
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
	f := &bridgeFixture{fd: -1, cpu: cpu, epoch: uint64(time.Now().UnixNano())}
	t.Cleanup(func() {
		if f.fd >= 0 {
			_ = unix.Close(f.fd)
			f.fd = -1
		}
		if f.r != nil {
			if e := f.r.Close(); e != nil {
				t.Error(e)
			}
		}
		if f.b != nil {
			if e := f.b.Close(); e != nil {
				t.Error(e)
			}
		}
	})
	f.fd, e = unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		t.Fatal(e)
	}
	ifr, e := unix.NewIfreq("nsbridge0")
	if e != nil {
		t.Fatal(e)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_TUN_EXCL)
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
	t.Logf("BRIDGE kernel=%s arch=%s epoch=%d queue=500 cpu=%d offloads=0 abi=3 mode=raw_tracepoint", unix.ByteSliceToString(uts.Release[:]), runtime.GOARCH, f.epoch, cpu)
	return f
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
				errCh <- e
				return
			}
			for j := range 600 {
				var p [8]byte
				binary.BigEndian.PutUint32(p[:4], uint32(i))
				binary.BigEndian.PutUint32(p[4:], uint32(j))
				if e := unix.Sendto(sockets[i], p[:], 0, &unix.SockaddrInet4{Addr: [4]byte{198, 18, 0, 2}, Port: 9000}); e != nil {
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
	delivered := 0
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
			if i >= senders || fr.Decision.Status != ReadCookie || fr.Decision.Packet.Cookie != cookies[i] {
				t.Fatalf("payload/cookie swap: sender=%d result=%+v", i, fr.Decision)
			}
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
	t.Logf("P1_DROP sent=1200 read=%d dropped=%d post_drop_cookie=correct", delivered, dropped)
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
	for _, v := range c {
		if !v.Present || v.ProgramID == 0 {
			t.Fatalf("counter ABI missing: %+v", v)
		}
	}
	t.Log(fmt.Sprintf("BRIDGE_COUNTERS programs=%d field_present=true", len(c)))
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
	t.Log("P2_PERF_BASELINE raw=32 perf=32 stressed_skip_control=not_yet_proved")
}
