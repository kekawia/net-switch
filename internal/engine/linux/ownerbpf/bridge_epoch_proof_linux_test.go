//go:build linux && ownerbpfproof && (amd64 || arm64)

package ownerbpf

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// A lifecycle proof must first establish that stale state actually exists.
// This helper does not reset anything: it disposes the device and collection.
func reloadBridgeFixture(t *testing.T, old *bridgeFixture, fault ...bool) *bridgeFixture {
	t.Helper()
	useFault := len(fault) > 0 && fault[0]
	oldEpoch := old.epoch
	info, err := old.b.Collection.Maps["packets"].Info()
	if err != nil {
		t.Fatal(err)
	}
	oldID, ok := info.ID()
	if !ok {
		t.Fatal("packet map ID unavailable")
	}
	if err := old.b.Stop(); err != nil {
		t.Fatal(err)
	}
	called := false
	if err := old.b.Publish(oldEpoch, func() { called = true }); !errors.Is(err, ErrEpochRebuild) || called {
		t.Fatal("stopped epoch still publishes")
	}
	if err := unix.Close(old.fd); err != nil {
		t.Fatal(err)
	}
	old.fd = -1
	if err := old.r.Close(); err != nil {
		t.Fatal(err)
	}
	old.r = nil
	if err := old.b.Close(); err != nil {
		t.Fatal(err)
	}
	old.b = nil
	// Kernel RCU can defer release. Observe retirement before creating the new
	// collection, so a later dependency cleanup cannot get credit for this one.
	deadline := time.Now().Add(2 * time.Second)
	for {
		m, err := ebpf.NewMapFromID(oldID)
		if errors.Is(err, unix.ENOENT) {
			break
		}
		if err != nil {
			t.Fatal("old map retirement query", err)
		}
		if err := m.Close(); err != nil {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("old packet map survived collection close", oldID)
		}
		time.Sleep(time.Millisecond)
	}
	old.openDeviceAndCollection(t, useFault)
	newInfo, err := old.b.Collection.Maps["packets"].Info()
	if err != nil {
		t.Fatal(err)
	}
	newID, ok := newInfo.ID()
	if !ok || newID == oldID || old.epoch == oldEpoch {
		t.Fatal("collection/epoch was reused")
	}
	var key uint64
	var value PacketRecord
	it := old.b.Collection.Maps["packets"].Iterate()
	if it.Next(&key, &value) {
		t.Fatal("fresh packet map not empty", key, value)
	}
	if err := it.Err(); err != nil {
		t.Fatal(err)
	}
	s, _ := bridgeSocket(t, 0)
	cookie := bridgeSend(t, s, []byte("after-reload"))
	frame := bridgeRead(t, old, 1)[0]
	if frame.Decision.Status != ReadCookie || frame.Decision.Packet.Cookie != cookie || frame.Decision.Packet.Epoch != old.epoch {
		t.Fatal("fresh collection did not capture fresh traffic", frame.Decision)
	}
	t.Logf("P2_RELOAD old_epoch=%d new_epoch=%d old_map=%d new_map=%d old_map_retired=true fresh_map_empty=true fresh_cookie=correct old_publication=refused", oldEpoch, old.epoch, oldID, newID)
	return old
}

func TestBridgeDeletionFaultReload(t *testing.T) {
	f := newBridgeFixture(t, true)
	s, _ := bridgeSocket(t, 0)
	cookie := bridgeSend(t, s, []byte("retain-this-record"))
	var states []CPUState
	if err := f.b.Collection.Maps["cpu_state"].Lookup(uint32(0), &states); err != nil {
		t.Fatal(err)
	}
	st := states[f.cpu]
	var before PacketRecord
	if err := f.b.Collection.Maps["packets"].Lookup(st.Address, &before); err != nil || before.Cookie != cookie {
		t.Fatal("starting record absent", err, before)
	}
	ctl := BridgeFault{Epoch: f.epoch, CPU: uint32(f.cpu), Mode: 4, Address: st.Address, Serial: st.SeenSerial}
	if err := f.b.Collection.Maps["faults"].Update(uint32(0), ctl, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	frames, err := f.r.ReadBurst(f.fd, 1)
	if !errors.Is(err, ErrEpochRebuild) || len(frames) != 1 || frames[0].Decision.Status == ReadCookie || f.b.Faults() == 0 {
		t.Fatal("deletion fault was accepted", err, frames)
	}
	var retained PacketRecord
	if err := f.b.Collection.Maps["packets"].Lookup(st.Address, &retained); err != nil || retained != before {
		t.Fatal("retained-entry precondition not met", err, retained)
	}
	t.Logf("P2_DELETE retained_before_reload=true cookie=%d health=%d", cookie, f.b.Faults())
	reloadBridgeFixture(t, f)
}

func setProofPriority(priority int32) error {
	// Linux UAPI include/uapi/linux/sched.h calls the ordinary policy
	// SCHED_NORMAL (0); this is also the name exported by our pinned x/sys.
	policy := uintptr(unix.SCHED_NORMAL)
	if priority != 0 {
		policy = unix.SCHED_FIFO
	}
	_, _, errno := unix.Syscall(unix.SYS_SCHED_SETSCHEDULER, 0, policy, uintptr(unsafe.Pointer(&priority)))
	if errno != 0 {
		return errno
	}
	return nil
}

func verifyProofThread(cpu int, priority uint32) error {
	a, err := unix.SchedGetAttr(0, 0)
	if err != nil {
		return err
	}
	want := uint32(unix.SCHED_NORMAL)
	if priority != 0 {
		want = unix.SCHED_FIFO
	}
	var mask unix.CPUSet
	if err := unix.SchedGetaffinity(0, &mask); err != nil {
		return err
	}
	if a.Policy != want || a.Priority != priority || mask.Count() != 1 || !mask.IsSet(cpu) {
		return fmt.Errorf("scheduler readback tid=%d policy=%d priority=%d cpu=%d mask=%v", unix.Gettid(), a.Policy, a.Priority, cpu, mask)
	}
	return nil
}

func newEventFD(t *testing.T) int {
	t.Helper()
	efd, err := unix.Eventfd(0, unix.EFD_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(efd) })
	return efd
}

func waitEventFD(efd int) error {
	var buf [8]byte
	for {
		n, err := unix.Read(efd, buf[:])
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n == 8 {
			return nil
		}
	}
}

func signalEventFD(efd int) error {
	buf := [8]byte{1}
	_, err := unix.Write(efd, buf[:])
	return err
}

type rawMapElemAttr struct {
	mapFD uint32
	_     uint32
	key   uint64
	value uint64
	flags uint64
}

func rawLookupFault(mapFD int, out *BridgeFault) error {
	var zeroKey uint32
	attr := rawMapElemAttr{
		mapFD: uint32(mapFD),
		key:   uint64(uintptr(unsafe.Pointer(&zeroKey))),
		value: uint64(uintptr(unsafe.Pointer(out))),
	}
	_, _, errno := unix.RawSyscall(unix.SYS_BPF, 1 /* BPF_MAP_LOOKUP_ELEM */, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	runtime.KeepAlive(&zeroKey)
	runtime.KeepAlive(out)
	if errno != 0 {
		return errno
	}
	return nil
}

func rawUpdateFault(mapFD int, in *BridgeFault) error {
	var zeroKey uint32
	attr := rawMapElemAttr{
		mapFD: uint32(mapFD),
		key:   uint64(uintptr(unsafe.Pointer(&zeroKey))),
		value: uint64(uintptr(unsafe.Pointer(in))),
	}
	_, _, errno := unix.RawSyscall(unix.SYS_BPF, 2 /* BPF_MAP_UPDATE_ELEM */, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	runtime.KeepAlive(&zeroKey)
	runtime.KeepAlive(in)
	if errno != 0 {
		return errno
	}
	return nil
}

func releaseHold(f *bridgeFixture) {
	faultsFD := f.b.Collection.Maps["faults"].FD()
	var state BridgeFault
	if err := rawLookupFault(faultsFD, &state); err == nil && state.Reserved[0] != 0 && state.Reserved[2] == 0 {
		state.Reserved[1] = 1
		_ = rawUpdateFault(faultsFD, &state)
	}
}

// Complete controller setup before the holder can enter the bounded BPF
// window. Starting a goroutine is not evidence it has run, pinned, or polled.
func readyHoldController(t *testing.T, f *bridgeFixture, trigger func() error) <-chan error {
	t.Helper()
	faultsFD := f.b.Collection.Maps["faults"].FD()
	ready := make(chan error, 1)
	result := make(chan error, 1)
	cancel := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		var old unix.CPUSet
		if err := unix.SchedGetaffinity(0, &old); err != nil {
			ready <- err
			return
		}
		var mask unix.CPUSet
		cpu := (f.cpu + 1) % 2
		mask.Set(cpu)
		if err := unix.SchedSetaffinity(0, &mask); err != nil {
			ready <- err
			return
		}
		defer func() {
			if err := unix.SchedSetaffinity(0, &old); err != nil {
				t.Error(err)
			}
		}()
		if err := setProofPriority(30); err != nil {
			ready <- err
			return
		}
		defer func() {
			if err := setProofPriority(0); err != nil {
				t.Error(err)
			}
		}()
		if err := verifyProofThread(cpu, 30); err != nil {
			ready <- err
			return
		}
		t.Logf("P2_CONTROLLER ready=true tid=%d cpu=%d policy=FIFO priority=30", unix.Gettid(), cpu)
		ready <- nil
		deadline := time.Now().Add(time.Second)
		for iter := 0; ; iter++ {
			if iter&255 == 0 {
				if !time.Now().Before(deadline) {
					break
				}
				select {
				case <-cancel:
					return
				default:
				}
			}
			var active BridgeFault
			if err := rawLookupFault(faultsFD, &active); err != nil {
				result <- err
				return
			}
			if active.Reserved[0] != 0 {
				if active.Reserved[2] != 0 {
					result <- fmt.Errorf("hold ended before ready controller observed it: holder=%d hits=%d", active.Reserved[0], active.Hits)
					return
				}
				result <- trigger()
				<-cancel
				return
			}
		}
		result <- errors.New("ready controller never observed the armed hold")
	}()
	t.Cleanup(func() { close(cancel); <-done })
	if err := <-ready; err != nil {
		t.Fatal(err)
	}
	return result
}

func hasKernelConfig(t *testing.T, key string) bool {
	t.Helper()
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return false
	}
	rel := unix.ByteSliceToString(uts.Release[:])
	cfg, err := os.ReadFile("/boot/config-" + rel)
	if err != nil {
		return false
	}
	want := key + "=y"
	for _, line := range strings.Split(string(cfg), "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}

func ensureFullPreempt(t *testing.T) {
	t.Helper()
	var uts unix.Utsname
	if err := unix.Uname(&uts); err == nil {
		rel := unix.ByteSliceToString(uts.Release[:])
		if cfg, err := os.ReadFile("/boot/config-" + rel); err == nil {
			for _, line := range strings.Split(string(cfg), "\n") {
				if strings.HasPrefix(line, "CONFIG_PREEMPT") || strings.HasPrefix(line, "CONFIG_TREE_RCU") {
					t.Logf("P2_KERNEL_CONFIG %s", line)
				}
			}
		}
	}
	dbg := t.TempDir()
	if err := unix.Mount("debugfs", dbg, "debugfs", 0, ""); err == nil {
		t.Cleanup(func() { _ = unix.Unmount(dbg, 0) })
	}
	for _, path := range []string{dbg + "/sched/preempt", "/sys/kernel/debug/sched/preempt"} {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		orig := strings.TrimSpace(string(b))
		t.Logf("P2_PREEMPT_MODE path=%s mode=%q", path, orig)
		if !strings.Contains(orig, "(full)") {
			if err := os.WriteFile(path, []byte("full"), 0600); err != nil {
				t.Logf("P2_PREEMPT_WRITE err=%v", err)
			} else {
				after, _ := os.ReadFile(path)
				t.Logf("P2_PREEMPT_AFTER mode=%q", strings.TrimSpace(string(after)))
				restore := "voluntary"
				if strings.Contains(orig, "(none)") {
					restore = "none"
				}
				p := path
				t.Cleanup(func() { _ = os.WriteFile(p, []byte(restore), 0600) })
			}
		}
		return
	}
}

func TestBridgePreemptedReader(t *testing.T) {
	// Ensure at least 8 Go Ps and quiesce GC during the bounded SCHED_FIFO preemption
	// proof so reader B (blocked in waitEventFD), controller, and holder A never stall
	// waiting for sysmon P retake or GC assist on a 2-vCPU guest.
	oldProcs := runtime.GOMAXPROCS(8)
	t.Cleanup(func() { runtime.GOMAXPROCS(oldProcs) })
	runtime.GC()
	oldGC := debug.SetGCPercent(-1)
	t.Cleanup(func() { debug.SetGCPercent(oldGC) })

	ensureFullPreempt(t)
	preemptRCU := hasKernelConfig(t, "CONFIG_PREEMPT_RCU")
	f := newBridgeFixture(t, true)
	if runtime.NumCPU() < 2 {
		t.Fatal("two CPUs required for independent controller")
	}
	// No packets or reads yet: temporarily disable capture while registering B.
	f.b.config.Enabled = 0
	if err := f.b.Collection.Maps["config"].Update(uint32(0), f.b.config, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	faultsFD := f.b.Collection.Maps["faults"].FD()
	wakeFD := newEventFD(t)
	ready := make(chan error, 1)
	done := make(chan struct{})
	type result struct {
		frames []ReadFrame
		err    error
		ended  uint64
	}
	out := make(chan result, 1)
	go func() {
		defer close(done)
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		var affinity unix.CPUSet
		affinity.Set(f.cpu)
		if err := unix.SchedSetaffinity(0, &affinity); err != nil {
			ready <- err
			return
		}
		r, err := f.b.Register()
		if err != nil {
			ready <- err
			return
		}
		defer func() {
			if err := r.Close(); err != nil {
				t.Error(err)
			}
		}()
		if err := setProofPriority(20); err != nil {
			ready <- err
			return
		}
		defer func() {
			if err := setProofPriority(0); err != nil {
				t.Error(err)
			}
		}()
		if err := verifyProofThread(f.cpu, 20); err != nil {
			ready <- err
			return
		}
		t.Logf("P2_READER ready=true tid=%d cpu=%d policy=FIFO priority=20", unix.Gettid(), f.cpu)
		var state BridgeFault
		var lookupErr error
		frames, readErr := r.readBurst(f.fd, 1, func(fd int, dst []byte) (int, error) {
			ready <- nil
			if err := waitEventFD(wakeFD); err != nil {
				return -1, err
			}
			n, err := unix.Read(fd, dst)
			lookupErr = rawLookupFault(faultsFD, &state)
			releaseHold(f)
			return n, err
		})
		out <- result{frames, errors.Join(readErr, lookupErr), state.Reserved[2]}
	}()
	t.Cleanup(func() {
		_ = signalEventFD(wakeFD)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("reader B did not stop")
		}
	})
	if err := <-ready; err != nil {
		t.Fatal(err)
	}
	if err := f.b.Enable(500); err != nil {
		t.Fatal(err)
	}
	s, _ := bridgeSocket(t, 0)
	cA := bridgeSend(t, s, []byte("reader-A"))
	cB := bridgeSend(t, s, []byte("reader-B"))
	before, err := f.b.Sample()
	if err != nil {
		t.Fatal(err)
	}
	ctl := BridgeFault{Epoch: f.epoch, CPU: uint32(f.cpu), Mode: 8}
	if err := f.b.Collection.Maps["faults"].Update(uint32(0), ctl, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := setProofPriority(10); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := setProofPriority(0); err != nil {
			t.Error(err)
		}
	}()
	if err := verifyProofThread(f.cpu, 10); err != nil {
		t.Fatal(err)
	}
	t.Logf("P2_HOLDER ready=true tid=%d cpu=%d policy=FIFO priority=10", unix.Gettid(), f.cpu)
	controller := readyHoldController(t, f, func() error { return signalEventFD(wakeFD) })
	a, aerr := f.r.ReadBurst(f.fd, 1)
	if err := setProofPriority(0); err != nil {
		t.Fatal(err)
	}
	if err := <-controller; err != nil {
		t.Fatal(err)
	}
	var b result
	select {
	case b = <-out:
	case <-time.After(time.Second):
		t.Fatal("preempting reader did not return")
	}
	<-done // B unregisters before any reload; also joins its cleanup.
	after, err := f.b.Sample()
	if err != nil {
		t.Fatal(err)
	}
	var postState BridgeFault
	_ = f.b.Collection.Maps["faults"].Lookup(uint32(0), &postState)
	if !before[1].Present && verifiedFloor58Profile() {
		// Upstream v5.8 __bpf_trace_run has no per-program recursion guard:
		// either RCU keeps the callback non-preemptible across tasks (b.ended == 1)
		// or B's consume_skb callback runs concurrently without being skipped (b.ended == 0),
		// retiring both packets cleanly and attributing both A and B to their cookies.
		if postState.Hits != 1 || postState.Serial == 0 {
			t.Fatalf("v5.8 holder did not execute bounded hold: hits=%d hold_ns=%d", postState.Hits, postState.Serial)
		}
		if aerr != nil || len(a) != 1 || a[0].Decision.Status != ReadCookie || a[0].Decision.Packet.Cookie != cA {
			t.Fatalf("v5.8 holder A read failed: err=%v frames=%+v", aerr, a)
		}
		if b.err != nil || len(b.frames) != 1 || b.frames[0].Decision.Status != ReadCookie || b.frames[0].Decision.Packet.Cookie != cB {
			t.Fatalf("v5.8 reader B read failed: err=%v frames=%+v", b.err, b.frames)
		}
		t.Logf("P2_PREEMPT floor58=true raw_recursion_guard=false ended=%d hold_ns=%d both_readers_attributed=true", b.ended, postState.Serial)
		reloadBridgeFixture(t, f)
		return
	}
	if !preemptRCU && b.ended == 1 {
		// On kernels without CONFIG_PREEMPT_RCU (e.g. CONFIG_PREEMPT_LAZY=y with TREE_RCU),
		// __bpf_trace_run's rcu_read_lock_dont_migrate() -> __rcu_read_lock() calls
		// preempt_disable(), keeping raw_tracepoint callbacks non-preemptible across tasks
		// even when woken by a higher-priority SCHED_FIFO reader on the same CPU.
		if postState.Hits != 1 || postState.Serial == 0 {
			t.Fatalf("holder did not execute bounded hold: hits=%d hold_ns=%d", postState.Hits, postState.Serial)
		}
		if after[1].Misses != before[1].Misses {
			t.Fatalf("unexpected consume recursion miss on non-preemptible RCU kernel: before=%d after=%d", before[1].Misses, after[1].Misses)
		}
		if aerr != nil || len(a) != 1 || a[0].Decision.Status != ReadCookie || a[0].Decision.Packet.Cookie != cA {
			t.Fatalf("holder A read failed on non-preemptible RCU kernel: err=%v frames=%+v", aerr, a)
		}
		if b.err != nil || len(b.frames) != 1 || b.frames[0].Decision.Status != ReadCookie || b.frames[0].Decision.Packet.Cookie != cB {
			t.Fatalf("reader B read failed on non-preemptible RCU kernel: err=%v frames=%+v", b.err, b.frames)
		}
		t.Logf("P2_PREEMPT preempt_rcu=false rcu_read_lock=preempt_disable hold_ns=%d consume_recursion_delta=0 task_serialized=true", postState.Serial)
		reloadBridgeFixture(t, f)
		return
	}
	if b.ended != 0 {
		t.Fatalf("B did not read while A's callback was active: ended=%d hold_ns=%d misses_before=%d misses_after=%d b_err=%v", b.ended, postState.Serial, before[1].Misses, after[1].Misses, b.err)
	}
	if after[1].Misses <= before[1].Misses {
		t.Fatal("kernel consume recursion counter did not grow", before, after)
	}
	for _, r := range []result{{frames: a, err: aerr}, b} {
		if !errors.Is(r.err, ErrEpochRebuild) || len(r.frames) != 1 || r.frames[0].Decision.Status == ReadCookie {
			t.Fatal("affected burst was not refused", r.err, r.frames)
		}
	}
	if f.b.DeliveredWithoutRecord.Load() == 0 {
		t.Fatal("reader terminal was not actually suppressed")
	}
	var key uint64
	var p PacketRecord
	it := f.b.Collection.Maps["packets"].Iterate()
	if !it.Next(&key, &p) {
		t.Fatal("skipped terminal did not leave a record", it.Err())
	}
	t.Logf("P2_PREEMPT consume_recursion_delta=%d missing_reads=%d retained_record=true affected_bursts=unknown", after[1].Misses-before[1].Misses, f.b.DeliveredWithoutRecord.Load())
	reloadBridgeFixture(t, f)
}

func triggerNestedFreeHold(t *testing.T, f *bridgeFixture, s int, beforeDrops uint64, before [3]CounterSample) (BridgeFault, [3]CounterSample, uint64) {
	t.Helper()
	runtime.GC()
	oldGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(oldGC)

	l, err := netlink.LinkByName("nsbridge0")
	if err != nil || l.Attrs().Statistics == nil {
		t.Fatal(err)
	}
	q := netlink.NewNetem(netlink.QdiscAttrs{LinkIndex: l.Attrs().Index, Handle: netlink.MakeHandle(1, 0), Parent: netlink.HANDLE_ROOT}, netlink.NetemQdiscAttrs{Latency: 2000, Limit: 100})
	if err := netlink.QdiscReplace(q); err != nil {
		t.Fatal("netem positive-control prerequisite", err)
	}
	ctl := BridgeFault{Epoch: f.epoch, CPU: uint32(f.cpu), Mode: 16}
	if err := f.b.Collection.Maps["faults"].Update(uint32(0), ctl, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	faultBuf, err := unix.Mmap(-1, 0, unix.Getpagesize(), unix.PROT_NONE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Munmap(faultBuf) }()

	// Arm netem's HRTIMER_MODE_ABS_PINNED watchdog on f.cpu (Latency=2000us=2ms)
	// inside readBurst's callback (after the 64KiB buffer allocation has already completed)
	// immediately before entering the kfree_skb hold (~13.5ms-20ms) on f.cpu. Even when
	// preemption is disabled on f.cpu, the hrtimer hardirq fires on f.cpu and
	// runs NET_TX_SOFTIRQ on irq_exit in the interrupted reader task's context.
	called := false
	var sendErr error
	_, readErr := f.r.readBurst(f.fd, 1, func(fd int, _ []byte) (int, error) {
		atomic.StoreUint64(&f.r.slot.Control.Armed, 0)
		for range 8 {
			if err := unix.Sendto(s, []byte("timer-drop"), 0, &unix.SockaddrInet4{Addr: [4]byte{198, 18, 0, 2}, Port: 9000}); err != nil {
				sendErr = err
				return -1, err
			}
		}
		atomic.StoreUint64(&f.r.slot.Control.Armed, 1)
		called = true
		return unix.Read(fd, faultBuf[:64])
	})
	if sendErr != nil {
		t.Fatal(sendErr)
	}
	if !errors.Is(readErr, unix.EFAULT) || !errors.Is(readErr, ErrEpochRebuild) {
		t.Fatalf("copy-fault precondition: syscall_entered=%t health=%d: %v", called, f.b.Faults(), readErr)
	}
	if err := f.b.Collection.Maps["faults"].Lookup(uint32(0), &ctl); err != nil {
		t.Fatal(err)
	}
	after, err := f.b.Sample()
	if err != nil {
		t.Fatal(err)
	}
	l, err = netlink.LinkByName("nsbridge0")
	if err != nil || l.Attrs().Statistics == nil {
		t.Fatal(err)
	}
	drops := l.Attrs().Statistics.TxDropped - beforeDrops
	floor58 := !before[2].Present && verifiedFloor58Profile()
	if ctl.Hits != 1 || ctl.Address == 0 || drops == 0 || (!floor58 && after[2].Misses <= before[2].Misses) {
		t.Fatalf("nested skip not exercised: hold=%d hold_ns=%d observed_same_task=%d kernel_drops=%d free_before=%d free_after=%d floor58=%t", ctl.Hits, ctl.Serial, ctl.Address, drops, before[2].Misses, after[2].Misses, floor58)
	}
	return ctl, after, drops
}

func TestBridgeNestedFreeSkip(t *testing.T) {
	// IFF_VNET_HDR ensures tun_put_user checks copy_to_iter's -EFAULT return
	// and routes the dequeued skb to kfree_skb(skb) in task context.
	f := newBridgeFixture(t, true, unix.IFF_VNET_HDR)
	if runtime.NumCPU() < 2 {
		t.Fatal("two CPUs required for ready nested-free stimulus")
	}
	assertHealthy := func(stage string) {
		f.b.mu.Lock()
		stopped := f.b.stopped
		f.b.mu.Unlock()
		health := f.b.Faults()
		var reasons [8]uint64
		if err := f.b.Collection.Maps["health"].Lookup(uint32(0), &reasons); err != nil {
			t.Fatal(err)
		}
		t.Logf("P2_STAGE epoch=%d stage=%s health=%d stopped=%t fault_reasons_capture_existing_update_delete_stamp=%v", f.epoch, stage, health, stopped, reasons[3:])
		if health != 0 || stopped {
			t.Fatalf("nested-free starting condition failed at %s; no reset performed", stage)
		}
	}
	assertHealthy("fresh")
	s, _ := bridgeSocket(t, 0)
	for range 500 {
		bridgeSend(t, s, []byte("fill-ring"))
	}
	// Independently count map entries before creating the timing stimulus.
	var key uint64
	var packet PacketRecord
	occupied := 0
	it := f.b.Collection.Maps["packets"].Iterate()
	for it.Next(&key, &packet) {
		occupied++
	}
	if err := it.Err(); err != nil || occupied != 500 {
		t.Fatal("full ring precondition", occupied, err)
	}
	assertHealthy("ring-filled")
	l, err := netlink.LinkByName("nsbridge0")
	if err != nil || l.Attrs().Statistics == nil {
		t.Fatal(err)
	}
	beforeDrops := l.Attrs().Statistics.TxDropped
	before, err := f.b.Sample()
	if err != nil {
		t.Fatal(err)
	}
	ctl, after, drops := triggerNestedFreeHold(t, f, s, beforeDrops, before)
	if !before[2].Present && verifiedFloor58Profile() {
		t.Logf("P2_NESTED_FREE floor58=true raw_recursion_guard=false full_ring_before=%d nested_same_task=%d kernel_drops=%d reload_required=true", occupied, ctl.Address, drops)
		reloadBridgeFixture(t, f)
		return
	}
	if f.b.UnknownRecursion.Load() != 1 {
		t.Fatal("recursion event not classified exactly once")
	}
	t.Logf("P2_NESTED_FREE full_ring_before=%d nested_same_task=%d kernel_drops=%d free_recursion_delta=%d reload_required=true", occupied, ctl.Address, drops, after[2].Misses-before[2].Misses)
	reloadBridgeFixture(t, f)
}

func TestBridgeStaleRecordMutation(t *testing.T) {
	if runtime.NumCPU() < 2 {
		t.Fatal("two CPUs required for ready recursion stimulus")
	}
	for _, skipPostCheck := range []bool{false, true} {
		t.Run(fmt.Sprintf("skip_post_check=%t", skipPostCheck), func(t *testing.T) {
			f := newBridgeFixture(t, true, unix.IFF_VNET_HDR)
			s1, _ := bridgeSocket(t, 0)
			s2, _ := bridgeSocket(t, 0)

			// Register a second reader r2 on its own OS thread while capture is temporarily
			// quiesced BEFORE any traffic on the interface so r2's baseline is sampled
			// before the kernel recursion skip and the 500-packet ring fill is undisturbed.
			f.b.config.Enabled = 0
			if err := f.b.Collection.Maps["config"].Update(uint32(0), f.b.config, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			type r2Result struct {
				frames []ReadFrame
				err    error
			}
			r2Ready := make(chan error, 1)
			r2Trigger := make(chan bool, 1)
			r2Out := make(chan r2Result, 1)
			r2Done := make(chan struct{})
			go func() {
				defer close(r2Done)
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				var mask unix.CPUSet
				mask.Set(f.cpu)
				if err := unix.SchedSetaffinity(0, &mask); err != nil {
					r2Ready <- err
					return
				}
				r2, err := f.b.Register()
				if err != nil {
					r2Ready <- err
					return
				}
				defer func() { _ = r2.Close() }()
				r2.SkipPostCheck = skipPostCheck
				r2Ready <- nil
				doRead := <-r2Trigger
				if !doRead {
					return
				}
				frames, readErr := r2.ReadBurst(f.fd, 1)
				r2Out <- r2Result{frames, readErr}
			}()
			t.Cleanup(func() {
				select {
				case r2Trigger <- false:
				default:
				}
				<-r2Done
			})
			if err := <-r2Ready; err != nil {
				t.Fatal(err)
			}
			if err := f.b.Enable(500); err != nil {
				t.Fatal(err)
			}

			// Step 1: Fill the ring with 500 packets from s1 (cookie c1) and trigger
			// a real kernel kfree_skb recursion stimulus using f.r.
			var c1 uint64
			for range 500 {
				c1 = bridgeSend(t, s1, []byte("fixed-size"))
			}
			var beforeMapKeys = make(map[uint64]PacketRecord)
			var k uint64
			var v PacketRecord
			it := f.b.Collection.Maps["packets"].Iterate()
			for it.Next(&k, &v) {
				beforeMapKeys[k] = v
			}
			if err := it.Err(); err != nil || len(beforeMapKeys) != 500 {
				t.Fatal("full ring precondition", len(beforeMapKeys), err)
			}
			l, err := netlink.LinkByName("nsbridge0")
			if err != nil || l.Attrs().Statistics == nil {
				t.Fatal(err)
			}
			beforeDrops := l.Attrs().Statistics.TxDropped
			before, err := f.b.Sample()
			if err != nil {
				t.Fatal(err)
			}
			_, afterHold, _ := triggerNestedFreeHold(t, f, s1, beforeDrops, before)

			buf := make([]byte, 2048)
			for range 499 {
				if _, err := unix.Read(f.fd, buf); err != nil {
					t.Fatal("drain ring after nested free:", err)
				}
			}
			// On 6.1+ kernels, entries still in packets now are the exact skb addresses whose
			// kfree_skb callback was suppressed by the kernel's raw_tracepoint recursion guard.
			// On upstream v5.8 (rawRecursionGuard=false), nested kfree_skb runs without suppression
			// so all 8 dropped records are deleted by freed() and retainedAddrs is empty!
			var retainedAddrs []uint64
			it = f.b.Collection.Maps["packets"].Iterate()
			for it.Next(&k, &v) {
				if v.Cookie != c1 {
					t.Fatalf("unexpected retained cookie: got %d want %d", v.Cookie, c1)
				}
				retainedAddrs = append(retainedAddrs, k)
			}
			if err := it.Err(); err != nil {
				t.Fatal(err)
			}
			if !before[2].Present && verifiedFloor58Profile() {
				if len(retainedAddrs) != 0 {
					t.Fatalf("v5.8 guard-free raw tracepoint unexpectedly left %d unretired records", len(retainedAddrs))
				}
				_ = netlink.QdiscDel(netlink.NewNetem(netlink.QdiscAttrs{LinkIndex: l.Attrs().Index, Handle: netlink.MakeHandle(1, 0), Parent: netlink.HANDLE_ROOT}, netlink.NetemQdiscAttrs{}))
				r2Trigger <- false
				<-r2Done
				t.Logf("P2_STALE_MUTATION floor58=true raw_recursion_guard=false skip_post_check=%t nested_frees_retired_all=true retained_records=0", skipPostCheck)
				reloadBridgeFixture(t, f)
				return
			}
			if len(retainedAddrs) == 0 {
				t.Fatalf("kernel recursion skip did not leave retained stale records: len=%d", len(retainedAddrs))
			}
			for _, addr := range retainedAddrs {
				if err := f.b.Collection.Maps["packets"].Delete(addr); err != nil {
					t.Fatal(err)
				}
			}
			_ = netlink.QdiscDel(netlink.NewNetem(netlink.QdiscAttrs{LinkIndex: l.Attrs().Index, Handle: netlink.MakeHandle(1, 0), Parent: netlink.HANDLE_ROOT}, netlink.NetemQdiscAttrs{}))

			// Step 2: Find the top-of-freelist recurring skb address on f.cpu using s1
			// and retain its genuine captured PacketRecord (cookie c1) while the real
			// kernel freed recursion_misses counter remains elevated above r2's baseline.
			seen := map[uint64]PacketRecord{}
			var targetAddr uint64
			deadline := time.Now().Add(10 * time.Second)
			for i := 0; i < 100000 && time.Now().Before(deadline); i++ {
				got := bridgeSend(t, s1, []byte("fixed-size"))
				if got != c1 {
					t.Fatal("s1 cookie changed", got, c1)
				}
				var states []CPUState
				if err := f.b.Collection.Maps["cpu_state"].Lookup(uint32(0), &states); err != nil {
					t.Fatal(err)
				}
				st := states[f.cpu]
				var rec PacketRecord
				if err := f.b.Collection.Maps["packets"].Lookup(st.Address, &rec); err != nil || rec.Cookie != c1 {
					t.Fatal("packet record missing before raw read", err, rec)
				}
				if _, err := unix.Read(f.fd, buf); err != nil {
					t.Fatal(err)
				}
				if oldRec, ok := seen[st.Address]; ok {
					targetAddr = st.Address
					if err := f.b.Collection.Maps["packets"].Update(targetAddr, oldRec, ebpf.UpdateNoExist); err != nil {
						t.Fatal("retain stale record at recurring address:", err)
					}
					break
				}
				seen[st.Address] = rec
			}
			if targetAddr == 0 {
				t.Fatal("pointer reuse not observed before mutation check")
			}

			// Clear b.stopped so r2 reaches the post-burst counter certification gate instead
			// of being rejected at the pre-read b.stopped check.
			f.b.mu.Lock()
			f.b.stopped = false
			f.b.mu.Unlock()

			// Step 3: Arm one-shot capture skip at targetAddr so Y (sent on s2 with cookie c2)
			// reuses targetAddr without updating or faulting the retained entry from X (cookie c1).
			skipCtl := BridgeFault{Epoch: f.epoch, CPU: uint32(f.cpu), Mode: 1, Address: targetAddr}
			if err := f.b.Collection.Maps["faults"].Update(uint32(0), skipCtl, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			var c2 uint64
			recurred := false
			for j := 0; j < 100000 && time.Now().Before(deadline); j++ {
				got := bridgeSend(t, s2, []byte("fixed-size"))
				if c2 == 0 {
					c2 = got
					if c1 == c2 {
						t.Fatal("distinct socket cookies required", c1, c2)
					}
				} else if got != c2 {
					t.Fatal("s2 cookie changed", got, c2)
				}
				if err := f.b.Collection.Maps["faults"].Lookup(uint32(0), &skipCtl); err != nil {
					t.Fatal(err)
				}
				if skipCtl.Hits != 0 {
					var observed []CPUState
					if err := f.b.Collection.Maps["cpu_state"].Lookup(uint32(0), &observed); err != nil {
						t.Fatal(err)
					}
					if observed[f.cpu].Address != targetAddr {
						t.Fatal("suppression hit without independently observed pointer recurrence")
					}
					r2Trigger <- true
					res := <-r2Out
					<-r2Done
					frames, readErr := res.frames, res.err
					if len(frames) != 1 {
						t.Fatalf("expected 1 frame, got %d (err=%v)", len(frames), readErr)
					}
					if !skipPostCheck {
						if !errors.Is(readErr, ErrEpochRebuild) || frames[0].Decision.Status != "attribution_unknown_recursion" {
							t.Fatalf("normal reader accepted stale record or wrong status: err=%v decision=%+v", readErr, frames[0].Decision)
						}
						t.Logf("P2_STALE_MUTATION skip_post_check=false address=%x stale_cookie=%d sender_cookie=%d free_recursion_delta=%d decision=%s result=refused", targetAddr, c1, c2, afterHold[2].Misses-before[2].Misses, frames[0].Decision.Status)
						reloadBridgeFixture(t, f)
					} else {
						if readErr != nil || frames[0].Decision.Status != ReadCookie || frames[0].Decision.Packet.Cookie != c1 {
							t.Fatalf("mutant reader without post-burst check did not accept stale record: err=%v decision=%+v want_cookie=%d", readErr, frames[0].Decision, c1)
						}
						t.Logf("P2_STALE_MUTATION skip_post_check=true address=%x stale_cookie=%d sender_cookie=%d accepted_cookie=%d free_recursion_delta=%d result=stale_accepted", targetAddr, c1, c2, frames[0].Decision.Packet.Cookie, afterHold[2].Misses-before[2].Misses)
					}
					recurred = true
					break
				}
				if _, err := unix.Read(f.fd, buf); err != nil {
					t.Fatal("raw read while waiting for recurrence:", err)
				}
			}
			if !recurred {
				t.Fatal("target address did not recur for stale-record mutation proof")
			}
		})
	}
}


