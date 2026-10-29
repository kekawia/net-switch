//go:build linux && ownerbpfproof && (amd64 || arm64)

package ownerbpf

import (
	"errors"
	"fmt"
	"runtime"
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

func releaseHold(f *bridgeFixture) {
	var state BridgeFault
	if err := f.b.Collection.Maps["faults"].Lookup(uint32(0), &state); err == nil && state.Reserved[0] != 0 && state.Reserved[2] == 0 {
		state.Reserved[1] = 1
		_ = f.b.Collection.Maps["faults"].Update(uint32(0), state, ebpf.UpdateAny)
	}
}

// Complete controller setup before the holder can enter the bounded BPF
// window. Starting a goroutine is not evidence it has run, pinned, or polled.
func readyHoldController(t *testing.T, f *bridgeFixture, trigger func() error) <-chan error {
	t.Helper()
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
		for time.Now().Before(deadline) {
			select {
			case <-cancel:
				return
			default:
			}
			var active BridgeFault
			if err := f.b.Collection.Maps["faults"].Lookup(uint32(0), &active); err != nil {
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

func TestBridgePreemptedReader(t *testing.T) {
	f := newBridgeFixture(t, true)
	if runtime.NumCPU() < 2 {
		t.Fatal("two CPUs required for independent controller")
	}
	// No packets or reads yet: temporarily disable capture while registering B.
	f.b.config.Enabled = 0
	if err := f.b.Collection.Maps["config"].Update(uint32(0), f.b.config, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
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
		ready <- nil
		if err := waitEventFD(wakeFD); err != nil {
			out <- result{err: err}
			return
		}
		frames, readErr := r.ReadBurst(f.fd, 1)
		var state BridgeFault
		lookupErr := f.b.Collection.Maps["faults"].Lookup(uint32(0), &state)
		ended := state.Reserved[2]
		releaseHold(f)
		out <- result{frames, errors.Join(readErr, lookupErr), ended}
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
	bridgeSend(t, s, []byte("reader-A"))
	bridgeSend(t, s, []byte("reader-B"))
	before, err := f.b.Sample()
	if err != nil {
		t.Fatal(err)
	}
	ctl := BridgeFault{Epoch: f.epoch, CPU: uint32(f.cpu), Mode: 8}
	if err := f.b.Collection.Maps["faults"].Update(uint32(0), ctl, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	controller := readyHoldController(t, f, func() error { return signalEventFD(wakeFD) })
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
	// immediately before entering the 20ms kfree_skb hold on f.cpu. Even when
	// preemption is disabled on f.cpu, the hrtimer hardirq fires on f.cpu and
	// runs NET_TX_SOFTIRQ on irq_exit in the interrupted reader task's context.
	for range 8 {
		if err := unix.Sendto(s, []byte("timer-drop"), 0, &unix.SockaddrInet4{Addr: [4]byte{198, 18, 0, 2}, Port: 9000}); err != nil {
			t.Fatal(err)
		}
	}
	called := false
	_, readErr := f.r.readBurst(f.fd, 1, func(fd int, _ []byte) (int, error) {
		called = true
		return unix.Read(fd, faultBuf[:64])
	})
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
	if ctl.Hits != 1 || ctl.Address == 0 || drops == 0 || after[2].Misses <= before[2].Misses {
		t.Fatalf("nested skip not exercised: hold=%d hold_ns=%d observed_same_task=%d kernel_drops=%d free_before=%d free_after=%d", ctl.Hits, ctl.Serial, ctl.Address, drops, before[2].Misses, after[2].Misses)
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
			c1 := bridgeSend(t, s1, []byte("init-1"))
			if fr := bridgeRead(t, f, 1)[0]; fr.Decision.Status != ReadCookie || fr.Decision.Packet.Cookie != c1 {
				t.Fatal("init-1 failed", fr.Decision)
			}
			c2 := bridgeSend(t, s2, []byte("init-2"))
			if fr := bridgeRead(t, f, 1)[0]; fr.Decision.Status != ReadCookie || fr.Decision.Packet.Cookie != c2 {
				t.Fatal("init-2 failed", fr.Decision)
			}
			if c1 == c2 {
				t.Fatal("distinct socket cookies required", c1, c2)
			}

			// Register a second reader r2 while capture is temporarily quiesced so r2's
			// baseline is sampled BEFORE the kernel recursion skip, then use f.r to
			// trigger the real nested-free kernel recursion skip.
			f.b.config.Enabled = 0
			if err := f.b.Collection.Maps["config"].Update(uint32(0), f.b.config, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			r2, err := f.b.Register()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if r2 != nil {
					_ = r2.Close()
				}
			})
			r2.SkipPostCheck = skipPostCheck
			if err := f.b.Enable(500); err != nil {
				t.Fatal(err)
			}

			// Step 1: Fill the ring with 500 packets from s1 (cookie c1) and trigger
			// a real kernel kfree_skb recursion skip using f.r. The 8 dropped packets
			// have their kfree_skb terminal suppressed by the kernel recursion guard,
			// so their stale records (cookie c1) remain in the kernel packet map AND
			// freed recursion_misses increments above r2's baseline!
			for range 500 {
				bridgeSend(t, s1, []byte("fixed-size"))
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

			// Remove netem qdisc by replacing with pfifo_fast / noqueue via link cycling or draining,
			// and drain the remaining 499 queued packets from the ring using raw unix.Read.
			// First reset f.b.stopped (which f.r's EFAULT read set) ONLY so r2 can enter ReadBurst
			// to test the post-burst counter gate directly.
			buf := make([]byte, 2048)
			for range 499 {
				if _, err := unix.Read(f.fd, buf); err != nil {
					t.Fatal("drain ring after nested free:", err)
				}
			}
			// Any entries still in packets now are the exact skb addresses whose kfree_skb
			// callback was suppressed by the kernel's raw_tracepoint recursion guard!
			var retainedAddrs []uint64
			it = f.b.Collection.Maps["packets"].Iterate()
			for it.Next(&k, &v) {
				if v.Cookie != c1 {
					t.Fatalf("unexpected retained cookie: got %d want %d", v.Cookie, c1)
				}
				retainedAddrs = append(retainedAddrs, k)
			}
			if err := it.Err(); err != nil || len(retainedAddrs) == 0 {
				t.Fatalf("kernel recursion skip did not leave retained stale records: len=%d err=%v", len(retainedAddrs), err)
			}
			targetAddr := retainedAddrs[0]
			// Delete the other retained records so only targetAddr remains armed for recurrence.
			for _, addr := range retainedAddrs[1:] {
				if err := f.b.Collection.Maps["packets"].Delete(addr); err != nil {
					t.Fatal(err)
				}
			}
			_ = netlink.QdiscDel(netlink.NewNetem(netlink.QdiscAttrs{LinkIndex: l.Attrs().Index, Handle: netlink.MakeHandle(1, 0), Parent: netlink.HANDLE_ROOT}, netlink.NetemQdiscAttrs{}))

			// Clear b.stopped so r2 reaches the post-burst counter certification gate instead
			// of being rejected at the pre-read b.stopped check.
			f.b.mu.Lock()
			f.b.stopped = false
			f.b.mu.Unlock()

			// Step 2: Arm one-shot capture skip at targetAddr so Y (sent on s2 with cookie c2)
			// reuses targetAddr without updating or faulting the retained entry from X (cookie c1).
			skipCtl := BridgeFault{Epoch: f.epoch, CPU: uint32(f.cpu), Mode: 1, Address: targetAddr}
			if err := f.b.Collection.Maps["faults"].Update(uint32(0), skipCtl, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(10 * time.Second)
			recurred := false
			for j := 0; j < 100000 && time.Now().Before(deadline); j++ {
				if got := bridgeSend(t, s2, []byte("fixed-size")); got != c2 {
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
					frames, readErr := r2.ReadBurst(f.fd, 1)
					if len(frames) != 1 {
						t.Fatalf("expected 1 frame, got %d (err=%v)", len(frames), readErr)
					}
					if !skipPostCheck {
						if !errors.Is(readErr, ErrEpochRebuild) || frames[0].Decision.Status != "attribution_unknown_recursion" {
							t.Fatalf("normal reader accepted stale record or wrong status: err=%v decision=%+v", readErr, frames[0].Decision)
						}
						t.Logf("P2_STALE_MUTATION skip_post_check=false address=%x stale_cookie=%d sender_cookie=%d free_recursion_delta=%d decision=%s result=refused", targetAddr, c1, c2, afterHold[2].Misses-before[2].Misses, frames[0].Decision.Status)
						_ = r2.Close()
						r2 = nil
						reloadBridgeFixture(t, f)
					} else {
						if readErr != nil || frames[0].Decision.Status != ReadCookie || frames[0].Decision.Packet.Cookie != c1 {
							t.Fatalf("mutant reader without post-burst check did not accept stale record: err=%v decision=%+v want_cookie=%d", readErr, frames[0].Decision, c1)
						}
						t.Logf("P2_STALE_MUTATION skip_post_check=true address=%x stale_cookie=%d sender_cookie=%d accepted_cookie=%d free_recursion_delta=%d result=stale_accepted", targetAddr, c1, c2, frames[0].Decision.Packet.Cookie, afterHold[2].Misses-before[2].Misses)
						_ = r2.Close()
						r2 = nil
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


