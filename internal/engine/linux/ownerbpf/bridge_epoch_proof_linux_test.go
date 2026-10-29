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

// Complete controller setup before the holder can enter the bounded BPF
// window. Starting a goroutine is not evidence it has run, pinned, or polled.
func readyHoldController(t *testing.T, f *bridgeFixture, trigger func()) <-chan error {
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
				trigger()
				result <- nil
				// Park here to hand the Go execution token to the waiting
				// actor. Restoring affinity now could move this controller
				// behind the held FIFO task before that handoff completed.
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
	ready := make(chan error, 1)
	start := make(chan struct{})
	cancel := make(chan struct{})
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
		select {
		case <-start:
		case <-cancel:
			return
		}
		frames, readErr := r.ReadBurst(f.fd, 1)
		var state BridgeFault
		lookupErr := f.b.Collection.Maps["faults"].Lookup(uint32(0), &state)
		out <- result{frames, errors.Join(readErr, lookupErr), state.Reserved[2]}
	}()
	t.Cleanup(func() {
		close(cancel)
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
	controller := readyHoldController(t, f, func() { close(start) })
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
	if b.ended != 0 {
		t.Fatal("B did not read while A's callback was active")
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

func TestBridgeNestedFreeSkip(t *testing.T) {
	f := newBridgeFixture(t, true)
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
	q := netlink.NewNetem(netlink.QdiscAttrs{LinkIndex: l.Attrs().Index, Handle: netlink.MakeHandle(1, 0), Parent: netlink.HANDLE_ROOT}, netlink.NetemQdiscAttrs{Latency: 100, Limit: 100})
	if err := netlink.QdiscReplace(q); err != nil {
		t.Fatal("netem positive-control prerequisite", err)
	}
	assertHealthy("qdisc-installed")
	before, err := f.b.Sample()
	if err != nil {
		t.Fatal(err)
	}
	ctl := BridgeFault{Epoch: f.epoch, CPU: uint32(f.cpu), Mode: 16}
	if err := f.b.Collection.Maps["faults"].Update(uint32(0), ctl, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	ready := make(chan error, 1)
	start := make(chan struct{})
	cancel := make(chan struct{})
	sent := make(chan error, 1)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		var old unix.CPUSet
		if err := unix.SchedGetaffinity(0, &old); err != nil {
			ready <- err
			return
		}
		var mask unix.CPUSet
		mask.Set(f.cpu)
		if err := unix.SchedSetaffinity(0, &mask); err != nil {
			ready <- err
			return
		}
		defer func() {
			if err := unix.SchedSetaffinity(0, &old); err != nil {
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
		t.Logf("P2_SENDER ready=true tid=%d cpu=%d policy=FIFO priority=20", unix.Gettid(), f.cpu)
		ready <- nil
		select {
		case <-start:
		case <-cancel:
			return
		}
		for range 8 {
			if err := unix.Sendto(s, []byte("timer-drop"), 0, &unix.SockaddrInet4{Addr: [4]byte{198, 18, 0, 2}, Port: 9000}); err != nil {
				sent <- err
				return
			}
		}
		sent <- nil
		// Park the higher-priority sender so the held FIFO-10 task resumes
		// before the queued timer traffic arrives on this same CPU.
		<-cancel
	}()
	t.Cleanup(func() { close(cancel); <-joined })
	if err := <-ready; err != nil {
		t.Fatal(err)
	}
	controller := readyHoldController(t, f, func() { close(start) })
	assertHealthy("stimulus-ready")
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
	// A real copy fault frees the reader's packet in task context. The netem
	// timer must interrupt that held free callback and drop from the full ring.
	called := false
	_, readErr := f.r.readBurst(f.fd, 1, func(fd int, _ []byte) (int, error) {
		called = true
		_, _, errno := unix.Syscall(unix.SYS_READ, uintptr(fd), 1, 64)
		if errno == 0 {
			return 0, errors.New("invalid destination did not fault")
		}
		return -1, errno
	})
	if err := setProofPriority(0); err != nil {
		t.Fatal(err)
	}
	if err := <-controller; err != nil {
		var reasons [8]uint64
		lookupErr := f.b.Collection.Maps["health"].Lookup(uint32(0), &reasons)
		t.Fatalf("nested-free stimulus: syscall_entered=%t health=%d reasons=%v lookup=%v: %v", called, f.b.Faults(), reasons[3:], lookupErr, err)
	}
	select {
	case err := <-sent:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("ready sender did not finish")
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
	if ctl.Hits != 1 || ctl.Address == 0 || drops == 0 || after[2].Misses <= before[2].Misses {
		t.Fatalf("nested skip not exercised: hold=%d observed_same_task=%d kernel_drops=%d free_before=%d free_after=%d", ctl.Hits, ctl.Address, drops, before[2].Misses, after[2].Misses)
	}
	if f.b.UnknownRecursion.Load() != 1 {
		t.Fatal("recursion event not classified exactly once")
	}
	t.Logf("P2_NESTED_FREE full_ring_before=%d nested_same_task=%d kernel_drops=%d free_recursion_delta=%d reload_required=true", occupied, ctl.Address, drops, after[2].Misses-before[2].Misses)
	reloadBridgeFixture(t, f)
}

func TestBridgeStaleRecordMutation(t *testing.T) {
	if runtime.NumCPU() < 2 {
		t.Fatal("two CPUs required for ready capture-recursion stimulus")
	}
	for _, skipPostCheck := range []bool{false, true} {
		t.Run(fmt.Sprintf("skip_post_check=%t", skipPostCheck), func(t *testing.T) {
			f := newBridgeFixture(t, true)
			f.r.SkipPostCheck = skipPostCheck
			s1, _ := bridgeSocket(t, 0)
			s2, _ := bridgeSocket(t, 0)
			s3, _ := bridgeSocket(t, 0)
			// Establish socket cookies via one normal ping-pong on each socket.
			c1 := bridgeSend(t, s1, []byte("init-1"))
			if fr := bridgeRead(t, f, 1)[0]; fr.Decision.Status != ReadCookie || fr.Decision.Packet.Cookie != c1 {
				t.Fatal("init-1 failed", fr.Decision)
			}
			c2 := bridgeSend(t, s2, []byte("init-2"))
			if fr := bridgeRead(t, f, 1)[0]; fr.Decision.Status != ReadCookie || fr.Decision.Packet.Cookie != c2 {
				t.Fatal("init-2 failed", fr.Decision)
			}
			c3 := bridgeSend(t, s3, []byte("init-3"))
			if fr := bridgeRead(t, f, 1)[0]; fr.Decision.Status != ReadCookie || fr.Decision.Packet.Cookie != c3 {
				t.Fatal("init-3 failed", fr.Decision)
			}
			if c1 == c2 || c1 == c3 || c2 == c3 {
				t.Fatal("distinct socket cookies required", c1, c2, c3)
			}

			// Step 1: Trigger a real kernel capture recursion skip on this epoch so
			// capture recursion_misses > f.r's baseline while health remains 0.
			before, err := f.b.Sample()
			if err != nil {
				t.Fatal(err)
			}
			ctl := BridgeFault{Epoch: f.epoch, CPU: uint32(f.cpu), Mode: 32}
			if err := f.b.Collection.Maps["faults"].Update(uint32(0), ctl, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			ready := make(chan error, 1)
			start := make(chan struct{})
			cancel := make(chan struct{})
			preempted := make(chan error, 1)
			joined := make(chan struct{})
			go func() {
				defer close(joined)
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				var old unix.CPUSet
				if err := unix.SchedGetaffinity(0, &old); err != nil {
					ready <- err
					return
				}
				var mask unix.CPUSet
				mask.Set(f.cpu)
				if err := unix.SchedSetaffinity(0, &mask); err != nil {
					ready <- err
					return
				}
				defer func() {
					if err := unix.SchedSetaffinity(0, &old); err != nil {
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
				ready <- nil
				select {
				case <-start:
				case <-cancel:
					return
				}
				// Send while the FIFO-10 holder is inside capture on the same CPU.
				// The kernel raw-tracepoint recursion guard suppresses this capture
				// and increments capture recursion_misses.
				preempted <- unix.Sendto(s3, []byte("preempt-xmit"), 0, &unix.SockaddrInet4{Addr: [4]byte{198, 18, 0, 2}, Port: 9000})
				<-cancel
			}()
			t.Cleanup(func() { close(cancel); <-joined })
			if err := <-ready; err != nil {
				t.Fatal(err)
			}
			controller := readyHoldController(t, f, func() { close(start) })
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
			if err := unix.Sendto(s3, []byte("holder-xmit"), 0, &unix.SockaddrInet4{Addr: [4]byte{198, 18, 0, 2}, Port: 9000}); err != nil {
				t.Fatal(err)
			}
			if err := setProofPriority(0); err != nil {
				t.Fatal(err)
			}
			if err := <-controller; err != nil {
				t.Fatal("capture recursion controller:", err)
			}
			if err := <-preempted; err != nil {
				t.Fatal("preempting sender:", err)
			}
			afterHold, err := f.b.Sample()
			if err != nil {
				t.Fatal(err)
			}
			if afterHold[0].Misses <= before[0].Misses {
				t.Fatalf("kernel capture recursion counter did not grow: before=%+v after=%+v", before[0], afterHold[0])
			}
			// Drain the two stimulus packets directly from the TUN fd without advancing f.r's guard.
			for range 2 {
				buf := make([]byte, 2048)
				if _, err := unix.Read(f.fd, buf); err != nil {
					t.Fatal("drain stimulus packet:", err)
				}
			}
			if f.b.Faults() != 0 {
				t.Fatal("unexpected health fault during capture hold", f.b.Faults())
			}

			// Step 2: Discover a reusable skb pointer address via ping-pong on s1
			// (using raw unix.Read so f.r's baseline stays before the capture skip).
			seen := map[uint64]uint64{}
			var targetAddr uint64
			var staleRecord PacketRecord
			deadline := time.Now().Add(10 * time.Second)
			for i := 0; i < 100000 && time.Now().Before(deadline); i++ {
				if got := bridgeSend(t, s1, []byte("fixed-size")); got != c1 {
					t.Fatal("cookie changed", got, c1)
				}
				var states []CPUState
				if err := f.b.Collection.Maps["cpu_state"].Lookup(uint32(0), &states); err != nil {
					t.Fatal(err)
				}
				st := states[f.cpu]
				var rec PacketRecord
				if err := f.b.Collection.Maps["packets"].Lookup(st.Address, &rec); err != nil || rec.Cookie != c1 {
					t.Fatal("packet record missing before read", err, rec)
				}
				buf := make([]byte, 2048)
				if _, err := unix.Read(f.fd, buf); err != nil {
					t.Fatal("seed raw read failed", err)
				}
				if _, ok := seen[st.Address]; ok {
					targetAddr = st.Address
					staleRecord = rec
					break
				}
				seen[st.Address] = st.SeenSerial
			}
			if targetAddr == 0 {
				t.Fatal("pointer reuse not observed within 10s/100000 iterations")
			}

			// Step 3: Retain staleRecord (cookie c1) at targetAddr in the kernel packet map
			// and arm one-shot capture skip at targetAddr so Y (sent on s2 with cookie c2)
			// reuses targetAddr without updating or faulting the retained entry.
			if err := f.b.Collection.Maps["packets"].Update(targetAddr, staleRecord, ebpf.UpdateNoExist); err != nil {
				t.Fatal("failed to insert retained stale record", err)
			}
			skipCtl := BridgeFault{Epoch: f.epoch, CPU: uint32(f.cpu), Mode: 1, Address: targetAddr}
			if err := f.b.Collection.Maps["faults"].Update(uint32(0), skipCtl, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
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
					frames, readErr := f.r.ReadBurst(f.fd, 1)
					if len(frames) != 1 {
						t.Fatalf("expected 1 frame, got %d (err=%v)", len(frames), readErr)
					}
					if !skipPostCheck {
						if !errors.Is(readErr, ErrEpochRebuild) || frames[0].Decision.Status != "attribution_unknown_recursion" {
							t.Fatalf("normal reader accepted stale record or wrong status: err=%v decision=%+v", readErr, frames[0].Decision)
						}
						t.Logf("P2_STALE_MUTATION skip_post_check=false address=%x stale_cookie=%d sender_cookie=%d capture_recursion_delta=%d decision=%s result=refused", targetAddr, c1, c2, afterHold[0].Misses-before[0].Misses, frames[0].Decision.Status)
						reloadBridgeFixture(t, f)
					} else {
						if readErr != nil || frames[0].Decision.Status != ReadCookie || frames[0].Decision.Packet.Cookie != c1 {
							t.Fatalf("mutant reader without post-burst check did not accept stale record: err=%v decision=%+v want_cookie=%d", readErr, frames[0].Decision, c1)
						}
						t.Logf("P2_STALE_MUTATION skip_post_check=true address=%x stale_cookie=%d sender_cookie=%d accepted_cookie=%d capture_recursion_delta=%d result=stale_accepted", targetAddr, c1, c2, frames[0].Decision.Packet.Cookie, afterHold[0].Misses-before[0].Misses)
					}
					recurred = true
					break
				}
				buf := make([]byte, 2048)
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

