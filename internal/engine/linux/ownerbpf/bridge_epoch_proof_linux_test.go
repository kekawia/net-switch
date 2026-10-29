//go:build linux && ownerbpfproof && (amd64 || arm64)

package ownerbpf

import (
	"errors"
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
func reloadBridgeFixture(t *testing.T, old *bridgeFixture) *bridgeFixture {
	t.Helper()
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
	if err := old.b.Close(); err != nil {
		t.Fatal(err)
	}
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
	fresh := newBridgeFixture(t, false)
	newInfo, err := fresh.b.Collection.Maps["packets"].Info()
	if err != nil {
		t.Fatal(err)
	}
	newID, ok := newInfo.ID()
	if !ok || newID == oldID || fresh.epoch == oldEpoch {
		t.Fatal("collection/epoch was reused")
	}
	var key uint64
	var value PacketRecord
	it := fresh.b.Collection.Maps["packets"].Iterate()
	if it.Next(&key, &value) {
		t.Fatal("fresh packet map not empty", key, value)
	}
	if err := it.Err(); err != nil {
		t.Fatal(err)
	}
	s, _ := bridgeSocket(t, 0)
	cookie := bridgeSend(t, s, []byte("after-reload"))
	frame := bridgeRead(t, fresh, 1)[0]
	if frame.Decision.Status != ReadCookie || frame.Decision.Packet.Cookie != cookie || frame.Decision.Packet.Epoch != fresh.epoch {
		t.Fatal("fresh collection did not capture fresh traffic", frame.Decision)
	}
	t.Logf("P2_RELOAD old_epoch=%d new_epoch=%d old_map=%d new_map=%d old_map_retired=true fresh_map_empty=true fresh_cookie=correct old_publication=refused", oldEpoch, fresh.epoch, oldID, newID)
	return fresh
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
	controller := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		var affinity unix.CPUSet
		affinity.Set((f.cpu + 1) % 2)
		if err := unix.SchedSetaffinity(0, &affinity); err != nil {
			controller <- err
			return
		}
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			var active BridgeFault
			if err := f.b.Collection.Maps["faults"].Lookup(uint32(0), &active); err != nil {
				controller <- err
				return
			}
			if active.Reserved[0] != 0 {
				if active.Reserved[2] != 0 {
					controller <- errors.New("bounded hold ended before preemption stimulus")
					return
				}
				close(start)
				controller <- nil
				return
			}
		}
		controller <- errors.New("consume hold was never observed")
	}()
	a, aerr := f.r.ReadBurst(f.fd, 1)
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
	l, err := netlink.LinkByName("nsbridge0")
	if err != nil || l.Attrs().Statistics == nil {
		t.Fatal(err)
	}
	beforeDrops := l.Attrs().Statistics.TxDropped
	q := netlink.NewNetem(netlink.QdiscAttrs{LinkIndex: l.Attrs().Index, Handle: netlink.MakeHandle(1, 0), Parent: netlink.HANDLE_ROOT}, netlink.NetemQdiscAttrs{Latency: 100, Limit: 100})
	if err := netlink.QdiscReplace(q); err != nil {
		t.Fatal("netem positive-control prerequisite", err)
	}
	before, err := f.b.Sample()
	if err != nil {
		t.Fatal(err)
	}
	ctl := BridgeFault{Epoch: f.epoch, CPU: uint32(f.cpu), Mode: 16}
	if err := f.b.Collection.Maps["faults"].Update(uint32(0), ctl, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	for range 8 {
		bridgeSend(t, s, []byte("timer-drop"))
	}
	// A real copy fault frees the reader's packet in task context. The netem
	// timer must interrupt that held free callback and drop from the full ring.
	_, readErr := f.r.readBurst(f.fd, 1, func(fd int, _ []byte) (int, error) {
		_, _, errno := unix.Syscall(unix.SYS_READ, uintptr(fd), 1, 64)
		if errno == 0 {
			return 0, errors.New("invalid destination did not fault")
		}
		return -1, errno
	})
	if !errors.Is(readErr, unix.EFAULT) || !errors.Is(readErr, ErrEpochRebuild) {
		t.Fatal("copy-fault precondition", readErr)
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
