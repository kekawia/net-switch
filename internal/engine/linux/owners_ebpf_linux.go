//go:build linux && (amd64 || arm64)

package linux

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/linux/ownerbpf"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"golang.org/x/sys/unix"
)

const provenanceCookieRetireGrace = 150 * time.Millisecond

func ebpfBackendSupported() bool { return true }

type ebpfBridgeBurstSource struct {
	owners *Owners
	bridge *ownerbpf.Bridge
}

func (s *ebpfBridgeBurstSource) BindReader() (
	func(fd int, rawBufs [][]byte, sizes []int, decisions []ownerbpf.ReadDecision) (int, error),
	func() error,
	error,
) {
	if s == nil || s.bridge == nil {
		return nil, nil, errors.New("nil eBPF provenance bridge")
	}
	r, err := s.bridge.Register()
	if err != nil {
		return nil, nil, err
	}
	return r.ReadBurstInto, r.Close, nil
}

func (s *ebpfBridgeBurstSource) RebuildEpoch(
	tun *Tun,
	closeOldReader func() error,
) (provenanceBurstSource, func(func() error) error, error) {
	if s == nil || s.owners == nil {
		return nil, nil, errors.New("nil eBPF owners on epoch rebuild")
	}
	return s.owners.rebuildProvenanceEpoch(tun, closeOldReader)
}

type ebpfOwnerStats struct {
	Epoch                        uint64                     `json:"epoch"`
	EpochPoisoned                bool                       `json:"epochPoisoned"`
	EpochRebuilds                uint64                     `json:"epochRebuilds"`
	ProbePoisoned                bool                       `json:"probePoisoned"`
	NoIOUringActive              bool                       `json:"noIOUringActive"`
	BPFMapBytes                  uint64                     `json:"bpfMapBytes"`
	BPFMapCount                  int                        `json:"bpfMapCount"`
	BPFMapMeasured               bool                       `json:"bpfMapMeasured"`
	Ledger                       ownerbpf.LedgerMetrics     `json:"ledger"`
	SocketSlots                  ownerbpf.SocketSlotMetrics `json:"socketSlots"`
	Classifier                   ownerbpf.ClassifierMetrics `json:"classifier"`
	BridgeDeliveredWithoutRecord uint64                     `json:"bridgeDeliveredWithoutRecord"`
	BridgeReadUnknown            uint64                     `json:"bridgeReadUnknown"`
	BridgeUnknownRecursion       uint64                     `json:"bridgeUnknownRecursion"`
	BridgeFaults                 uint64                     `json:"bridgeFaults"`
	TCPKnown                     uint64                     `json:"tcpKnown"`
	TCPUnknownIdentity           uint64                     `json:"tcpUnknownIdentity"`
	TCPConflicting               uint64                     `json:"tcpConflicting"`
	TCPMissingCookie             uint64                     `json:"tcpMissingCookie"`
	TCPKernelControl             uint64                     `json:"tcpKernelControl"`
	UDPKnown                     uint64                     `json:"udpKnown"`
	UDPUnknownIdentity           uint64                     `json:"udpUnknownIdentity"`
	UDPConflicting               uint64                     `json:"udpConflicting"`
	UDPMissingCookie             uint64                     `json:"udpMissingCookie"`
	UDPKernelControl             uint64                     `json:"udpKernelControl"`
	UDPDatagramDrops             uint64                     `json:"udpDatagramDrops"`
	UDPDatagramInvalidations     uint64                     `json:"udpDatagramInvalidations"`
	RetiredCookies               uint64                     `json:"retiredCookies"`
	ReconciledDeadCookies        uint64                     `json:"reconciledDeadCookies"`
	ActorDrainErrors             uint64                     `json:"actorDrainErrors"`
}

type ebpfOwnerState struct {
	mu          sync.Mutex
	stopped     bool
	nextEpoch   atomic.Uint64
	tun         *Tun
	bridge      *ownerbpf.Bridge
	probe       *ownerbpf.AcceptedSenderProbe
	runtime     *ownerbpf.ProvenanceRuntime
	maintCancel context.CancelFunc
	maintWG     sync.WaitGroup
	reconcileCh chan struct{}
	retireCh    chan struct{}

	retireMu                  sync.Mutex
	pendingRetire             map[uint64]time.Time
	lastPressureReconcileNano atomic.Int64

	bridgeDeliveredBase        atomic.Uint64
	bridgeReadUnknownBase      atomic.Uint64
	bridgeUnknownRecursionBase atomic.Uint64
	bridgeFaultsBase           atomic.Uint64

	epochRebuilds            atomic.Uint64
	tcpKnown                 atomic.Uint64
	tcpUnknownIdentity       atomic.Uint64
	tcpConflicting           atomic.Uint64
	tcpMissingCookie         atomic.Uint64
	tcpKernelControl         atomic.Uint64
	udpKnown                 atomic.Uint64
	udpUnknownIdentity       atomic.Uint64
	udpConflicting           atomic.Uint64
	udpMissingCookie         atomic.Uint64
	udpKernelControl         atomic.Uint64
	udpDatagramDrops         atomic.Uint64
	udpDatagramInvalidations atomic.Uint64
	retiredCookies           atomic.Uint64
	reconciledDeadCookies    atomic.Uint64
	actorDrainErrors         atomic.Uint64
}

func (o *Owners) foldBridgeStatsLocked(b *ownerbpf.Bridge) {
	if b == nil {
		return
	}
	o.ebpf.bridgeDeliveredBase.Add(b.DeliveredWithoutRecord.Load())
	o.ebpf.bridgeReadUnknownBase.Add(b.ReadUnknown.Load())
	o.ebpf.bridgeUnknownRecursionBase.Add(b.UnknownRecursion.Load())
	o.ebpf.bridgeFaultsBase.Add(b.Faults())
}

func (o *Owners) ebpfCurrent() (*ownerbpf.ProvenanceRuntime, *ownerbpf.AcceptedSenderProbe, *ownerbpf.Bridge, *Tun) {
	o.ebpf.mu.Lock()
	defer o.ebpf.mu.Unlock()
	return o.ebpf.runtime, o.ebpf.probe, o.ebpf.bridge, o.ebpf.tun
}

func (o *Owners) ebpfStats() *ebpfOwnerStats {
	o.ebpf.mu.Lock()
	rt := o.ebpf.runtime
	probe := o.ebpf.probe
	delivered := o.ebpf.bridgeDeliveredBase.Load()
	readUnknown := o.ebpf.bridgeReadUnknownBase.Load()
	unknownRec := o.ebpf.bridgeUnknownRecursionBase.Load()
	faults := o.ebpf.bridgeFaultsBase.Load()
	if b := o.ebpf.bridge; b != nil {
		delivered += b.DeliveredWithoutRecord.Load()
		readUnknown += b.ReadUnknown.Load()
		unknownRec += b.UnknownRecursion.Load()
		faults += b.Faults()
	}
	o.ebpf.mu.Unlock()

	out := &ebpfOwnerStats{
		EpochRebuilds:                o.ebpf.epochRebuilds.Load(),
		BridgeDeliveredWithoutRecord: delivered,
		BridgeReadUnknown:            readUnknown,
		BridgeUnknownRecursion:       unknownRec,
		BridgeFaults:                 faults,
		TCPKnown:                     o.ebpf.tcpKnown.Load(),
		TCPUnknownIdentity:           o.ebpf.tcpUnknownIdentity.Load(),
		TCPConflicting:               o.ebpf.tcpConflicting.Load(),
		TCPMissingCookie:             o.ebpf.tcpMissingCookie.Load(),
		TCPKernelControl:             o.ebpf.tcpKernelControl.Load(),
		UDPKnown:                     o.ebpf.udpKnown.Load(),
		UDPUnknownIdentity:           o.ebpf.udpUnknownIdentity.Load(),
		UDPConflicting:               o.ebpf.udpConflicting.Load(),
		UDPMissingCookie:             o.ebpf.udpMissingCookie.Load(),
		UDPKernelControl:             o.ebpf.udpKernelControl.Load(),
		UDPDatagramDrops:             o.ebpf.udpDatagramDrops.Load(),
		UDPDatagramInvalidations:     o.ebpf.udpDatagramInvalidations.Load(),
		RetiredCookies:               o.ebpf.retiredCookies.Load(),
		ReconciledDeadCookies:        o.ebpf.reconciledDeadCookies.Load(),
		ActorDrainErrors:             o.ebpf.actorDrainErrors.Load(),
	}
	if rt != nil {
		out.Epoch = rt.Epoch()
		out.EpochPoisoned = rt.IsEpochPoisoned()
		out.Ledger, out.SocketSlots, out.Classifier = rt.Metrics()
	}
	if probe != nil {
		out.ProbePoisoned = probe.IsPoisoned()
		out.NoIOUringActive = probe.NoIOUringActive()
	}
	if mapBytes, mapCount, err := ReadSelfBPFMapMemlockBytes(); err == nil {
		out.BPFMapBytes = mapBytes
		out.BPFMapCount = mapCount
		out.BPFMapMeasured = true
	}
	return out
}

func classifyHostLoadFailure(err error) ownerbpf.DegradedFallbackReason {
	lockdownRaw := ""
	if b, rErr := os.ReadFile("/sys/kernel/security/lockdown"); rErr == nil {
		lockdownRaw = string(b)
	}
	_, btfErr := os.Stat("/sys/kernel/btf/vmlinux")
	hasBTF := btfErr == nil
	isCgroupV2 := false
	var fs unix.Statfs_t
	if unix.Statfs("/sys/fs/cgroup", &fs) == nil && fs.Type == unix.CGROUP2_SUPER_MAGIC {
		isCgroupV2 = true
	}
	return ownerbpf.ClassifyLoadFailure(err, lockdownRaw, hasBTF, isCgroupV2)
}

func (o *Owners) degradeToProcFallback(ctx context.Context, reason ownerbpf.DegradedFallbackReason, cause error) (bool, error) {
	log.Printf("eBPF owner attribution unavailable (%s: %v); degrading to proc-fallback", reason, cause)
	o.ebpfActive.Store(false)
	o.mu.Lock()
	o.backend = OwnerBackendProcFallback
	o.degradedFallback = true
	o.degradedReason = string(reason)
	o.warmed = false
	o.mu.Unlock()
	if err := o.Warm(ctx); err != nil {
		return false, err
	}
	return false, nil
}

func unwrapNativeTun(dev platform.TunDevice) (*Tun, bool) {
	for dev != nil {
		if native, ok := dev.(*Tun); ok {
			return native, true
		}
		u, ok := dev.(platform.TunUnwrapper)
		if !ok {
			return nil, false
		}
		dev = u.UnwrapTun()
	}
	return nil, false
}

func (o *Owners) AttachProvenance(ctx context.Context, dev platform.TunDevice) (bool, error) {
	if !o.isEBPFBackend() {
		if os.Getenv("NETSWITCH_BENCH_EBPF_INSTRUMENTATION_ONLY") == "1" {
			return o.attachInstrumentationOnly(dev)
		}
		return false, nil
	}
	tun, ok := unwrapNativeTun(dev)
	if !ok || tun == nil {
		err := errors.New("eBPF owner backend requires native Linux *Tun device")
		if o.autoFallback {
			return o.degradeToProcFallback(ctx, ownerbpf.FallbackKernelUnsupported, err)
		}
		return false, err
	}
	_ = o.CloseProvenance()

	handleLoadFailure := func(stage string, err error) (bool, error) {
		wrapped := fmt.Errorf("%s: %w", stage, err)
		if o.autoFallback {
			reason := classifyHostLoadFailure(err)
			if reason != ownerbpf.FallbackVerifierRejected && reason != ownerbpf.FallbackNone {
				return o.degradeToProcFallback(ctx, reason, wrapped)
			}
		}
		return false, wrapped
	}

	epoch := o.ebpf.nextEpoch.Add(1)
	slots, err := ownerbpf.NewMmapSocketSlotTable(ownerbpf.DefaultEngineMaxSocketSlots)
	if err != nil {
		return handleLoadFailure("allocate eBPF socket-slot table", err)
	}
	ledger := ownerbpf.NewIdentityLedger(ownerbpf.DefaultEngineMaxSnapshots, ownerbpf.DefaultEngineMaxBlobBytes)
	rt := ownerbpf.NewProvenanceRuntime(epoch, ledger, slots)

	bridge, err := ownerbpf.LoadEngineBridge(uint32(tun.Ifindex()), tun.NetNSInode(), epoch, uint64(tun.TxQLen()))
	if err != nil {
		_ = rt.Close()
		return handleLoadFailure("load eBPF provenance bridge", err)
	}
	probe, err := ownerbpf.LoadEngineSenderProbe("/sys/fs/cgroup", ownerbpf.DefaultEngineMaxActors, ownerbpf.DefaultEngineActorEventQueue)
	if err != nil {
		_ = bridge.Close()
		_ = rt.Close()
		return handleLoadFailure("load eBPF sender probe", err)
	}

	o.ebpf.retireMu.Lock()
	o.ebpf.pendingRetire = make(map[uint64]time.Time)
	o.ebpf.retireMu.Unlock()
	o.ebpf.lastPressureReconcileNano.Store(0)
	o.ebpf.bridgeDeliveredBase.Store(0)
	o.ebpf.bridgeReadUnknownBase.Store(0)
	o.ebpf.bridgeUnknownRecursionBase.Store(0)
	o.ebpf.bridgeFaultsBase.Store(0)

	o.ebpf.mu.Lock()
	o.ebpf.stopped = false
	o.ebpf.tun = tun
	o.ebpf.bridge = bridge
	o.ebpf.probe = probe
	o.ebpf.runtime = rt
	o.ebpf.reconcileCh = make(chan struct{}, 1)
	o.ebpf.retireCh = make(chan struct{}, 1)
	o.ebpf.mu.Unlock()

	tun.AttachProvenanceReader(&ebpfBridgeBurstSource{owners: o, bridge: bridge}, o.onProvenanceBurst)
	return true, nil
}

// attachInstrumentationOnly loads and enables the production eBPF bridge and
// sender probe while keeping userspace on the non-provenance TUN pump and
// proc-fallback scanner so 3-way benchmarks isolate kernel BPF hook cost.
func (o *Owners) attachInstrumentationOnly(dev platform.TunDevice) (bool, error) {
	tun, ok := unwrapNativeTun(dev)
	if !ok || tun == nil {
		return false, errors.New("NETSWITCH_BENCH_EBPF_INSTRUMENTATION_ONLY requires native Linux *Tun device")
	}
	_ = o.CloseProvenance()

	epoch := o.ebpf.nextEpoch.Add(1)
	bridge, err := ownerbpf.LoadEngineBridge(uint32(tun.Ifindex()), tun.NetNSInode(), epoch, uint64(tun.TxQLen()))
	if err != nil {
		return false, fmt.Errorf("load instrumentation-only eBPF bridge: %w", err)
	}
	probe, err := ownerbpf.LoadEngineSenderProbe("/sys/fs/cgroup", ownerbpf.DefaultEngineMaxActors, ownerbpf.DefaultEngineActorEventQueue)
	if err != nil {
		_ = bridge.Close()
		return false, fmt.Errorf("load instrumentation-only eBPF sender probe: %w", err)
	}
	if err := probe.Enable(); err != nil {
		_ = probe.Close()
		_ = bridge.Close()
		return false, fmt.Errorf("enable instrumentation-only eBPF sender probe: %w", err)
	}
	if err := bridge.Enable(uint64(tun.TxQLen())); err != nil {
		_ = probe.Disable()
		_ = probe.Close()
		_ = bridge.Close()
		return false, fmt.Errorf("enable instrumentation-only eBPF bridge: %w", err)
	}

	o.ebpf.bridgeDeliveredBase.Store(0)
	o.ebpf.bridgeReadUnknownBase.Store(0)
	o.ebpf.bridgeUnknownRecursionBase.Store(0)
	o.ebpf.bridgeFaultsBase.Store(0)

	o.ebpf.mu.Lock()
	o.ebpf.stopped = false
	o.ebpf.tun = tun
	o.ebpf.bridge = bridge
	o.ebpf.probe = probe
	o.ebpf.mu.Unlock()
	return false, nil
}

func (o *Owners) rebuildProvenanceEpoch(
	tun *Tun,
	closeOldReader func() error,
) (provenanceBurstSource, func(func() error) error, error) {
	if tun == nil {
		return nil, nil, errors.New("cannot rebuild nil provenance TUN")
	}
	o.ebpf.mu.Lock()
	stopped := o.ebpf.stopped
	oldBridge := o.ebpf.bridge
	probe := o.ebpf.probe
	rt := o.ebpf.runtime
	o.ebpf.mu.Unlock()
	if stopped || rt == nil || probe == nil {
		return nil, nil, errors.New("provenance stopped or detached before epoch rebuild")
	}

	if oldBridge != nil {
		_ = oldBridge.Stop()
	}
	if closeOldReader != nil {
		_ = closeOldReader()
	}

	o.ebpf.mu.Lock()
	if o.ebpf.bridge == oldBridge {
		o.foldBridgeStatsLocked(oldBridge)
		o.ebpf.bridge = nil
	}
	stopped = o.ebpf.stopped
	o.ebpf.mu.Unlock()

	if oldBridge != nil {
		_ = oldBridge.Close()
	}
	if stopped {
		return nil, nil, errors.New("provenance stopped during epoch rebuild")
	}

	newEpoch := o.ebpf.nextEpoch.Add(1)
	rt.AdvanceBridgeEpoch(newEpoch)

	newBridge, err := ownerbpf.LoadEngineBridge(uint32(tun.Ifindex()), tun.NetNSInode(), newEpoch, uint64(tun.TxQLen()))
	if err != nil {
		return nil, nil, fmt.Errorf("reload eBPF provenance bridge for epoch %d: %w", newEpoch, err)
	}

	o.ebpf.mu.Lock()
	if o.ebpf.stopped || o.ebpf.runtime != rt || o.ebpf.probe == nil {
		o.ebpf.mu.Unlock()
		_ = newBridge.Close()
		return nil, nil, errors.New("provenance stopped during bridge reload")
	}
	o.ebpf.bridge = newBridge
	o.ebpf.mu.Unlock()

	enableNew := func(drainLocked func() error) error {
		if drainLocked != nil {
			if err := drainLocked(); err != nil {
				return fmt.Errorf("drain uncertified TUN frames during epoch rebuild: %w", err)
			}
		}
		o.ebpf.mu.Lock()
		aborted := o.ebpf.stopped || o.ebpf.bridge != newBridge
		o.ebpf.mu.Unlock()
		if aborted {
			return errors.New("provenance stopped before enabling rebuilt bridge")
		}
		if err := newBridge.Enable(uint64(tun.TxQLen())); err != nil {
			return fmt.Errorf("enable rebuilt eBPF provenance bridge: %w", err)
		}
		o.ebpf.epochRebuilds.Add(1)
		return nil
	}
	return &ebpfBridgeBurstSource{owners: o, bridge: newBridge}, enableNew, nil
}

func (o *Owners) EnableProvenance() error {
	if !o.isEBPFBackend() {
		return nil
	}
	rt, probe, bridge, tun := o.ebpfCurrent()
	if rt == nil || probe == nil || bridge == nil || tun == nil {
		return errors.New("eBPF provenance is not attached")
	}
	if err := probe.Enable(); err != nil {
		return fmt.Errorf("enable eBPF sender probe: %w", err)
	}
	if err := tun.DrainNonblock(); err != nil {
		_ = probe.Disable()
		return fmt.Errorf("drain pre-enable TUN frames: %w", err)
	}
	if err := bridge.Enable(uint64(tun.TxQLen())); err != nil {
		_ = probe.Disable()
		return fmt.Errorf("enable eBPF provenance bridge: %w", err)
	}
	o.startProvenanceMaintenance()
	return nil
}

func (o *Owners) StopProvenance() error {
	o.ebpf.mu.Lock()
	o.ebpf.stopped = true
	cancel := o.ebpf.maintCancel
	o.ebpf.maintCancel = nil
	probe := o.ebpf.probe
	bridge := o.ebpf.bridge
	o.ebpf.mu.Unlock()

	if cancel != nil {
		cancel()
		o.ebpf.maintWG.Wait()
	}
	var errs []error
	if probe != nil {
		errs = append(errs, probe.Disable())
	}
	if bridge != nil {
		errs = append(errs, bridge.Stop())
	}
	return errors.Join(errs...)
}

func (o *Owners) CloseProvenance() error {
	stopErr := o.StopProvenance()

	o.ebpf.mu.Lock()
	tun := o.ebpf.tun
	bridge := o.ebpf.bridge
	probe := o.ebpf.probe
	rt := o.ebpf.runtime
	o.foldBridgeStatsLocked(bridge)
	o.ebpf.tun = nil
	o.ebpf.bridge = nil
	o.ebpf.probe = nil
	o.ebpf.runtime = nil
	o.ebpf.reconcileCh = nil
	o.ebpf.retireCh = nil
	o.ebpf.mu.Unlock()

	o.ebpf.retireMu.Lock()
	o.ebpf.pendingRetire = nil
	o.ebpf.retireMu.Unlock()

	if tun != nil {
		tun.DetachProvenanceReader()
	}
	var errs []error
	if stopErr != nil {
		errs = append(errs, stopErr)
	}
	if bridge != nil {
		errs = append(errs, bridge.Close())
	}
	if probe != nil {
		errs = append(errs, probe.Close())
	}
	if rt != nil {
		errs = append(errs, rt.Close())
	}
	return errors.Join(errs...)
}

func (o *Owners) drainPendingActors(rt *ownerbpf.ProvenanceRuntime, probe *ownerbpf.AcceptedSenderProbe) {
	if rt == nil || probe == nil {
		return
	}
	if probe.IsPoisoned() {
		rt.PoisonEpoch()
	}
	if !probe.HasPendingNewActors() {
		return
	}
	events, err := probe.DrainNewActors(nil)
	if err != nil {
		o.ebpf.actorDrainErrors.Add(1)
	}
	if len(events) > 0 {
		rt.SyncQueuedActorsWithOptions(events, probe.NoIOUringActive())
		if rt.TrackedCookieCount() >= ownerbpf.DefaultEngineMaxSocketSlots/4 {
			nowNano := time.Now().UnixNano()
			last := o.ebpf.lastPressureReconcileNano.Load()
			if nowNano-last >= int64(250*time.Millisecond) && o.ebpf.lastPressureReconcileNano.CompareAndSwap(last, nowNano) {
				o.requestProvenanceReconcile()
			}
		}
	}
	if probe.IsPoisoned() {
		rt.PoisonEpoch()
	}
}

func (o *Owners) onProvenanceBurst(
	rawBufs [][]byte,
	sizes []int,
	decisions []ownerbpf.ReadDecision,
	count int,
	out []*ownerbpf.ProvenanceEnvelope,
) {
	rt, probe, _, _ := o.ebpfCurrent()
	o.drainPendingActors(rt, probe)
	for i := 0; i < count; i++ {
		var l3 []byte
		if sizes[i] > ownerbpf.VirtioNetHdrLen {
			l3 = rawBufs[i][ownerbpf.VirtioNetHdrLen:sizes[i]]
		}
		out[i] = rt.AcquirePacket(l3, decisions[i])
	}
}

func (o *Owners) scheduleProvenanceCookieRetire(cookie uint64) {
	if !o.isEBPFBackend() || cookie == 0 {
		return
	}
	flushNow := false
	o.ebpf.retireMu.Lock()
	if o.ebpf.pendingRetire != nil {
		if _, exists := o.ebpf.pendingRetire[cookie]; !exists {
			o.ebpf.pendingRetire[cookie] = time.Now()
		}
		flushNow = len(o.ebpf.pendingRetire) >= 2048
	}
	o.ebpf.retireMu.Unlock()
	if flushNow {
		o.requestProvenanceRetireSweep()
	}
}

func (o *Owners) requestProvenanceRetireSweep() {
	if !o.isEBPFBackend() {
		return
	}
	o.ebpf.mu.Lock()
	ch := o.ebpf.retireCh
	o.ebpf.mu.Unlock()
	if ch != nil {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (o *Owners) requestProvenanceReconcile() {
	if !o.isEBPFBackend() {
		return
	}
	o.ebpf.mu.Lock()
	ch := o.ebpf.reconcileCh
	o.ebpf.mu.Unlock()
	if ch != nil {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (o *Owners) retireCookieNow(rt *ownerbpf.ProvenanceRuntime, probe *ownerbpf.AcceptedSenderProbe, cookie uint64) {
	if rt == nil || cookie == 0 {
		return
	}
	keys, unreferenced := rt.RetireSocket(cookie)
	if probe != nil && len(keys) > 0 {
		probe.DeleteActorKeys(keys)
	}
	o.ebpf.retiredCookies.Add(1)
	for _, actorID := range unreferenced {
		if ctx, ok := rt.ActorContextIfUnreferenced(actorID); ok && !ownerbpf.IsActorIncarnationAlive(ctx) {
			rt.ReleaseActorIfUnreferenced(actorID)
		}
	}
}

func (o *Owners) sweepPendingCookieRetires(now time.Time) {
	rt, probe, _, _ := o.ebpfCurrent()
	if rt == nil {
		return
	}
	var matured []uint64
	o.ebpf.retireMu.Lock()
	for cookie, at := range o.ebpf.pendingRetire {
		if now.Sub(at) >= provenanceCookieRetireGrace {
			matured = append(matured, cookie)
			delete(o.ebpf.pendingRetire, cookie)
		}
	}
	o.ebpf.retireMu.Unlock()
	if len(matured) == 0 {
		return
	}
	o.drainPendingActors(rt, probe)
	for _, cookie := range matured {
		o.retireCookieNow(rt, probe, cookie)
	}
}

func (o *Owners) reconcileProvenanceLiveCookies(ctx context.Context) {
	rt, probe, _, _ := o.ebpfCurrent()
	if rt == nil {
		return
	}
	if rt.TrackedCookieCount() == 0 && rt.ActiveActorCount() == 0 && (probe == nil || !probe.HasPendingNewActors()) {
		return
	}
	o.drainPendingActors(rt, probe)
	if rt.TrackedCookieCount() > 0 {
		started := time.Now().Add(-provenanceCookieRetireGrace)
		dumpCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		sweep := rt.BeginCookieLiveSweep()
		var batch [256]uint64
		nBatch := 0
		flushBatch := func() {
			if nBatch > 0 {
				rt.MarkCookiesLive(batch[:nBatch], sweep)
				nBatch = 0
			}
		}
		complete := sweep != 0
		for _, fam := range []int{unix.AF_INET, unix.AF_INET6} {
			if !complete {
				break
			}
			for _, proto := range []int{unix.IPPROTO_UDP, unix.IPPROTO_TCP} {
				err := diagStreamCookies(dumpCtx, fam, proto, func(cookie uint64) {
					batch[nBatch] = cookie
					nBatch++
					if nBatch == len(batch) {
						flushBatch()
					}
				})
				flushBatch()
				if err != nil {
					complete = false
					break
				}
			}
		}
		cancel()
		if complete {
			dead := rt.CollectDeadCookies(started, sweep)
			for _, cookie := range dead {
				o.ebpf.retireMu.Lock()
				delete(o.ebpf.pendingRetire, cookie)
				o.ebpf.retireMu.Unlock()
				o.retireCookieNow(rt, probe, cookie)
				o.ebpf.reconciledDeadCookies.Add(1)
			}
		}
	}
	if rt.ActiveActorCount() > 0 {
		rt.ReapExitedUnreferencedActors()
	}
}

func (o *Owners) startProvenanceMaintenance() {
	o.ebpf.mu.Lock()
	if o.ebpf.maintCancel != nil || o.ebpf.stopped {
		o.ebpf.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	o.ebpf.maintCancel = cancel
	reconcileCh := o.ebpf.reconcileCh
	retireCh := o.ebpf.retireCh
	o.ebpf.maintWG.Add(1)
	o.ebpf.mu.Unlock()

	go func() {
		defer o.ebpf.maintWG.Done()
		retireTicker := time.NewTicker(100 * time.Millisecond)
		defer retireTicker.Stop()
		reconcileTicker := time.NewTicker(2 * time.Second)
		defer reconcileTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-retireTicker.C:
				o.sweepPendingCookieRetires(now)
			case <-retireCh:
				o.sweepPendingCookieRetires(time.Now())
			case <-reconcileTicker.C:
				o.sweepPendingCookieRetires(time.Now())
				o.reconcileProvenanceLiveCookies(ctx)
			case <-reconcileCh:
				o.sweepPendingCookieRetires(time.Now())
				o.reconcileProvenanceLiveCookies(ctx)
			}
		}
	}()
}

func (o *Owners) TCPWithProvenance(ctx context.Context, t platform.Tuple, provenance any) (owner platform.Owner, err error) {
	if !o.isEBPFBackend() {
		return o.TCP(ctx, t)
	}
	defer func() { o.recordError(err) }()
	if o.fault != nil {
		if err := o.fault(ctx); err != nil {
			return platform.Owner{}, err
		}
	}
	if stopErr := lookupContextError(ctx); stopErr != nil {
		return platform.Owner{}, stopErr
	}
	env, ok := provenance.(*ownerbpf.ProvenanceEnvelope)
	if !ok || env == nil {
		o.ebpf.tcpMissingCookie.Add(1)
		return platform.Owner{}, os.ErrNotExist
	}
	validatedOwner, status := env.ValidateForwarding()
	switch status {
	case ownerbpf.EnvelopeKnown:
		o.ebpf.tcpKnown.Add(1)
		return validatedOwner, nil
	case ownerbpf.EnvelopeConflicting:
		o.ebpf.tcpConflicting.Add(1)
		return platform.Owner{Generation: validatedOwner.Generation, Ambiguous: true}, platform.ErrAmbiguous
	case ownerbpf.EnvelopeKernelControl:
		o.ebpf.tcpKernelControl.Add(1)
		return platform.Owner{Generation: validatedOwner.Generation}, os.ErrNotExist
	case ownerbpf.EnvelopeUnknownIdentity:
		o.ebpf.tcpUnknownIdentity.Add(1)
		return platform.Owner{Generation: validatedOwner.Generation}, os.ErrNotExist
	default:
		o.ebpf.tcpMissingCookie.Add(1)
		return platform.Owner{}, os.ErrNotExist
	}
}

func (o *Owners) UDPWithProvenance(ctx context.Context, tuple platform.Tuple, provenance any) (owner platform.Owner, err error) {
	if !o.isEBPFBackend() {
		return o.UDPFor(ctx, tuple)
	}
	started := time.Now()
	defer func() {
		o.recordError(err)
		if err != nil && owner.Generation == "" {
			o.recordUDPGenerationFailure(ctx, tuple, "ebpf-envelope", started, err)
		}
	}()

	forcedUnknown := false
	if o.fault != nil {
		if fErr := o.fault(ctx); fErr != nil {
			if !errors.Is(fErr, errForcedUnknown) {
				return platform.Owner{}, fErr
			}
			forcedUnknown = true
		}
	}
	identity, cancel := lookupContext(ctx)
	defer cancel()
	if o.afterUDPIdentityContext != nil {
		o.afterUDPIdentityContext(identity)
	}

	env, ok := provenance.(*ownerbpf.ProvenanceEnvelope)
	if !ok || env == nil {
		o.ebpf.udpMissingCookie.Add(1)
		return platform.Owner{}, os.ErrNotExist
	}
	validatedOwner, status := env.ValidateForwarding()
	if outerStopped := lookupContextError(ctx); outerStopped != nil {
		return platform.Owner{}, fmt.Errorf("UDP setup context: %w", outerStopped)
	}

	switch status {
	case ownerbpf.EnvelopeKnown:
		if o.afterUDPOwnerResolution != nil {
			o.afterUDPOwnerResolution(identity, validatedOwner)
		}
		if stopped := lookupContextError(identity); stopped != nil {
			o.udpIdentityExpiredGeneration.Add(1)
			o.udpLateIdentityDiscarded.Add(1)
			o.recordUDPUnknown(tuple.Source, env.Cookie, true)
			return platform.Owner{Generation: validatedOwner.Generation}, fmt.Errorf("UDP identity context: %w", stopped)
		}
		if forcedUnknown {
			o.recordUDPUnknown(tuple.Source, env.Cookie, true)
			return platform.Owner{Generation: validatedOwner.Generation}, nil
		}
		o.recordUDPUnknown(tuple.Source, env.Cookie, false)
		o.ebpf.udpKnown.Add(1)
		return validatedOwner, nil
	case ownerbpf.EnvelopeConflicting:
		o.ebpf.udpConflicting.Add(1)
		return platform.Owner{Generation: validatedOwner.Generation, Ambiguous: true}, platform.ErrAmbiguous
	case ownerbpf.EnvelopeKernelControl:
		o.ebpf.udpKernelControl.Add(1)
		o.recordUDPUnknown(tuple.Source, env.Cookie, true)
		return platform.Owner{Generation: validatedOwner.Generation}, os.ErrNotExist
	case ownerbpf.EnvelopeUnknownIdentity:
		o.ebpf.udpUnknownIdentity.Add(1)
		o.recordUDPUnknown(tuple.Source, env.Cookie, true)
		return platform.Owner{Generation: validatedOwner.Generation}, os.ErrNotExist
	default:
		o.ebpf.udpMissingCookie.Add(1)
		return platform.Owner{}, os.ErrNotExist
	}
}

func (o *Owners) ValidateUDPDatagram(sessionOwner platform.Owner, provenance any) platform.DatagramValidation {
	if !o.isEBPFBackend() {
		return platform.DatagramValid
	}
	env, ok := provenance.(*ownerbpf.ProvenanceEnvelope)
	if !ok || env == nil {
		o.ebpf.udpDatagramDrops.Add(1)
		return platform.DatagramDrop
	}
	owner, status := env.ValidateForwarding()
	if status == ownerbpf.EnvelopeMissingCookie || owner.Generation == "" {
		o.ebpf.udpDatagramDrops.Add(1)
		return platform.DatagramDrop
	}
	if owner.Generation != sessionOwner.Generation {
		o.ebpf.udpDatagramInvalidations.Add(1)
		return platform.DatagramInvalidateOwner
	}
	if sessionOwner.Ambiguous {
		return platform.DatagramValid
	}
	if status == ownerbpf.EnvelopeConflicting {
		o.ebpf.udpDatagramInvalidations.Add(1)
		return platform.DatagramInvalidateOwner
	}
	if sessionOwner.AppID != "" {
		if status != ownerbpf.EnvelopeKnown || owner.AppID != sessionOwner.AppID {
			o.ebpf.udpDatagramInvalidations.Add(1)
			return platform.DatagramInvalidateOwner
		}
	}
	return platform.DatagramValid
}

func (o *Owners) snapshotEBPFAt(ctx context.Context, keys []netip.AddrPort, started time.Time) (map[netip.AddrPort]platform.Owner, error) {
	o.sweepPendingCookieRetires(started)
	rt, _, _, _ := o.ebpfCurrent()

	rows := map[int][]socketRow{}
	for _, fam := range []int{unix.AF_INET, unix.AF_INET6} {
		need := false
		for _, k := range keys {
			if familyOf(k.Addr()) == fam || fam == unix.AF_INET6 {
				need = true
				break
			}
		}
		if !need {
			continue
		}
		v, err := diagDump(ctx, fam, unix.IPPROTO_UDP, netip.AddrPort{})
		if err != nil {
			return nil, err
		}
		rows[fam] = v
	}

	byPort := map[uint16][]socketRow{}
	for _, familyRows := range rows {
		for _, r := range familyRows {
			byPort[r.local.Port()] = append(byPort[r.local.Port()], r)
		}
	}

	live := make(map[uint64]bool, len(keys))
	out := make(map[netip.AddrPort]platform.Owner, len(keys))
	for _, k := range keys {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		candidates := udpCandidates(byPort[k.Port()], k)
		if len(candidates) == 0 {
			continue
		}
		var chosen socketRow
		if len(candidates) == 1 {
			chosen = candidates[0]
		} else {
			activeSenders := 0
			for _, candidate := range candidates {
				live[candidate.cookie] = true
				if rt != nil {
					if _, _, ok := rt.LookupLiveCookieOwner(candidate.cookie); ok {
						chosen = candidate
						activeSenders++
					}
				}
			}
			if activeSenders != 1 {
				o.mu.Lock()
				o.ambiguousPorts[k.Port()] = time.Now().Add(2 * time.Second)
				o.mu.Unlock()
				out[k] = platform.Owner{Generation: cookieSet(byPort[k.Port()], k), Ambiguous: activeSenders > 1}
				continue
			}
		}

		live[chosen.cookie] = true
		if rt == nil {
			out[k] = platform.Owner{Generation: chosen.generation()}
			continue
		}
		liveOwner, liveStatus, ok := rt.LookupLiveCookieOwner(chosen.cookie)
		if !ok {
			out[k] = platform.Owner{Generation: chosen.generation()}
			continue
		}
		if liveStatus == ownerbpf.IdentityConflicting {
			out[k] = platform.Owner{Generation: chosen.generation(), Ambiguous: true}
			continue
		}
		if o.udpWasUnknown(k, chosen.cookie) {
			out[k] = platform.Owner{Generation: chosen.generation()}
			continue
		}
		out[k] = liveOwner
	}

	o.mu.Lock()
	for port, until := range o.ambiguousPorts {
		if !time.Now().Before(until) {
			delete(o.ambiguousPorts, port)
		}
	}
	o.mu.Unlock()
	referenced := make(map[netip.AddrPort]bool, len(keys))
	for _, key := range keys {
		referenced[key] = true
	}
	o.pruneCookies(live, referenced, started)
	return out, nil
}
