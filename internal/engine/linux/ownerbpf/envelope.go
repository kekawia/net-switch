package ownerbpf

import (
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

const (
	// ProvenanceSourcePacket identifies immutable eBPF packet-bound provenance,
	// kept strictly distinct from proc-fallback live tuple scans.
	ProvenanceSourcePacket  = "ebpf-packet"
	ProvenanceSourceScanner = "proc-fallback"
)

type EnvelopeStatus string

const (
	EnvelopeKnown           EnvelopeStatus = "known"
	EnvelopeUnknownIdentity EnvelopeStatus = "unknown_identity"
	EnvelopeConflicting     EnvelopeStatus = "conflicting"
	EnvelopeMissingCookie   EnvelopeStatus = "missing_cookie"
	EnvelopeKernelControl   EnvelopeStatus = "kernel_control"
)

// FormatCookieGeneration formats a non-zero Linux socket cookie identically to
// socketRow.generation() in internal/engine/linux/diag_linux.go so SOCK_DESTROY
// notifications and SnapshotAt reconciliations match NAT session generations.
func FormatCookieGeneration(cookie uint64) string {
	if cookie == 0 {
		return ""
	}
	return strconv.FormatUint(cookie, 16)
}

func snapshotToOwner(snap *IdentitySnapshot, cookie uint64) platform.Owner {
	return snapshotToOwnerWithGen(snap, FormatCookieGeneration(cookie))
}

func snapshotToOwnerWithGen(snap *IdentitySnapshot, gen string) platform.Owner {
	if snap == nil {
		return platform.Owner{Generation: gen}
	}
	start := snap.Context.StartTicks
	if start == 0 {
		start = snap.Context.StartBoottime
	}
	return platform.Owner{
		PID:        snap.Context.TGID,
		StartTime:  start,
		Path:       snap.Path,
		AppID:      snap.AppID,
		Generation: gen,
	}
}

type envelopePin struct {
	snap      *IdentitySnapshot
	slotIndex uint32
	hasSlot   bool
	retained  bool
}

var runtimeMonoOrigin = time.Now()

func monoSinceOrigin(t time.Time) int64 {
	if t.IsZero() {
		t = time.Now()
	}
	return int64(t.Sub(runtimeMonoOrigin))
}

type cookieActorRef struct {
	start uint64
	exec  uint64
	tgid  uint32
	_     uint32
}

// trackedCookie is a 40-byte pointer-free (noscan) map value holding the
// cookie's earliest observation timestamp, current netlink sweep mark, and
// inline first actor incarnation so single-actor sockets allocate zero slices.
type trackedCookie struct {
	observedMono int64
	first        cookieActorRef
	liveSweep    uint32
	hasFirst     bool
	_            [3]byte
}

var (
	_ [40 - unsafe.Sizeof(trackedCookie{})]byte
	_ [unsafe.Sizeof(trackedCookie{}) - 40]byte
)

// ProvenanceRuntime coordinates thread-safe actor/socket lifecycle updates on
// an IdentityLedger and SocketSlotTable while allowing forwarding decisions to
// validate pinned socket-slot generations atomically without locks or syscalls.
type ProvenanceRuntime struct {
	mu                sync.Mutex
	closed            bool
	epoch             atomic.Uint64
	epochPoisoned     atomic.Bool
	ledger            *IdentityLedger
	slots             *SocketSlotTable
	classifier        *KernelControlClassifier
	processed         map[ActorKey]bool
	cookies           map[uint64]trackedCookie
	multiCookieActors map[uint64][]cookieActorRef
	actorRefCookies   map[ActorIdentityKey]int
	liveSweepSeq      uint32
}

func NewProvenanceRuntime(epoch uint64, ledger *IdentityLedger, slots *SocketSlotTable) *ProvenanceRuntime {
	if ledger == nil {
		ledger = NewIdentityLedger(DefaultMaxIdentitySnapshots, DefaultMaxIdentityBlobBytes)
	}
	if slots == nil {
		slots = NewSocketSlotTable(DefaultMaxSocketSlots)
	}
	ledger.AttachSlotTable(slots)
	if epoch == 0 {
		epoch = 1
	}
	rt := &ProvenanceRuntime{
		ledger:          ledger,
		slots:           slots,
		classifier:      NewKernelControlClassifier(),
		cookies:         make(map[uint64]trackedCookie, min(slots.MaxSlots, 256)),
		actorRefCookies: make(map[ActorIdentityKey]int),
	}
	rt.epoch.Store(epoch)
	rt.syncEpochPoisonedLocked()
	return rt
}

func (rt *ProvenanceRuntime) PoisonEpoch() {
	if rt == nil {
		return
	}
	rt.epochPoisoned.Store(true)
}

func (rt *ProvenanceRuntime) IsEpochPoisoned() bool {
	if rt == nil {
		return true
	}
	return rt.epochPoisoned.Load()
}

func (rt *ProvenanceRuntime) Epoch() uint64 {
	if rt == nil {
		return 0
	}
	return rt.epoch.Load()
}

func (rt *ProvenanceRuntime) SetEpoch(epoch uint64) {
	if rt == nil {
		return
	}
	rt.mu.Lock()
	rt.epoch.Store(epoch)
	rt.mu.Unlock()
}

// AdvanceBridgeEpoch transitions rt to a new strictly larger packet-capture
// epoch during a quiesced live Bridge reload while keeping the uninterrupted
// AcceptedSenderProbe, IdentityLedger, and SocketSlotTable intact. Any
// previously acquired ProvenanceEnvelope immediately fails ValidateForwarding
// (rt.epoch != e.Epoch -> MissingCookie), while existing live sockets retain
// their validated slot ownership for packets captured in the new Bridge epoch.
// AdvanceBridgeEpoch never clears an already-poisoned epoch.
func (rt *ProvenanceRuntime) AdvanceBridgeEpoch(newEpoch uint64) {
	if rt == nil {
		return
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.closed {
		return
	}
	if cur := rt.epoch.Load(); newEpoch <= cur {
		newEpoch = cur + 1
	}
	rt.epoch.Store(newEpoch)
	rt.syncEpochPoisonedLocked()
}

// AdvanceEpoch transitions rt to a new strictly larger epoch during a full
// live bridge+probe reset. Any previously acquired ProvenanceEnvelope on the
// Go heap immediately sees rt.epoch.Load() != e.Epoch (returning MissingCookie)
// while its mmap slot and IdentitySnapshot pins remain valid until GC cleanup.
func (rt *ProvenanceRuntime) AdvanceEpoch(newEpoch uint64) {
	if rt == nil {
		return
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.closed {
		return
	}
	if cur := rt.epoch.Load(); newEpoch <= cur {
		newEpoch = cur + 1
	}
	rt.epoch.Store(newEpoch)
	rt.epochPoisoned.Store(false)
	if rt.slots != nil {
		rt.slots.metrics.EpochPoisoned = false
		for idx := uint32(0); idx < rt.slots.highWater; idx++ {
			m := &rt.slots.meta[idx]
			if !m.inUse {
				continue
			}
			s := &rt.slots.slots[idx]
			cookie := atomic.LoadUint64(&s.Cookie)
			delete(rt.slots.cookieToSlot, cookie)
			before := *m
			m.socketAlive = false
			rt.slots.updateSlotMetrics(before, *m)
			flags := SocketSlotFlags(atomic.LoadUint32(&s.Flags))
			atomic.StoreUint32(&s.Flags, uint32((flags&^SocketSlotValid)|SocketSlotDestroyed))
			rt.slots.tryReclaimSlot(rt.ledger, idx)
		}
	}
	if rt.ledger != nil {
		if rt.ledger.stagedCork != nil {
			clear(rt.ledger.stagedCork)
		}
		for cookie, st := range rt.ledger.sockets {
			owner := st.Owner
			st.Owner = nil
			delete(rt.ledger.sockets, cookie)
			rt.ledger.decrementSocketRef(owner)
		}
		for _, snap := range rt.ledger.actors {
			if snap == nil {
				continue
			}
			snap.actorRefs = 0
			rt.ledger.tryReclaimSnapshot(snap)
		}
	}
	if rt.processed != nil {
		clear(rt.processed)
	}
	clear(rt.cookies)
	if rt.multiCookieActors != nil {
		clear(rt.multiCookieActors)
	}
	clear(rt.actorRefCookies)
	rt.classifier = NewKernelControlClassifier()
}

func (rt *ProvenanceRuntime) syncEpochPoisonedLocked() {
	if rt.slots != nil && rt.slots.metrics.EpochPoisoned {
		rt.epochPoisoned.Store(true)
	}
}

func (rt *ProvenanceRuntime) EnrichActor(key ActorKey, ev ActorEvidence, mat RawProcessMaterial) (*IdentitySnapshot, IdentityReason) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if key.Cookie != 0 {
		rt.classifier.RecordUserspaceSocket(key.Cookie)
	}
	snap, reason := rt.ledger.EnrichActor(key, ev, mat)
	rt.syncEpochPoisonedLocked()
	return snap, reason
}

func (rt *ProvenanceRuntime) ObserveWarmSend(key ActorKey, ev ActorEvidence) (*IdentitySnapshot, IdentityReason) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if key.Cookie != 0 {
		rt.classifier.RecordUserspaceSocket(key.Cookie)
	}
	snap, reason := rt.ledger.ObserveWarmSend(key, ev)
	rt.syncEpochPoisonedLocked()
	return snap, reason
}

func (rt *ProvenanceRuntime) InheritFork(parentKey ActorIdentityKey, childKey ActorKey, childEv ActorEvidence, childCtx ExecutionContext) (*IdentitySnapshot, IdentityReason) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if childKey.Cookie != 0 {
		rt.classifier.RecordUserspaceSocket(childKey.Cookie)
	}
	snap, reason := rt.ledger.InheritFork(parentKey, childKey, childEv, childCtx)
	rt.syncEpochPoisonedLocked()
	return snap, reason
}

func (rt *ProvenanceRuntime) ObserveColdUnretained(key ActorKey, ev ActorEvidence) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if key.Cookie != 0 {
		rt.classifier.RecordUserspaceSocket(key.Cookie)
	}
	rt.ledger.ObserveColdUnretained(key, ev)
	rt.syncEpochPoisonedLocked()
}

func (rt *ProvenanceRuntime) ObserveUnobservableSubmitter(cookie uint64) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.ledger.ObserveUnobservableSubmitter(cookie)
	rt.syncEpochPoisonedLocked()
}

func (rt *ProvenanceRuntime) ObserveFailedSend(cookie uint64, key ActorKey) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.ledger.ObserveFailedSend(cookie, key)
}

func (rt *ProvenanceRuntime) StageCorkContributor(key ActorKey, ev ActorEvidence, mat RawProcessMaterial) (*IdentitySnapshot, IdentityReason) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if key.Cookie != 0 {
		rt.classifier.RecordUserspaceSocket(key.Cookie)
	}
	snap, reason := rt.ledger.StageCorkContributor(key, ev, mat)
	rt.syncEpochPoisonedLocked()
	return snap, reason
}

func (rt *ProvenanceRuntime) FlushCork(cookie uint64) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	ok := rt.ledger.FlushCork(cookie)
	rt.syncEpochPoisonedLocked()
	return ok
}

func (rt *ProvenanceRuntime) DiscardCork(cookie uint64) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.ledger.DiscardCork(cookie)
}

func (rt *ProvenanceRuntime) ReleaseActor(key ActorIdentityKey) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.ledger.ReleaseActor(key)
}

func (rt *ProvenanceRuntime) ReleaseSocket(cookie uint64) {
	_, _ = rt.RetireSocket(cookie)
}

func (rt *ProvenanceRuntime) trackSocketActorLocked(key ActorKey, observedAt time.Time) bool {
	if key.Cookie == 0 {
		return false
	}
	obsMono := monoSinceOrigin(observedAt)
	tc, exists := rt.cookies[key.Cookie]
	if !exists {
		tc = trackedCookie{observedMono: obsMono}
	} else if obsMono < tc.observedMono {
		tc.observedMono = obsMono
	}
	rt.classifier.RecordUserspaceSocket(key.Cookie)

	ref := cookieActorRef{
		start: key.Start,
		exec:  key.Exec,
		tgid:  key.TGID,
	}
	if tc.hasFirst && tc.first == ref {
		rt.cookies[key.Cookie] = tc
		return false
	}
	if extras := rt.multiCookieActors[key.Cookie]; len(extras) > 0 {
		for _, existing := range extras {
			if existing == ref {
				rt.cookies[key.Cookie] = tc
				return false
			}
		}
	}
	if !tc.hasFirst {
		tc.hasFirst = true
		tc.first = ref
		rt.cookies[key.Cookie] = tc
	} else {
		rt.cookies[key.Cookie] = tc
		if rt.multiCookieActors == nil {
			rt.multiCookieActors = make(map[uint64][]cookieActorRef)
		}
		rt.multiCookieActors[key.Cookie] = append(rt.multiCookieActors[key.Cookie], ref)
	}
	if key.TGID != 0 {
		actorID := ActorIdentityKey{
			TGID:          key.TGID,
			StartBoottime: key.Start,
			ExecID:        key.Exec,
		}
		rt.actorRefCookies[actorID]++
	}
	return true
}

// RetireSocket releases cookie's retained SocketSlotTable entry, removes its
// tracked ActorKeys, and returns both the BPF actor keys to delete from
// Maps["actors"] and any ActorIdentityKeys whose live-socket reference count
// just reached zero.
func (rt *ProvenanceRuntime) RetireSocket(cookie uint64) ([]ActorKey, []ActorIdentityKey) {
	if rt == nil || cookie == 0 {
		return nil, nil
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.ledger.ReleaseSocket(cookie)
	rt.classifier.ForgetSocket(cookie)
	tc, ok := rt.cookies[cookie]
	delete(rt.cookies, cookie)
	var extras []cookieActorRef
	if rt.multiCookieActors != nil {
		extras = rt.multiCookieActors[cookie]
		delete(rt.multiCookieActors, cookie)
	}
	if (!ok || !tc.hasFirst) && len(extras) == 0 {
		return nil, nil
	}
	total := len(extras)
	if ok && tc.hasFirst {
		total++
	}
	keys := make([]ActorKey, 0, total)
	var unreferenced []ActorIdentityKey
	retireRef := func(r cookieActorRef) {
		ak := ActorKey{
			Cookie: cookie,
			Start:  r.start,
			Exec:   r.exec,
			TGID:   r.tgid,
		}
		keys = append(keys, ak)
		if rt.processed != nil {
			delete(rt.processed, ak)
		}
		if r.tgid != 0 {
			actorID := ActorIdentityKey{
				TGID:          r.tgid,
				StartBoottime: r.start,
				ExecID:        r.exec,
			}
			rem := rt.actorRefCookies[actorID] - 1
			if rem <= 0 {
				delete(rt.actorRefCookies, actorID)
				unreferenced = append(unreferenced, actorID)
			} else {
				rt.actorRefCookies[actorID] = rem
			}
		}
	}
	if ok && tc.hasFirst {
		retireRef(tc.first)
	}
	for _, r := range extras {
		retireRef(r)
	}
	return keys, unreferenced
}

// ReleaseActorIfUnreferenced drops activeActor retention in IdentityLedger only
// if no new socket has referenced actorID since RetireSocket returned it.
func (rt *ProvenanceRuntime) ReleaseActorIfUnreferenced(actorID ActorIdentityKey) {
	if rt == nil || actorID.TGID == 0 {
		return
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.actorRefCookies[actorID] == 0 {
		rt.ledger.ReleaseActor(actorID)
	}
}

// ActorContextIfUnreferenced returns the retained ExecutionContext for actorID
// when no live socket cookie currently references it.
func (rt *ProvenanceRuntime) ActorContextIfUnreferenced(actorID ActorIdentityKey) (ExecutionContext, bool) {
	if rt == nil || actorID.TGID == 0 {
		return ExecutionContext{}, false
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.actorRefCookies[actorID] != 0 {
		return ExecutionContext{}, false
	}
	snap, ok := rt.ledger.actors[actorID]
	if !ok || snap == nil || snap.socketRefs > 0 || snap.packetRefs > 0 {
		return ExecutionContext{}, false
	}
	return snap.Context, true
}

// UnreferencedActorContexts returns all retained actor ExecutionContexts that
// currently have zero live socket or packet references.
func (rt *ProvenanceRuntime) UnreferencedActorContexts() []ExecutionContext {
	if rt == nil {
		return nil
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	var out []ExecutionContext
	for actorID, snap := range rt.ledger.actors {
		if snap == nil || rt.actorRefCookies[actorID] != 0 || snap.socketRefs > 0 || snap.packetRefs > 0 {
			continue
		}
		out = append(out, snap.Context)
	}
	return out
}

func (rt *ProvenanceRuntime) TrackedCookieCount() int {
	if rt == nil {
		return 0
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return len(rt.cookies)
}

func (rt *ProvenanceRuntime) ActiveActorCount() int {
	if rt == nil {
		return 0
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return len(rt.ledger.actors)
}

// BeginCookieLiveSweep advances the runtime's sweep generation so callers can
// stream live socket cookies from netlink in small stack batches without
// allocating a live-cookie map or socketRow slice.
func (rt *ProvenanceRuntime) BeginCookieLiveSweep() uint32 {
	if rt == nil {
		return 0
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.liveSweepSeq++
	if rt.liveSweepSeq == 0 {
		for cookie, tc := range rt.cookies {
			tc.liveSweep = 0
			rt.cookies[cookie] = tc
		}
		rt.liveSweepSeq = 1
	}
	return rt.liveSweepSeq
}

// MarkCookiesLive marks any tracked cookies present in cookies as seen during
// sweep without allocating entries for untracked sockets.
func (rt *ProvenanceRuntime) MarkCookiesLive(cookies []uint64, sweep uint32) {
	if rt == nil || sweep == 0 || len(cookies) == 0 {
		return
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for _, cookie := range cookies {
		if tc, ok := rt.cookies[cookie]; ok && tc.liveSweep != sweep {
			tc.liveSweep = sweep
			rt.cookies[cookie] = tc
		}
	}
}

// CollectDeadCookies returns tracked cookies observed strictly before started
// that were not marked during sweep.
func (rt *ProvenanceRuntime) CollectDeadCookies(started time.Time, sweep uint32) []uint64 {
	if rt == nil || sweep == 0 {
		return nil
	}
	cutoff := monoSinceOrigin(started)
	rt.mu.Lock()
	defer rt.mu.Unlock()
	var dead []uint64
	for cookie, tc := range rt.cookies {
		if tc.observedMono >= cutoff {
			continue
		}
		if tc.liveSweep != sweep {
			dead = append(dead, cookie)
		}
	}
	return dead
}

// ReconcileLiveCookies returns tracked cookies observed strictly before started
// that are absent from live, ensuring missed netlink destroy notifications
// never leak socket slots, BPF actor rows, or retained snapshots.
func (rt *ProvenanceRuntime) ReconcileLiveCookies(started time.Time, live map[uint64]struct{}) []uint64 {
	if rt == nil {
		return nil
	}
	cutoff := monoSinceOrigin(started)
	rt.mu.Lock()
	defer rt.mu.Unlock()
	var dead []uint64
	for cookie, tc := range rt.cookies {
		if tc.observedMono >= cutoff {
			continue
		}
		if _, ok := live[cookie]; !ok {
			dead = append(dead, cookie)
		}
	}
	return dead
}

// SyncActors runs fn under rt.mu with access to the ledger and the compact
// socket-actor association tracker (which reports false on duplicate ActorKeys).
func (rt *ProvenanceRuntime) SyncActors(fn func(ledger *IdentityLedger, track func(key ActorKey, observedAt time.Time) bool)) {
	if rt == nil || fn == nil {
		return
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	fn(rt.ledger, rt.trackSocketActorLocked)
	rt.syncEpochPoisonedLocked()
}

func (rt *ProvenanceRuntime) RecordUserspaceSocket(cookie uint64) {
	if rt == nil || cookie == 0 {
		return
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.classifier.RecordUserspaceSocket(cookie)
}

func (rt *ProvenanceRuntime) RecordKernelControlSocket(ev KernelControlEvidence) {
	if rt == nil || ev.Cookie == 0 {
		return
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.classifier.RecordKernelControlSocket(ev)
}

// WithLedger runs fn under rt.mu with direct access to the underlying ledger
// and lazily-allocated processed-actor map (for full-map proof tests).
func (rt *ProvenanceRuntime) WithLedger(fn func(ledger *IdentityLedger, processed map[ActorKey]bool)) {
	if rt == nil || fn == nil {
		return
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.processed == nil {
		rt.processed = make(map[ActorKey]bool)
	}
	fn(rt.ledger, rt.processed)
	rt.syncEpochPoisonedLocked()
}

func (rt *ProvenanceRuntime) Metrics() (LedgerMetrics, SocketSlotMetrics, ClassifierMetrics) {
	if rt == nil {
		return LedgerMetrics{}, SocketSlotMetrics{}, ClassifierMetrics{}
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.ledger.Metrics(), rt.slots.Metrics(), rt.classifier.Metrics()
}

func (rt *ProvenanceRuntime) Close() error {
	if rt == nil {
		return nil
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.closed {
		return nil
	}
	rt.closed = true
	rt.epoch.Add(1)
	rt.epochPoisoned.Store(true)
	if rt.slots != nil {
		return rt.slots.Close()
	}
	return nil
}

// LookupLiveCookieOwner returns the retained socket-generation owner for cookie
// during periodic UDP SnapshotAt reconciliation without overwriting historical
// sender identity with a fresh /proc holder scan.
func (rt *ProvenanceRuntime) LookupLiveCookieOwner(cookie uint64) (platform.Owner, IdentityStatus, bool) {
	gen := FormatCookieGeneration(cookie)
	if rt == nil || cookie == 0 {
		return platform.Owner{Generation: gen}, IdentityUnknown, false
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.epochPoisoned.Load() || rt.slots == nil {
		return platform.Owner{Generation: gen}, IdentityUnknown, false
	}
	idx, ok := rt.slots.cookieToSlot[cookie]
	if !ok || int(idx) >= int(rt.slots.highWater) || int(idx) >= len(rt.slots.meta) || int(idx) >= len(rt.slots.slots) {
		return platform.Owner{Generation: gen}, IdentityUnknown, false
	}
	s := &rt.slots.slots[idx]
	m := &rt.slots.meta[idx]
	if !m.inUse {
		return platform.Owner{Generation: gen}, IdentityUnknown, false
	}
	v1 := atomic.LoadUint64(&s.Version)
	c1 := atomic.LoadUint64(&s.Conflicts)
	slotCookie := atomic.LoadUint64(&s.Cookie)
	rev := atomic.LoadUint64(&s.EvidenceRevision)
	flags := SocketSlotFlags(atomic.LoadUint32(&s.Flags))
	v2 := atomic.LoadUint64(&s.Version)
	c2 := atomic.LoadUint64(&s.Conflicts)
	if slotCookie != cookie {
		return platform.Owner{Generation: gen}, IdentityUnknown, false
	}
	if (flags&SocketSlotConflicting) != 0 || codeToReason(m.lastReasonCode) == ReasonConflictingApp {
		return platform.Owner{Generation: gen, Ambiguous: true}, IdentityConflicting, true
	}
	if v1 == v2 && v1 != 0 && c1 == 0 && c2 == 0 && (flags&SocketSlotValid) != 0 &&
		(flags&(SocketSlotIncomplete|SocketSlotPoisoned)) == 0 &&
		m.owner != nil && m.owner.EvidenceRevision == rev {
		return snapshotToOwnerWithGen(m.owner, gen), IdentityKnown, true
	}
	return platform.Owner{Generation: gen}, IdentityUnknown, true
}

func (rt *ProvenanceRuntime) releasePin(pin envelopePin) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.closed {
		return
	}
	fe := ForwardEnvelope{
		Identity:  PacketIdentityDecision{Snapshot: pin.snap},
		SlotIndex: pin.slotIndex,
		HasSlot:   pin.hasSlot,
		retained:  pin.retained,
	}
	rt.ledger.ReleaseEnvelope(&fe)
}

// AcquirePacket resolves a certified raw-read ReadDecision against the ledger
// and mmap socket-slot table, classifies verified kernel-control traffic when
// L3 bytes are supplied, and returns an immutable *ProvenanceEnvelope whose
// heap lifetime pins its IdentitySnapshot and SocketStateSlot via AddCleanup.
//
// When a single raw TUN read carries a GSO super-packet, callers pass that
// single returned *ProvenanceEnvelope pointer to every derived segment so all
// segments share the envelope without extra reference-count churn.
func (rt *ProvenanceRuntime) AcquirePacket(pkt []byte, readDec ReadDecision) *ProvenanceEnvelope {
	if rt == nil {
		return &ProvenanceEnvelope{
			Source:          ProvenanceSourcePacket,
			Status:          EnvelopeMissingCookie,
			ReadStatus:      readDec.Status,
			RebuildRequired: readDec.Rebuild,
			Reason:          ReasonPacketIncomplete,
		}
	}
	rt.mu.Lock()
	epoch := rt.epoch.Load()
	if readDec.Status == ReadCookie && !readDec.Rebuild && readDec.Packet.Cookie != 0 {
		if _, ok := rt.cookies[readDec.Packet.Cookie]; !ok {
			rt.cookies[readDec.Packet.Cookie] = trackedCookie{
				observedMono: monoSinceOrigin(time.Now()),
			}
		}
	}
	fwd := rt.ledger.ResolvePacketEnvelope(readDec)
	rt.syncEpochPoisonedLocked()
	var pktClass PacketClass
	if len(pkt) > 0 {
		pktClass = rt.classifier.Classify(pkt, fwd)
	}
	rt.mu.Unlock()

	env := &ProvenanceEnvelope{
		runtime:         rt,
		Source:          ProvenanceSourcePacket,
		Epoch:           epoch,
		ReadStatus:      readDec.Status,
		RebuildRequired: readDec.Rebuild,
		CaptureSerial:   readDec.Packet.Serial,
	}

	if readDec.Status != ReadCookie || readDec.Rebuild || readDec.Packet.Cookie == 0 {
		env.Status = EnvelopeMissingCookie
		env.Reason = ReasonPacketIncomplete
	} else {
		cookie := readDec.Packet.Cookie
		gen := FormatCookieGeneration(cookie)
		env.Cookie = cookie
		env.Generation = gen
		env.OwnerVersion = fwd.Identity.OwnerVersion
		env.slotIndex = fwd.SlotIndex
		env.slotGeneration = fwd.SlotGeneration
		env.hasSlot = fwd.HasSlot
		switch {
		case pktClass == PacketClassKernelControl:
			env.Status = EnvelopeKernelControl
			env.Owner = platform.Owner{Generation: gen}
			env.Reason = fwd.Identity.Reason
		case fwd.Identity.Status == IdentityKnown && fwd.Identity.Snapshot != nil:
			env.Status = EnvelopeKnown
			env.Owner = snapshotToOwnerWithGen(fwd.Identity.Snapshot, gen)
			env.EvidenceRevision = fwd.Identity.Snapshot.EvidenceRevision
			env.Reason = fwd.Identity.Reason
		case fwd.Identity.Status == IdentityConflicting:
			env.Status = EnvelopeConflicting
			env.Owner = platform.Owner{Generation: gen, Ambiguous: true}
			env.Reason = fwd.Identity.Reason
		default:
			env.Status = EnvelopeUnknownIdentity
			env.Owner = platform.Owner{Generation: gen}
			env.Reason = fwd.Identity.Reason
		}
	}

	if fwd.Identity.Snapshot != nil || fwd.retained {
		runtime.AddCleanup(env, rt.releasePin, envelopePin{
			snap:      fwd.Identity.Snapshot,
			slotIndex: fwd.SlotIndex,
			hasSlot:   fwd.HasSlot,
			retained:  fwd.retained,
		})
	}
	return env
}

func (rt *ProvenanceRuntime) Acquire(readDec ReadDecision) *ProvenanceEnvelope {
	return rt.AcquirePacket(nil, readDec)
}

// ProvenanceEnvelope is an immutable packet-provenance record attached to
// gVisor PacketBuffers, TCP ForwarderRequests, and queued UDP NAT datagrams.
type ProvenanceEnvelope struct {
	runtime          *ProvenanceRuntime
	pinAnchor        *ProvenanceEnvelope
	Source           string
	Epoch            uint64
	Status           EnvelopeStatus
	ReadStatus       ReadStatus
	RebuildRequired  bool
	Cookie           uint64
	Generation       string
	CaptureSerial    uint64
	OwnerVersion     uint64
	EvidenceRevision uint64
	Owner            platform.Owner
	Reason           IdentityReason
	FragmentsMerged  int
	acquireCostNanos uint64
	slotIndex        uint32
	slotGeneration   uint64
	hasSlot          bool
}

func (e *ProvenanceEnvelope) SetAcquireCost(d time.Duration) {
	if e == nil || d <= 0 {
		return
	}
	atomic.StoreUint64(&e.acquireCostNanos, uint64(d))
}

func (e *ProvenanceEnvelope) ProvenanceLookupCost() time.Duration {
	if e == nil {
		return 0
	}
	return time.Duration(atomic.SwapUint64(&e.acquireCostNanos, 0))
}

func (e *ProvenanceEnvelope) anchor() *ProvenanceEnvelope {
	if e == nil {
		return nil
	}
	if e.pinAnchor != nil {
		return e.pinAnchor
	}
	return e
}

// ValidateForwarding performs a lock-free, syscall-free coherent check of the
// pinned SocketStateSlot at the TCP admission or UDP datagram send-linearization
// point using the 5.8 (v1, c1) -> (cookie, gen, rev, flags) -> (v2, c2) rule.
func (e *ProvenanceEnvelope) ValidateForwarding() (platform.Owner, EnvelopeStatus) {
	if e == nil {
		return platform.Owner{}, EnvelopeMissingCookie
	}
	if e.runtime != nil {
		if e.runtime.epoch.Load() != e.Epoch {
			return platform.Owner{}, EnvelopeMissingCookie
		}
		if e.runtime.epochPoisoned.Load() {
			if e.Cookie == 0 {
				return platform.Owner{}, EnvelopeMissingCookie
			}
			return platform.Owner{Generation: e.Generation}, EnvelopeUnknownIdentity
		}
	}

	switch e.Status {
	case EnvelopeMissingCookie:
		return platform.Owner{}, EnvelopeMissingCookie
	case EnvelopeKernelControl:
		return platform.Owner{Generation: e.Generation}, EnvelopeKernelControl
	case EnvelopeConflicting:
		if !e.slotStillMatchesGeneration() {
			return platform.Owner{}, EnvelopeMissingCookie
		}
		return platform.Owner{Generation: e.Generation, Ambiguous: true}, EnvelopeConflicting
	case EnvelopeUnknownIdentity:
		if !e.slotStillMatchesGeneration() {
			return platform.Owner{}, EnvelopeMissingCookie
		}
		if e.slotHasConflict() {
			return platform.Owner{Generation: e.Generation, Ambiguous: true}, EnvelopeConflicting
		}
		return platform.Owner{Generation: e.Generation}, EnvelopeUnknownIdentity
	case EnvelopeKnown:
		if e.runtime == nil || e.runtime.slots == nil || !e.hasSlot || int(e.slotIndex) >= len(e.runtime.slots.slots) {
			return platform.Owner{Generation: e.Generation}, EnvelopeUnknownIdentity
		}
		s := &e.runtime.slots.slots[e.slotIndex]
		v1 := atomic.LoadUint64(&s.Version)
		c1 := atomic.LoadUint64(&s.Conflicts)
		cookie := atomic.LoadUint64(&s.Cookie)
		gen := atomic.LoadUint64(&s.SlotGeneration)
		rev := atomic.LoadUint64(&s.EvidenceRevision)
		flags := SocketSlotFlags(atomic.LoadUint32(&s.Flags))
		v2 := atomic.LoadUint64(&s.Version)
		c2 := atomic.LoadUint64(&s.Conflicts)

		if cookie != e.Cookie || gen != e.slotGeneration {
			return platform.Owner{}, EnvelopeMissingCookie
		}
		if c1 != 0 || c2 != 0 || (flags&SocketSlotConflicting) != 0 {
			return platform.Owner{Generation: e.Generation, Ambiguous: true}, EnvelopeConflicting
		}
		if v1 != v2 || v1 == 0 || v1 != e.OwnerVersion || rev != e.EvidenceRevision ||
			(flags&SocketSlotValid) == 0 || (flags&(SocketSlotIncomplete|SocketSlotPoisoned)) != 0 {
			return platform.Owner{Generation: e.Generation}, EnvelopeUnknownIdentity
		}
		return e.Owner, EnvelopeKnown
	default:
		return platform.Owner{}, EnvelopeMissingCookie
	}
}

func (e *ProvenanceEnvelope) slotStillMatchesGeneration() bool {
	if e == nil || e.Cookie == 0 {
		return false
	}
	if e.runtime == nil || e.runtime.slots == nil || !e.hasSlot {
		return true
	}
	if int(e.slotIndex) >= len(e.runtime.slots.slots) {
		return false
	}
	s := &e.runtime.slots.slots[e.slotIndex]
	return atomic.LoadUint64(&s.Cookie) == e.Cookie && atomic.LoadUint64(&s.SlotGeneration) == e.slotGeneration
}

func (e *ProvenanceEnvelope) slotHasConflict() bool {
	if e == nil || e.runtime == nil || e.runtime.slots == nil || !e.hasSlot || int(e.slotIndex) >= len(e.runtime.slots.slots) {
		return false
	}
	s := &e.runtime.slots.slots[e.slotIndex]
	return (SocketSlotFlags(atomic.LoadUint32(&s.Flags)) & SocketSlotConflicting) != 0
}

// NetSwitchMissingProvenance implements stack.NetSwitchMissingProvenanceProvider
// so reassembling a provenanced fragment with a nil-provenance peer produces an
// explicitebpf-packet missing-cookie envelope that never triggers scanner fallback.
func (e *ProvenanceEnvelope) NetSwitchMissingProvenance() any {
	epoch := uint64(0)
	merged := 1
	var cost uint64
	if e != nil {
		epoch = e.Epoch
		merged = e.FragmentsMerged + 1
		cost = uint64(e.ProvenanceLookupCost())
	}
	return &ProvenanceEnvelope{
		Source:           ProvenanceSourcePacket,
		Epoch:            epoch,
		Status:           EnvelopeMissingCookie,
		ReadStatus:       ReadMissing,
		Reason:           ReasonPacketIncomplete,
		FragmentsMerged:  merged,
		acquireCostNanos: cost,
	}
}

// MergeNetSwitchProvenance implements stack.NetSwitchProvenanceMerger for IPv4
// and IPv6 fragment reassembly inside gVisor. Known attribution survives only
// when all fragments share the same epoch, non-zero socket cookie, slot
// generation, owner version, and coherent non-conflicting AppID (their skb
// CaptureSerial values naturally differ).
func (e *ProvenanceEnvelope) MergeNetSwitchProvenance(other any) any {
	if e == nil {
		if o, ok := other.(*ProvenanceEnvelope); ok && o != nil {
			return o.NetSwitchMissingProvenance()
		}
		return &ProvenanceEnvelope{
			Source:          ProvenanceSourcePacket,
			Status:          EnvelopeMissingCookie,
			ReadStatus:      ReadMissing,
			Reason:          ReasonPacketIncomplete,
			FragmentsMerged: 1,
		}
	}
	o, ok := other.(*ProvenanceEnvelope)
	if !ok || o == nil {
		return e.NetSwitchMissingProvenance()
	}

	mergedCount := max(1, e.FragmentsMerged) + max(1, o.FragmentsMerged)
	mergedCost := uint64(e.ProvenanceLookupCost() + o.ProvenanceLookupCost())
	if e.Epoch == 0 || e.Epoch != o.Epoch ||
		e.Cookie == 0 || o.Cookie == 0 || e.Cookie != o.Cookie ||
		e.Status == EnvelopeMissingCookie || o.Status == EnvelopeMissingCookie {
		return &ProvenanceEnvelope{
			Source:           ProvenanceSourcePacket,
			Epoch:            e.Epoch,
			Status:           EnvelopeMissingCookie,
			ReadStatus:       ReadMissing,
			Reason:           ReasonPacketIncomplete,
			FragmentsMerged:  mergedCount,
			acquireCostNanos: mergedCost,
		}
	}

	ownerA, statusA := e.ValidateForwarding()
	ownerB, statusB := o.ValidateForwarding()
	if statusA == EnvelopeMissingCookie || statusB == EnvelopeMissingCookie {
		return &ProvenanceEnvelope{
			Source:           ProvenanceSourcePacket,
			Epoch:            e.Epoch,
			Status:           EnvelopeMissingCookie,
			ReadStatus:       ReadMissing,
			Reason:           ReasonPacketIncomplete,
			FragmentsMerged:  mergedCount,
			acquireCostNanos: mergedCost,
		}
	}

	anchor := e.anchor()
	if anchor == nil {
		anchor = o.anchor()
	}

	if statusA == EnvelopeKnown && statusB == EnvelopeKnown &&
		ownerA.AppID != "" && ownerA.AppID == ownerB.AppID &&
		e.hasSlot && o.hasSlot &&
		e.slotIndex == o.slotIndex &&
		e.slotGeneration == o.slotGeneration &&
		e.OwnerVersion == o.OwnerVersion {
		cp := *e
		cp.pinAnchor = anchor
		cp.FragmentsMerged = mergedCount
		cp.acquireCostNanos = mergedCost
		return &cp
	}

	if statusA == EnvelopeConflicting || statusB == EnvelopeConflicting ||
		(statusA == EnvelopeKnown && statusB == EnvelopeKnown && ownerA.AppID != ownerB.AppID) {
		return &ProvenanceEnvelope{
			runtime:          e.runtime,
			pinAnchor:        anchor,
			Source:           ProvenanceSourcePacket,
			Epoch:            e.Epoch,
			Status:           EnvelopeConflicting,
			ReadStatus:       ReadCookie,
			Cookie:           e.Cookie,
			Generation:       e.Generation,
			CaptureSerial:    e.CaptureSerial,
			Owner:            platform.Owner{Generation: e.Generation, Ambiguous: true},
			Reason:           ReasonConflictingApp,
			FragmentsMerged:  mergedCount,
			acquireCostNanos: mergedCost,
			slotIndex:        e.slotIndex,
			slotGeneration:   e.slotGeneration,
			hasSlot:          e.hasSlot,
		}
	}

	if statusA == EnvelopeKernelControl && statusB == EnvelopeKernelControl {
		return &ProvenanceEnvelope{
			runtime:          e.runtime,
			pinAnchor:        anchor,
			Source:           ProvenanceSourcePacket,
			Epoch:            e.Epoch,
			Status:           EnvelopeKernelControl,
			ReadStatus:       ReadCookie,
			Cookie:           e.Cookie,
			Generation:       e.Generation,
			CaptureSerial:    e.CaptureSerial,
			Owner:            platform.Owner{Generation: e.Generation},
			Reason:           e.Reason,
			FragmentsMerged:  mergedCount,
			acquireCostNanos: mergedCost,
			slotIndex:        e.slotIndex,
			slotGeneration:   e.slotGeneration,
			hasSlot:          e.hasSlot,
		}
	}

	return &ProvenanceEnvelope{
		runtime:          e.runtime,
		pinAnchor:        anchor,
		Source:           ProvenanceSourcePacket,
		Epoch:            e.Epoch,
		Status:           EnvelopeUnknownIdentity,
		ReadStatus:       ReadCookie,
		Cookie:           e.Cookie,
		Generation:       e.Generation,
		CaptureSerial:    e.CaptureSerial,
		Owner:            platform.Owner{Generation: e.Generation},
		Reason:           ReasonPacketIncomplete,
		FragmentsMerged:  mergedCount,
		acquireCostNanos: mergedCost,
		slotIndex:        e.slotIndex,
		slotGeneration:   e.slotGeneration,
		hasSlot:          e.hasSlot,
	}
}
