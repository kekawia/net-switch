package ownerbpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"syscall"
	"unsafe"
)

const (
	DefaultMaxSocketSlots       = 4096
	DefaultMaxFragmentedPackets = 256
	DefaultMaxFragmentBytes     = 1 << 20
	MaxIPv6ExtensionHeaders     = 8
	VirtioNetHdrLen             = 10
)

const (
	VirtioNetHdrFNeedsCsum = 1
	VirtioNetHdrGSONone    = 0
	VirtioNetHdrGSOTCPv4   = 1
	VirtioNetHdrGSOUDP     = 3
	VirtioNetHdrGSOTCPv6   = 4
	VirtioNetHdrGSOUDPL4   = 5
	VirtioNetHdrGSOECN     = 0x80
)

type SocketSlotFlags uint32

const (
	SocketSlotNone        SocketSlotFlags = 0
	SocketSlotValid       SocketSlotFlags = 1 << 0
	SocketSlotIncomplete  SocketSlotFlags = 1 << 1
	SocketSlotConflicting SocketSlotFlags = 1 << 2
	SocketSlotDestroyed   SocketSlotFlags = 1 << 3
	SocketSlotPoisoned    SocketSlotFlags = 1 << 4
)

// SocketStateSlot is the 64-byte cache-line-aligned per-socket-generation state
// cell shared via a BPF_F_MMAPABLE array map (or aligned slice in unit tests).
// All 64-bit counters sit at 8-byte-aligned offsets for atomic XADD/load access.
type SocketStateSlot struct {
	Cookie           uint64
	SlotGeneration   uint64
	Version          uint64
	Conflicts        uint64
	EvidenceRevision uint64
	Flags            uint32
	Reserved         uint32
	Pad              [2]uint64
}

var (
	_ [64 - unsafe.Sizeof(SocketStateSlot{})]byte
	_ [unsafe.Sizeof(SocketStateSlot{}) - 64]byte
)

type stagedCorkContributor struct {
	actorKey ActorIdentityKey
	snap     *IdentitySnapshot
	reason   IdentityReason
}

type socketSlotMeta struct {
	inUse          bool
	socketAlive    bool
	envelopeRefs   int
	owner          *IdentitySnapshot
	lastReason     IdentityReason
	contributors   map[ActorIdentityKey]IdentityReason
	stagedCork     []stagedCorkContributor
	corkCommitted  bool
}

type SocketSlotMetrics struct {
	ActiveSlots      int
	LiveSockets      int
	RetainedSlots    int
	AllocatedTotal   uint64
	ReclaimedTotal   uint64
	Refusals         uint64
	ConflictUpdates  uint64
	WrapPoisons      uint64
	FailedSends      uint64
	CorkFlushes      uint64
	CorkDiscards     uint64
	EpochPoisoned    bool
}

// SocketSlotTable manages bounded per-socket-generation state slots and enforces
// the 5.8 conflict/version publication order (conflicts += 1 first, then version += 1)
// and envelope-pinned reclamation after socket destruction.
type SocketSlotTable struct {
	MaxSlots       int
	slots          []SocketStateSlot
	meta           []socketSlotMeta
	cookieToSlot   map[uint64]uint32
	freeSlots      []uint32
	nextGeneration uint64
	metrics        SocketSlotMetrics
	closeFn        func() error
}

func NewSocketSlotTable(maxSlots int) *SocketSlotTable {
	if maxSlots <= 0 {
		maxSlots = DefaultMaxSocketSlots
	}
	slots := make([]SocketStateSlot, maxSlots)
	return newSocketSlotTableFromBacking(slots, nil)
}

func newSocketSlotTableFromBacking(slots []SocketStateSlot, closeFn func() error) *SocketSlotTable {
	maxSlots := len(slots)
	free := make([]uint32, maxSlots)
	for i := 0; i < maxSlots; i++ {
		free[i] = uint32(maxSlots - 1 - i)
	}
	return &SocketSlotTable{
		MaxSlots:     maxSlots,
		slots:        slots,
		meta:         make([]socketSlotMeta, maxSlots),
		cookieToSlot: make(map[uint64]uint32, maxSlots),
		freeSlots:    free,
		closeFn:      closeFn,
	}
}

func (t *SocketSlotTable) Close() error {
	if t == nil || t.closeFn == nil {
		return nil
	}
	fn := t.closeFn
	t.closeFn = nil
	return fn()
}

func (t *SocketSlotTable) Metrics() SocketSlotMetrics {
	if t == nil {
		return SocketSlotMetrics{}
	}
	m := t.metrics
	active := 0
	live := 0
	retained := 0
	for i := range t.meta {
		if !t.meta[i].inUse {
			continue
		}
		active++
		if t.meta[i].socketAlive {
			live++
		} else if t.meta[i].envelopeRefs > 0 {
			retained++
		}
	}
	m.ActiveSlots = active
	m.LiveSockets = live
	m.RetainedSlots = retained
	return m
}

func (t *SocketSlotTable) SlotSnapshot(cookie uint64) (SocketStateSlot, uint32, bool) {
	if t == nil || cookie == 0 {
		return SocketStateSlot{}, 0, false
	}
	idx, ok := t.cookieToSlot[cookie]
	if !ok {
		return SocketStateSlot{}, 0, false
	}
	s := &t.slots[idx]
	return SocketStateSlot{
		Cookie:           atomic.LoadUint64(&s.Cookie),
		SlotGeneration:   atomic.LoadUint64(&s.SlotGeneration),
		Version:          atomic.LoadUint64(&s.Version),
		Conflicts:        atomic.LoadUint64(&s.Conflicts),
		EvidenceRevision: atomic.LoadUint64(&s.EvidenceRevision),
		Flags:            atomic.LoadUint32(&s.Flags),
	}, idx, true
}

// ForceCountersForTest sets a slot's version and conflict counters directly to
// exercise 64-bit wrap-around poisoning without spinning 2^64 times.
func (t *SocketSlotTable) ForceCountersForTest(cookie, version, conflicts uint64) bool {
	if t == nil || cookie == 0 {
		return false
	}
	idx, ok := t.cookieToSlot[cookie]
	if !ok {
		return false
	}
	s := &t.slots[idx]
	atomic.StoreUint64(&s.Version, version)
	atomic.StoreUint64(&s.Conflicts, conflicts)
	return true
}

func (t *SocketSlotTable) ensureSlot(cookie uint64) (uint32, bool) {
	if cookie == 0 || t.metrics.EpochPoisoned {
		return 0, false
	}
	if idx, ok := t.cookieToSlot[cookie]; ok {
		return idx, true
	}
	if len(t.freeSlots) == 0 {
		t.metrics.Refusals++
		return 0, false
	}
	if t.nextGeneration == ^uint64(0) {
		t.metrics.EpochPoisoned = true
		t.metrics.WrapPoisons++
		return 0, false
	}
	t.nextGeneration++
	gen := t.nextGeneration
	idx := t.freeSlots[len(t.freeSlots)-1]
	t.freeSlots = t.freeSlots[:len(t.freeSlots)-1]

	s := &t.slots[idx]
	atomic.StoreUint64(&s.Cookie, cookie)
	atomic.StoreUint64(&s.SlotGeneration, gen)
	atomic.StoreUint64(&s.Version, 0)
	atomic.StoreUint64(&s.Conflicts, 0)
	atomic.StoreUint64(&s.EvidenceRevision, 0)
	atomic.StoreUint32(&s.Flags, uint32(SocketSlotNone))

	t.meta[idx] = socketSlotMeta{
		inUse:        true,
		socketAlive:  true,
		contributors: make(map[ActorIdentityKey]IdentityReason),
	}
	t.cookieToSlot[cookie] = idx
	t.metrics.AllocatedTotal++
	return idx, true
}

func (t *SocketSlotTable) checkAndPoisonWrap(s *SocketStateSlot) bool {
	if atomic.LoadUint64(&s.Version) == ^uint64(0) || atomic.LoadUint64(&s.Conflicts) == ^uint64(0) {
		t.metrics.EpochPoisoned = true
		t.metrics.WrapPoisons++
		oldFlags := SocketSlotFlags(atomic.LoadUint32(&s.Flags))
		atomic.StoreUint32(&s.Flags, uint32((oldFlags&^SocketSlotValid)|SocketSlotPoisoned))
		return true
	}
	return false
}

// publishContributor applies one accepted send contribution to the socket slot
// following the 5.8 XADD publication order:
//   - On conflict or incomplete identity: XADD conflicts += 1 first, then XADD version += 1.
//   - On first complete owner: store immutable owner/revision, then XADD version += 1.
//   - Incomplete first identity is never promoted in place by a subsequent contributor.
func (t *SocketSlotTable) publishContributor(ledger *IdentityLedger, cookie uint64, actorKey ActorIdentityKey, snap *IdentitySnapshot, reason IdentityReason) bool {
	idx, ok := t.ensureSlot(cookie)
	if !ok {
		return false
	}
	s := &t.slots[idx]
	m := &t.meta[idx]
	if !m.socketAlive {
		// Late contribution after socket close cannot promote a destroyed slot.
		return false
	}
	if t.checkAndPoisonWrap(s) {
		return false
	}
	if actorKey != (ActorIdentityKey{}) {
		m.contributors[actorKey] = reason
	}

	flags := SocketSlotFlags(atomic.LoadUint32(&s.Flags))
	curVersion := atomic.LoadUint64(&s.Version)
	curConflicts := atomic.LoadUint64(&s.Conflicts)

	if snap == nil {
		if m.owner != nil {
			if ledger != nil {
				ledger.decrementSocketRef(m.owner)
			}
			m.owner = nil
		}
		newFlags := (flags &^ SocketSlotValid) | SocketSlotIncomplete | SocketSlotConflicting
		atomic.StoreUint32(&s.Flags, uint32(newFlags))
		atomic.StoreUint64(&s.EvidenceRevision, 0)
		// 5.8 XADD order: conflicts += 1 first, then version += 1.
		atomic.AddUint64(&s.Conflicts, 1)
		atomic.AddUint64(&s.Version, 1)
		t.metrics.ConflictUpdates++
		if m.lastReason == "" || m.lastReason == ReasonValidated || m.lastReason == ReasonInheritedValidated {
			m.lastReason = reason
		}
		return true
	}

	// An incomplete or conflicting socket generation never promotes back to known.
	if curConflicts > 0 || (flags&(SocketSlotIncomplete|SocketSlotConflicting|SocketSlotPoisoned)) != 0 {
		atomic.AddUint64(&s.Conflicts, 1)
		atomic.AddUint64(&s.Version, 1)
		t.metrics.ConflictUpdates++
		return true
	}

	if m.owner == nil && curVersion == 0 {
		snap.socketRefs++
		m.owner = snap
		m.lastReason = snap.Reason
		atomic.StoreUint64(&s.EvidenceRevision, snap.EvidenceRevision)
		atomic.StoreUint32(&s.Flags, uint32((flags&^SocketSlotNone)|SocketSlotValid))
		atomic.AddUint64(&s.Version, 1)
		return true
	}

	if m.owner != nil && m.owner.AppID == snap.AppID {
		return true
	}

	if m.owner != nil && ledger != nil {
		ledger.decrementSocketRef(m.owner)
	}
	m.owner = nil
	m.lastReason = ReasonConflictingApp
	atomic.StoreUint64(&s.EvidenceRevision, 0)
	atomic.StoreUint32(&s.Flags, uint32((flags&^SocketSlotValid)|SocketSlotConflicting))
	// 5.8 XADD order: conflicts += 1 first, then version += 1.
	atomic.AddUint64(&s.Conflicts, 1)
	atomic.AddUint64(&s.Version, 1)
	t.metrics.ConflictUpdates++
	return true
}

func (t *SocketSlotTable) tryReclaimSlot(ledger *IdentityLedger, idx uint32) {
	if int(idx) >= len(t.meta) {
		return
	}
	m := &t.meta[idx]
	if !m.inUse || m.socketAlive || m.envelopeRefs > 0 {
		return
	}
	s := &t.slots[idx]
	cookie := atomic.LoadUint64(&s.Cookie)
	if m.owner != nil {
		if ledger != nil {
			ledger.decrementSocketRef(m.owner)
		}
		m.owner = nil
	}
	delete(t.cookieToSlot, cookie)
	atomic.StoreUint64(&s.Cookie, 0)
	atomic.StoreUint64(&s.SlotGeneration, 0)
	atomic.StoreUint64(&s.Version, 0)
	atomic.StoreUint64(&s.Conflicts, 0)
	atomic.StoreUint64(&s.EvidenceRevision, 0)
	atomic.StoreUint32(&s.Flags, 0)
	*m = socketSlotMeta{}
	t.freeSlots = append(t.freeSlots, idx)
	t.metrics.ReclaimedTotal++
}

// ForwardEnvelope carries a packet's certified bridge ReadDecision, its initial
// socket-slot identity decision, and a reference pin on the socket slot and
// identity snapshot until the packet is forwarded or dropped.
type ForwardEnvelope struct {
	Read           ReadDecision
	Identity       PacketIdentityDecision
	SlotIndex      uint32
	SlotGeneration uint64
	HasSlot        bool
	retained       bool
}

// AttachSlotTable binds a SocketSlotTable (such as a BPF_F_MMAPABLE array map)
// to the IdentityLedger so every actor enrichment, warm send, fork inheritance,
// packet resolution, and socket release operates on bounded mmap-compatible slots.
func (l *IdentityLedger) AttachSlotTable(table *SocketSlotTable) {
	l.slotTable = table
}

func (l *IdentityLedger) SlotTable() *SocketSlotTable {
	return l.slotTable
}

// ObserveFailedSend records a failed send syscall (such as EMSGSIZE, EDESTADDRREQ,
// EINVAL, or ENETUNREACH) that contributed no payload to any emitted packet.
// Failed sends never claim ownership on an unused socket and never poison an
// already-owned socket generation.
func (l *IdentityLedger) ObserveFailedSend(cookie uint64, _ ActorKey) {
	if l.slotTable != nil {
		l.slotTable.metrics.FailedSends++
	}
	_ = cookie
}

// StageCorkContributor stages a corked write contribution (UDP_CORK / MSG_MORE)
// on cookie without emitting a packet yet. If corked data is later flushed via
// FlushCork, all staged contributors are applied to the socket generation. If
// aborted via DiscardCork before any datagram is emitted on an unused socket,
// no ownership is claimed.
func (l *IdentityLedger) StageCorkContributor(key ActorKey, ev ActorEvidence, mat RawProcessMaterial) (*IdentitySnapshot, IdentityReason) {
	if key.Cookie == 0 {
		return nil, ReasonIdentityUnretained
	}
	// Enrich the actor snapshot without mutating the socket generation until FlushCork.
	snap, reason := l.enrichActorSnapshotOnly(key, ev, mat)
	if l.slotTable == nil {
		l.AttachSlotTable(NewSocketSlotTable(DefaultMaxSocketSlots))
	}
	idx, ok := l.slotTable.ensureSlot(key.Cookie)
	if !ok {
		l.recordFailureMetric(ReasonBudgetExceeded)
		return nil, ReasonBudgetExceeded
	}
	m := &l.slotTable.meta[idx]
	actorID := ActorIdentityKey{TGID: key.TGID, StartBoottime: key.Start, ExecID: key.Exec}
	m.stagedCork = append(m.stagedCork, stagedCorkContributor{
		actorKey: actorID,
		snap:     snap,
		reason:   reason,
	})
	return snap, reason
}

// DiscardCork discards uncommitted corked writes (e.g. when a corked send fails
// and the cork buffer is flushed empty without transmitting a packet). If the
// socket had no prior committed owner, the slot remains unclaimed.
func (l *IdentityLedger) DiscardCork(cookie uint64) {
	if l.slotTable == nil || cookie == 0 {
		return
	}
	idx, ok := l.slotTable.cookieToSlot[cookie]
	if !ok {
		return
	}
	m := &l.slotTable.meta[idx]
	m.stagedCork = nil
	l.slotTable.metrics.CorkDiscards++
	s := &l.slotTable.slots[idx]
	if !m.corkCommitted && atomic.LoadUint64(&s.Version) == 0 && atomic.LoadUint64(&s.Conflicts) == 0 && m.envelopeRefs == 0 {
		m.socketAlive = false
		l.slotTable.tryReclaimSlot(l, idx)
	}
}

// FlushCork commits all staged cork contributors on cookie when the corked
// datagram is actually constructed for transmission.
func (l *IdentityLedger) FlushCork(cookie uint64) bool {
	if l.slotTable == nil || cookie == 0 {
		return false
	}
	idx, ok := l.slotTable.cookieToSlot[cookie]
	if !ok {
		return false
	}
	m := &l.slotTable.meta[idx]
	if len(m.stagedCork) == 0 {
		return false
	}
	staged := m.stagedCork
	m.stagedCork = nil
	m.corkCommitted = true
	l.slotTable.metrics.CorkFlushes++
	for _, c := range staged {
		l.applyContributor(cookie, c.actorKey, c.snap, c.reason)
	}
	return true
}

// ResolvePacketEnvelope resolves a certified bridge ReadDecision against the
// IdentityLedger and SocketSlotTable and pins the socket slot + snapshot in a
// ForwardEnvelope until ReleaseEnvelope is called.
func (l *IdentityLedger) ResolvePacketEnvelope(readDec ReadDecision) ForwardEnvelope {
	if l.slotTable != nil && l.slotTable.metrics.EpochPoisoned {
		l.metrics.UnknownPackets++
		l.metrics.BudgetExceeded++
		return ForwardEnvelope{
			Read: readDec,
			Identity: PacketIdentityDecision{
				Status: IdentityUnknown,
				Reason: ReasonBudgetExceeded,
			},
		}
	}
	dec := l.ResolvePacket(readDec)
	env := ForwardEnvelope{
		Read:     readDec,
		Identity: dec,
	}
	if l.slotTable != nil && readDec.Status == ReadCookie && !readDec.Rebuild && readDec.Packet.Cookie != 0 {
		if idx, ok := l.slotTable.cookieToSlot[readDec.Packet.Cookie]; ok {
			s := &l.slotTable.slots[idx]
			m := &l.slotTable.meta[idx]
			env.SlotIndex = idx
			env.SlotGeneration = atomic.LoadUint64(&s.SlotGeneration)
			env.HasSlot = true
			env.retained = true
			m.envelopeRefs++
		}
	}
	return env
}

// CloneEnvelope duplicates a ForwardEnvelope (for example across GSO segments
// derived from a single certified raw TUN read) and increments reference counts
// on both the socket slot and the identity snapshot.
func (l *IdentityLedger) CloneEnvelope(env ForwardEnvelope) ForwardEnvelope {
	cloned := env
	if cloned.Identity.Snapshot != nil {
		cloned.Identity.Snapshot.packetRefs++
	}
	if cloned.HasSlot && l.slotTable != nil && int(cloned.SlotIndex) < len(l.slotTable.meta) {
		m := &l.slotTable.meta[cloned.SlotIndex]
		if m.inUse {
			m.envelopeRefs++
			cloned.retained = true
		}
	}
	return cloned
}

// ValidateForwardingEnvelope re-reads the socket state slot at the forwarding
// decision using the coherent (v1, c1) -> owner -> (v2, c2) check and verifies:
//   - v1 == v2 && v1 != 0 && c1 == 0 && c2 == 0
//   - slot.Cookie == env.Identity.Cookie
//   - slot.SlotGeneration == env.SlotGeneration
//   - v1 == env.Identity.OwnerVersion
//
// Even-numbered version values are rejected whenever conflicts > 0 or
// v1 != env.Identity.OwnerVersion; this is not an odd/even seqlock.
func (l *IdentityLedger) ValidateForwardingEnvelope(env ForwardEnvelope) PacketIdentityDecision {
	if l.slotTable != nil && l.slotTable.metrics.EpochPoisoned {
		return PacketIdentityDecision{
			Status: IdentityUnknown,
			Reason: ReasonBudgetExceeded,
			Cookie: env.Identity.Cookie,
		}
	}
	if env.Read.Status != ReadCookie || env.Read.Rebuild || env.Identity.Cookie == 0 {
		return PacketIdentityDecision{
			Status: IdentityUnknown,
			Reason: ReasonPacketIncomplete,
		}
	}
	if l.slotTable == nil {
		st, ok := l.sockets[env.Identity.Cookie]
		if !ok {
			return PacketIdentityDecision{
				Status: IdentityUnknown,
				Reason: ReasonIdentityUnretained,
				Cookie: env.Identity.Cookie,
			}
		}
		v1, c1 := st.Version, st.Conflicts
		owner := st.Owner
		v2, c2 := st.Version, st.Conflicts
		if v1 != v2 || v1 == 0 || c1 != 0 || c2 != 0 || owner == nil || v1 != env.Identity.OwnerVersion {
			status := IdentityUnknown
			reason := st.LastReason
			if reason == ReasonConflictingApp || c2 > 0 {
				status = IdentityConflicting
				reason = ReasonConflictingApp
			} else if reason == "" {
				reason = ReasonIdentityUnretained
			}
			return PacketIdentityDecision{
				Status:       status,
				Reason:       reason,
				Cookie:       env.Identity.Cookie,
				OwnerVersion: v2,
				Conflicts:    c2,
			}
		}
		return env.Identity
	}

	if !env.HasSlot || int(env.SlotIndex) >= len(l.slotTable.slots) {
		return PacketIdentityDecision{
			Status: IdentityUnknown,
			Reason: ReasonIdentityUnretained,
			Cookie: env.Identity.Cookie,
		}
	}
	s := &l.slotTable.slots[env.SlotIndex]
	m := &l.slotTable.meta[env.SlotIndex]
	if !m.inUse {
		return PacketIdentityDecision{
			Status: IdentityUnknown,
			Reason: ReasonIdentityUnretained,
			Cookie: env.Identity.Cookie,
		}
	}

	v1 := atomic.LoadUint64(&s.Version)
	c1 := atomic.LoadUint64(&s.Conflicts)
	cookie := atomic.LoadUint64(&s.Cookie)
	gen := atomic.LoadUint64(&s.SlotGeneration)
	rev := atomic.LoadUint64(&s.EvidenceRevision)
	flags := SocketSlotFlags(atomic.LoadUint32(&s.Flags))
	owner := m.owner
	lastReason := m.lastReason
	v2 := atomic.LoadUint64(&s.Version)
	c2 := atomic.LoadUint64(&s.Conflicts)

	if cookie != env.Identity.Cookie || gen != env.SlotGeneration {
		return PacketIdentityDecision{
			Status: IdentityUnknown,
			Reason: ReasonContextChanged,
			Cookie: env.Identity.Cookie,
		}
	}
	if v1 != v2 || v1 == 0 || c1 != 0 || c2 != 0 ||
		v1 != env.Identity.OwnerVersion ||
		(flags&SocketSlotValid) == 0 ||
		(flags&(SocketSlotIncomplete|SocketSlotConflicting|SocketSlotPoisoned)) != 0 ||
		owner == nil || owner.EvidenceRevision != rev ||
		env.Identity.Status != IdentityKnown {
		status := IdentityUnknown
		reason := lastReason
		if reason == ReasonConflictingApp || (flags&SocketSlotConflicting) != 0 && reason == "" {
			if lastReason == ReasonConflictingApp {
				status = IdentityConflicting
				reason = ReasonConflictingApp
			}
		}
		if lastReason == ReasonConflictingApp {
			status = IdentityConflicting
			reason = ReasonConflictingApp
		} else if reason == "" || reason == ReasonValidated || reason == ReasonInheritedValidated {
			reason = ReasonIdentityUnretained
		}
		return PacketIdentityDecision{
			Status:       status,
			Reason:       reason,
			Cookie:       cookie,
			OwnerVersion: v2,
			Conflicts:    c2,
		}
	}
	return PacketIdentityDecision{
		Status:       IdentityKnown,
		Reason:       owner.Reason,
		Cookie:       cookie,
		OwnerVersion: v1,
		Conflicts:    0,
		Snapshot:     owner,
	}
}

// ReleaseEnvelope releases the packet's reference on its IdentitySnapshot and
// its pin on the SocketStateSlot. If the socket was already destroyed and this
// was the last queued envelope, the slot is reclaimed immediately.
func (l *IdentityLedger) ReleaseEnvelope(env *ForwardEnvelope) {
	if env == nil {
		return
	}
	if env.Identity.Snapshot != nil {
		l.ReleasePacket(env.Identity.Snapshot)
		env.Identity.Snapshot = nil
	}
	if env.retained && env.HasSlot && l.slotTable != nil && int(env.SlotIndex) < len(l.slotTable.meta) {
		m := &l.slotTable.meta[env.SlotIndex]
		if m.envelopeRefs > 0 {
			m.envelopeRefs--
		}
		env.retained = false
		l.slotTable.tryReclaimSlot(l, env.SlotIndex)
	}
}

// PacketHeaderSummary describes the parsed L3/fragment/extension-header layout
// of an IPv4 or IPv6 packet without trusting L4 ports on non-first fragments.
type PacketHeaderSummary struct {
	Version             uint8
	NextHeader          uint8
	HasExtensionHeaders bool
	ExtensionCount      int
	IsFragment          bool
	MoreFragments       bool
	FragmentOffset      uint16
	Identification      uint32
	PayloadOffset       int
	PayloadLength       int
	Src                 netip.Addr
	Dst                 netip.Addr
}

func isIPv6ExtensionHeader(nh uint8) bool {
	switch nh {
	case 0, 43, 44, 51, 60:
		return true
	default:
		return false
	}
}

// InspectPacketHeader parses IPv4 and IPv6 headers, walking any IPv6 extension
// headers (Hop-by-Hop, Routing, Fragment, AH, Destination Options) without
// assuming transport ports sit at a fixed offset or exist on non-first fragments.
func InspectPacketHeader(pkt []byte) (PacketHeaderSummary, error) {
	if len(pkt) < 20 {
		return PacketHeaderSummary{}, errors.New("packet shorter than minimum L3 header")
	}
	ver := pkt[0] >> 4
	switch ver {
	case 4:
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl {
			return PacketHeaderSummary{}, errors.New("invalid IPv4 IHL")
		}
		totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
		if totalLen < ihl || totalLen > len(pkt) {
			return PacketHeaderSummary{}, errors.New("invalid IPv4 total length")
		}
		id := uint32(binary.BigEndian.Uint16(pkt[4:6]))
		flagsFrag := binary.BigEndian.Uint16(pkt[6:8])
		mf := (flagsFrag & 0x2000) != 0
		fragOff := (flagsFrag & 0x1fff) * 8
		src, _ := netip.AddrFromSlice(pkt[12:16])
		dst, _ := netip.AddrFromSlice(pkt[16:20])
		return PacketHeaderSummary{
			Version:             4,
			NextHeader:          pkt[9],
			HasExtensionHeaders: ihl > 20,
			IsFragment:          mf || fragOff > 0,
			MoreFragments:       mf,
			FragmentOffset:      fragOff,
			Identification:      id,
			PayloadOffset:       ihl,
			PayloadLength:       totalLen - ihl,
			Src:                 src,
			Dst:                 dst,
		}, nil

	case 6:
		if len(pkt) < 40 {
			return PacketHeaderSummary{}, errors.New("packet shorter than IPv6 header")
		}
		payloadLen := int(binary.BigEndian.Uint16(pkt[4:6]))
		totalLen := 40 + payloadLen
		if totalLen > len(pkt) {
			return PacketHeaderSummary{}, errors.New("invalid IPv6 payload length")
		}
		src, _ := netip.AddrFromSlice(pkt[8:24])
		dst, _ := netip.AddrFromSlice(pkt[24:40])
		nh := pkt[6]
		offset := 40
		extCount := 0
		var isFrag, mf bool
		var fragOff uint16
		var fragID uint32

		for isIPv6ExtensionHeader(nh) {
			if extCount >= MaxIPv6ExtensionHeaders {
				return PacketHeaderSummary{}, errors.New("IPv6 extension header chain exceeds limit")
			}
			extCount++
			if nh == 44 {
				// IPv6 Fragment Header (fixed 8 bytes).
				if offset+8 > totalLen {
					return PacketHeaderSummary{}, errors.New("truncated IPv6 fragment header")
				}
				nextNH := pkt[offset]
				offFlags := binary.BigEndian.Uint16(pkt[offset+2 : offset+4])
				fragOff = offFlags & 0xfff8
				mf = (offFlags & 0x0001) != 0
				fragID = binary.BigEndian.Uint32(pkt[offset+4 : offset+8])
				isFrag = true
				nh = nextNH
				offset += 8
				break
			}
			if offset+2 > totalLen {
				return PacketHeaderSummary{}, errors.New("truncated IPv6 extension header")
			}
			nextNH := pkt[offset]
			var hdrBytes int
			if nh == 51 {
				// Authentication Header length is in 4-byte words minus 2.
				hdrBytes = (int(pkt[offset+1]) + 2) * 4
			} else {
				// Standard IPv6 extension header length is in 8-byte units not including the first 8 bytes.
				hdrBytes = (int(pkt[offset+1]) + 1) * 8
			}
			if hdrBytes < 8 || offset+hdrBytes > totalLen {
				return PacketHeaderSummary{}, errors.New("invalid IPv6 extension header length")
			}
			nh = nextNH
			offset += hdrBytes
		}

		return PacketHeaderSummary{
			Version:             6,
			NextHeader:          nh,
			HasExtensionHeaders: extCount > 0,
			ExtensionCount:      extCount,
			IsFragment:          isFrag,
			MoreFragments:       mf,
			FragmentOffset:      fragOff,
			Identification:      fragID,
			PayloadOffset:       offset,
			PayloadLength:       totalLen - offset,
			Src:                 src,
			Dst:                 dst,
		}, nil

	default:
		return PacketHeaderSummary{}, fmt.Errorf("unsupported IP version %d", ver)
	}
}

type fragmentKey struct {
	version    uint8
	nextHeader uint8
	id         uint32
	src        netip.Addr
	dst        netip.Addr
}

type fragmentPiece struct {
	offset  int
	end     int
	payload []byte
	env     ForwardEnvelope
}

type fragmentAssembly struct {
	headerPrefix []byte
	pieces       []fragmentPiece
	totalLen     int
	haveTail     bool
	bytesStored  int
}

// FragmentReassembler reassembles IPv4 and IPv6 fragments (in-order and
// out-of-order) under bounded memory and merges per-fragment ForwardEnvelopes
// conservatively: the reassembled packet is IdentityKnown only if every
// constituent fragment is IdentityKnown with matching Cookie, OwnerVersion,
// SlotGeneration, and AppID.
type FragmentReassembler struct {
	MaxAssemblies int
	MaxBytes      int
	usedBytes     int
	assemblies    map[fragmentKey]*fragmentAssembly
}

func NewFragmentReassembler(maxAssemblies, maxBytes int) *FragmentReassembler {
	if maxAssemblies <= 0 {
		maxAssemblies = DefaultMaxFragmentedPackets
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxFragmentBytes
	}
	return &FragmentReassembler{
		MaxAssemblies: maxAssemblies,
		MaxBytes:      maxBytes,
		assemblies:    make(map[fragmentKey]*fragmentAssembly),
	}
}

func (r *FragmentReassembler) ActiveAssemblies() int {
	return len(r.assemblies)
}

func (r *FragmentReassembler) UsedBytes() int {
	return r.usedBytes
}

func (r *FragmentReassembler) Ingest(ledger *IdentityLedger, pkt []byte, env ForwardEnvelope) ([]byte, ForwardEnvelope, bool, error) {
	hdr, err := InspectPacketHeader(pkt)
	if err != nil {
		return nil, ForwardEnvelope{}, false, err
	}
	if !hdr.IsFragment {
		return append([]byte(nil), pkt...), env, true, nil
	}
	if hdr.PayloadLength <= 0 {
		return nil, ForwardEnvelope{}, false, errors.New("empty IP fragment payload")
	}
	if hdr.MoreFragments && (hdr.PayloadLength%8) != 0 {
		return nil, ForwardEnvelope{}, false, errors.New("non-tail IP fragment payload is not a multiple of 8 bytes")
	}

	key := fragmentKey{
		version:    hdr.Version,
		nextHeader: hdr.NextHeader,
		id:         hdr.Identification,
		src:        hdr.Src,
		dst:        hdr.Dst,
	}
	asm, exists := r.assemblies[key]
	if !exists {
		if len(r.assemblies) >= r.MaxAssemblies {
			return nil, ForwardEnvelope{}, false, errors.New("fragment reassembly table full")
		}
		asm = &fragmentAssembly{}
		r.assemblies[key] = asm
	}
	if r.usedBytes+hdr.PayloadLength > r.MaxBytes {
		return nil, ForwardEnvelope{}, false, errors.New("fragment reassembly byte budget exceeded")
	}

	start := int(hdr.FragmentOffset)
	end := start + hdr.PayloadLength
	payload := append([]byte(nil), pkt[hdr.PayloadOffset:hdr.PayloadOffset+hdr.PayloadLength]...)

	for _, existing := range asm.pieces {
		if start < existing.end && end > existing.offset {
			// Reject overlapping fragments cleanly and release queued pieces.
			r.dropAssembly(ledger, key, asm)
			return nil, ForwardEnvelope{}, false, errors.New("overlapping IP fragment offset range")
		}
	}

	if start == 0 {
		if hdr.Version == 4 {
			prefix := append([]byte(nil), pkt[:hdr.PayloadOffset]...)
			prefix[6] = 0
			prefix[7] = 0
			asm.headerPrefix = prefix
		} else {
			// Strip the 8-byte IPv6 fragment header and update the preceding NextHeader byte.
			fragHdrPos := hdr.PayloadOffset - 8
			prefix := make([]byte, fragHdrPos)
			copy(prefix, pkt[:fragHdrPos])
			if fragHdrPos == 40 {
				prefix[6] = hdr.NextHeader
			} else {
				// Update the last unfragmented extension header's NextHeader field.
				nhPos := 6
				curOff := 40
				for curOff < fragHdrPos {
					nhPos = curOff
					nh := pkt[curOff]
					if nh == 51 {
						curOff += (int(pkt[curOff+1]) + 2) * 4
					} else {
						curOff += (int(pkt[curOff+1]) + 1) * 8
					}
				}
				prefix[nhPos] = hdr.NextHeader
			}
			asm.headerPrefix = prefix
		}
	}

	if !hdr.MoreFragments {
		if asm.haveTail && asm.totalLen != end {
			r.dropAssembly(ledger, key, asm)
			return nil, ForwardEnvelope{}, false, errors.New("conflicting tail fragment total length")
		}
		asm.haveTail = true
		asm.totalLen = end
	}

	asm.pieces = append(asm.pieces, fragmentPiece{
		offset:  start,
		end:     end,
		payload: payload,
		env:     env,
	})
	asm.bytesStored += len(payload)
	r.usedBytes += len(payload)

	if !asm.haveTail || len(asm.headerPrefix) == 0 || asm.bytesStored != asm.totalLen {
		return nil, ForwardEnvelope{}, false, nil
	}

	// Verify contiguous coverage [0, asm.totalLen) across arbitrary arrival order.
	reassembledPayload := make([]byte, asm.totalLen)
	covered := 0
	cursor := 0
	for cursor < asm.totalLen {
		found := false
		for _, p := range asm.pieces {
			if p.offset == cursor {
				copy(reassembledPayload[p.offset:p.end], p.payload)
				cursor = p.end
				covered += len(p.payload)
				found = true
				break
			}
		}
		if !found {
			return nil, ForwardEnvelope{}, false, nil
		}
	}
	if covered != asm.totalLen {
		return nil, ForwardEnvelope{}, false, nil
	}

	out := make([]byte, len(asm.headerPrefix)+len(reassembledPayload))
	copy(out, asm.headerPrefix)
	copy(out[len(asm.headerPrefix):], reassembledPayload)
	if hdr.Version == 4 {
		binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	} else {
		binary.BigEndian.PutUint16(out[4:6], uint16(len(out)-40))
	}

	mergedEnv := mergeFragmentEnvelopes(ledger, asm.pieces)
	r. usedBytes -= asm.bytesStored
	delete(r.assemblies, key)
	return out, mergedEnv, true, nil
}

func (r *FragmentReassembler) dropAssembly(ledger *IdentityLedger, key fragmentKey, asm *fragmentAssembly) {
	if ledger != nil {
		for i := range asm.pieces {
			ledger.ReleaseEnvelope(&asm.pieces[i].env)
		}
	}
	r.usedBytes -= asm.bytesStored
	delete(r.assemblies, key)
}

func mergeFragmentEnvelopes(ledger *IdentityLedger, pieces []fragmentPiece) ForwardEnvelope {
	first := pieces[0].env
	allKnown := true
	anyConflict := false
	seenSerials := make(map[uint64]bool, len(pieces))

	for i := range pieces {
		e := pieces[i].env
		if e.Read.Packet.Serial != 0 {
			if seenSerials[e.Read.Packet.Serial] {
				allKnown = false
			}
			seenSerials[e.Read.Packet.Serial] = true
		}
		if e.Identity.Status == IdentityConflicting {
			anyConflict = true
			allKnown = false
		} else if e.Identity.Status != IdentityKnown || e.Identity.Snapshot == nil {
			allKnown = false
		}
		if i > 0 {
			if e.Identity.Cookie != 0 && first.Identity.Cookie != 0 && e.Identity.Cookie != first.Identity.Cookie {
				anyConflict = true
				allKnown = false
			}
			if e.Identity.Snapshot != nil && first.Identity.Snapshot != nil && e.Identity.Snapshot.AppID != first.Identity.Snapshot.AppID {
				anyConflict = true
				allKnown = false
			}
			if e.Identity.OwnerVersion != first.Identity.OwnerVersion || e.SlotGeneration != first.SlotGeneration {
				allKnown = false
			}
		}
	}

	// Release all non-primary fragment envelopes so only the merged envelope holds references.
	if ledger != nil {
		for i := 1; i < len(pieces); i++ {
			ledger.ReleaseEnvelope(&pieces[i].env)
		}
	}

	if allKnown && first.Identity.Status == IdentityKnown && first.Identity.Snapshot != nil {
		if ledger != nil {
			rechecked := ledger.ValidateForwardingEnvelope(first)
			if rechecked.Status != IdentityKnown {
				ledger.ReleaseEnvelope(&first)
				return ForwardEnvelope{
					Read:     first.Read,
					Identity: rechecked,
				}
			}
		}
		return first
	}

	if ledger != nil {
		ledger.ReleaseEnvelope(&first)
	}
	if anyConflict {
		return ForwardEnvelope{
			Read: first.Read,
			Identity: PacketIdentityDecision{
				Status: IdentityConflicting,
				Reason: ReasonConflictingApp,
				Cookie: first.Identity.Cookie,
			},
		}
	}
	return ForwardEnvelope{
		Read: first.Read,
		Identity: PacketIdentityDecision{
			Status: IdentityUnknown,
			Reason: ReasonPacketIncomplete,
			Cookie: first.Identity.Cookie,
		},
	}
}

// SplitVirtioGSO normalizes a TUN frame beginning with a 10-byte virtio_net_hdr
// into individual L3 segments. Every segment derived from a single certified raw
// TUN read inherits a cloned ForwardEnvelope from that certified read.
func SplitVirtioGSO(ledger *IdentityLedger, vnetFrame []byte, rawEnv ForwardEnvelope) ([][]byte, []ForwardEnvelope, error) {
	if len(vnetFrame) < VirtioNetHdrLen {
		return nil, nil, errors.New("frame shorter than virtio_net_hdr")
	}
	gsoType := vnetFrame[1] &^ VirtioNetHdrGSOECN
	hdrLen := int(binary.LittleEndian.Uint16(vnetFrame[2:4]))
	gsoSize := int(binary.LittleEndian.Uint16(vnetFrame[4:6]))
	pkt := vnetFrame[VirtioNetHdrLen:]

	if gsoType == VirtioNetHdrGSONone || gsoSize == 0 {
		outPkt := append([]byte(nil), pkt...)
		return [][]byte{outPkt}, []ForwardEnvelope{rawEnv}, nil
	}
	if hdrLen <= 0 || hdrLen > len(pkt) {
		return nil, nil, errors.New("invalid virtio_net_hdr hdr_len")
	}
	hdr, err := InspectPacketHeader(pkt)
	if err != nil {
		return nil, nil, err
	}
	switch gsoType {
	case VirtioNetHdrGSOTCPv4, VirtioNetHdrGSOTCPv6:
		if hdr.PayloadOffset+20 > hdrLen {
			return nil, nil, errors.New("TCP GSO header shorter than L3+TCP minimum")
		}
	case VirtioNetHdrGSOUDP, VirtioNetHdrGSOUDPL4:
		if hdr.PayloadOffset+8 > hdrLen {
			return nil, nil, errors.New("UDP GSO header shorter than L3+UDP minimum")
		}
	default:
		return nil, nil, fmt.Errorf("unsupported virtio GSO type %d", gsoType)
	}

	data := pkt[hdrLen:]
	if len(data) <= gsoSize {
		outPkt := append([]byte(nil), pkt...)
		return [][]byte{outPkt}, []ForwardEnvelope{rawEnv}, nil
	}

	var segments [][]byte
	var envs []ForwardEnvelope
	baseSeq := uint32(0)
	origFlags := uint8(0)
	if gsoType == VirtioNetHdrGSOTCPv4 || gsoType == VirtioNetHdrGSOTCPv6 {
		baseSeq = binary.BigEndian.Uint32(pkt[hdr.PayloadOffset+4 : hdr.PayloadOffset+8])
		origFlags = pkt[hdr.PayloadOffset+13]
	}

	segIdx := 0
	for off := 0; off < len(data); off += gsoSize {
		end := off + gsoSize
		isLast := end >= len(data)
		if isLast {
			end = len(data)
		}
		chunk := data[off:end]
		seg := make([]byte, hdrLen+len(chunk))
		copy(seg, pkt[:hdrLen])
		copy(seg[hdrLen:], chunk)

		if hdr.Version == 4 {
			binary.BigEndian.PutUint16(seg[2:4], uint16(len(seg)))
			binary.BigEndian.PutUint16(seg[4:6], uint16(hdr.Identification)+uint16(segIdx))
		} else {
			binary.BigEndian.PutUint16(seg[4:6], uint16(len(seg)-40))
		}

		if gsoType == VirtioNetHdrGSOTCPv4 || gsoType == VirtioNetHdrGSOTCPv6 {
			binary.BigEndian.PutUint32(seg[hdr.PayloadOffset+4:hdr.PayloadOffset+8], baseSeq+uint32(off))
			flags := origFlags
			if !isLast {
				// Clear FIN (0x01) and PSH (0x08) on non-final TCP GSO segments.
				flags &^= 0x09
			}
			seg[hdr.PayloadOffset+13] = flags
		} else {
			udpLen := uint16(8 + len(chunk))
			binary.BigEndian.PutUint16(seg[hdr.PayloadOffset+4:hdr.PayloadOffset+6], udpLen)
		}

		segments = append(segments, seg)
		if segIdx == 0 {
			envs = append(envs, rawEnv)
		} else if ledger != nil {
			envs = append(envs, ledger.CloneEnvelope(rawEnv))
		} else {
			envs = append(envs, rawEnv)
		}
		segIdx++
	}
	return segments, envs, nil
}

// SegmentAccounting records per-segment skb provenance when kernel software
// segmentation (skb_gso_segment) runs before net_dev_start_xmit.
// Socket-less segments (such as N-1 segments of UDP_SEGMENT when skb_gso_segment
// uses sock_wfree) remain ReadUnknown and never borrow ownership from segment N.
type SegmentAccounting struct {
	TotalSegments      uint64
	AttributedSegments uint64
	SocketlessSegments uint64
	UnknownSegments    uint64
}

func (a *SegmentAccounting) ObserveRawSegment(readDec ReadDecision, env ForwardEnvelope) {
	a.TotalSegments++
	if readDec.Status == ReadUnknown && readDec.Packet.Cookie == 0 {
		a.SocketlessSegments++
		a.UnknownSegments++
		return
	}
	if readDec.Status == ReadCookie && readDec.Packet.Cookie != 0 && env.Identity.Status == IdentityKnown {
		a.AttributedSegments++
		return
	}
	a.UnknownSegments++
}

type PacketClass string

const (
	PacketClassApplicationKnown       PacketClass = "application_known"
	PacketClassApplicationUnknown     PacketClass = "application_unknown"
	PacketClassApplicationConflicting PacketClass = "application_conflicting"
	PacketClassKernelControl          PacketClass = "verified_kernel_control"
)

type KernelControlKind string

const (
	KernelControlICMPReply   KernelControlKind = "kernel_icmp_reply"
	KernelControlTCPTimeWait KernelControlKind = "kernel_tcp_timewait_or_rst"
)

// KernelControlEvidence records verified kernel-control-socket provenance
// captured from kernel control socket emission paths (inet_ctl_sock_create
// sockets where cgroup/sock_create never ran, emitting via ip_send_unicast_reply
// or icmp_push_reply/__icmp_send).
type KernelControlEvidence struct {
	Cookie   uint64
	NetNS    uint32
	Protocol uint8
	Kind     KernelControlKind
}

type ClassifierMetrics struct {
	ApplicationKnown       uint64
	ApplicationMisses      uint64
	ApplicationConflicts   uint64
	VerifiedKernelControl  uint64
}

// KernelControlClassifier separates verified kernel-control-socket traffic
// (ICMP replies on net->ipv4.icmp_sk and TCP TIME_WAIT ACK/RST on net->ipv4.tcp_sock)
// from ordinary application traffic. Missing metadata or packet protocol alone
// never qualifies a packet as KernelControl.
type KernelControlClassifier struct {
	userspaceCookies map[uint64]bool
	kernelControl    map[uint64]KernelControlEvidence
	metrics          ClassifierMetrics
}

func NewKernelControlClassifier() *KernelControlClassifier {
	return &KernelControlClassifier{
		userspaceCookies: make(map[uint64]bool),
		kernelControl:    make(map[uint64]KernelControlEvidence),
	}
}

func (c *KernelControlClassifier) RecordUserspaceSocket(cookie uint64) {
	if cookie == 0 {
		return
	}
	c.userspaceCookies[cookie] = true
	delete(c.kernelControl, cookie)
}

func (c *KernelControlClassifier) RecordKernelControlSocket(ev KernelControlEvidence) {
	if ev.Cookie == 0 || c.userspaceCookies[ev.Cookie] {
		return
	}
	if ev.Kind != KernelControlICMPReply && ev.Kind != KernelControlTCPTimeWait {
		return
	}
	if ev.Protocol != 1 && ev.Protocol != 6 && ev.Protocol != 58 {
		return
	}
	c.kernelControl[ev.Cookie] = ev
}

func (c *KernelControlClassifier) Metrics() ClassifierMetrics {
	return c.metrics
}

// Classify evaluates a packet's ForwardEnvelope and L3 header against verified
// kernel-control-socket evidence. A packet is classified as PacketClassKernelControl
// (and excluded from ApplicationMisses) if and only if:
//  1. It was captured with a valid non-zero socket cookie (ReadCookie),
//  2. The socket cookie was never created by userspace (not in userspaceCookies)
//     and has no userspace actor ownership in the ledger, and
//  3. The socket cookie has verified KernelControlEvidence whose NetNS and
//     L4 protocol match the actual emitted packet.
func (c *KernelControlClassifier) Classify(pkt []byte, env ForwardEnvelope) PacketClass {
	switch env.Identity.Status {
	case IdentityKnown:
		c.metrics.ApplicationKnown++
		return PacketClassApplicationKnown
	case IdentityConflicting:
		c.metrics.ApplicationConflicts++
		return PacketClassApplicationConflicting
	}

	cookie := env.Read.Packet.Cookie
	if env.Read.Status == ReadCookie && !env.Read.Rebuild && cookie != 0 && !c.userspaceCookies[cookie] {
		if kEv, ok := c.kernelControl[cookie]; ok {
			if hdr, err := InspectPacketHeader(pkt); err == nil {
				if (kEv.NetNS == 0 || kEv.NetNS == env.Read.Packet.NetNS) && hdr.NextHeader == kEv.Protocol {
					c.metrics.VerifiedKernelControl++
					return PacketClassKernelControl
				}
			}
		}
	}
	c.metrics.ApplicationMisses++
	return PacketClassApplicationUnknown
}

type LockdownMode string

const (
	LockdownNone            LockdownMode = "none"
	LockdownIntegrity       LockdownMode = "integrity"
	LockdownConfidentiality LockdownMode = "confidentiality"
	LockdownUnknown         LockdownMode = "unknown"
)

func ParseLockdownMode(raw string) LockdownMode {
	s := strings.TrimSpace(raw)
	if s == "" {
		return LockdownNone
	}
	for _, token := range strings.Fields(s) {
		if strings.HasPrefix(token, "[") && strings.HasSuffix(token, "]") {
			active := LockdownMode(strings.TrimSuffix(strings.TrimPrefix(token, "["), "]"))
			switch active {
			case LockdownNone, LockdownIntegrity, LockdownConfidentiality:
				return active
			default:
				return LockdownUnknown
			}
		}
	}
	switch LockdownMode(s) {
	case LockdownNone, LockdownIntegrity, LockdownConfidentiality:
		return LockdownMode(s)
	default:
		return LockdownUnknown
	}
}

type DegradedFallbackReason string

const (
	FallbackNone                    DegradedFallbackReason = ""
	FallbackLockdownConfidentiality DegradedFallbackReason = "degraded_lockdown_confidentiality"
	FallbackMissingBTF              DegradedFallbackReason = "degraded_missing_btf"
	FallbackCgroupV1                DegradedFallbackReason = "degraded_cgroup_v1"
	FallbackCapabilityDenied        DegradedFallbackReason = "degraded_capability_denied"
	FallbackVerifierRejected        DegradedFallbackReason = "degraded_verifier_rejected"
)

func ClassifyLoadFailure(err error, lockdownRaw string, hasBTF, isCgroupV2 bool) DegradedFallbackReason {
	mode := ParseLockdownMode(lockdownRaw)
	if mode == LockdownConfidentiality {
		return FallbackLockdownConfidentiality
	}
	if !hasBTF {
		return FallbackMissingBTF
	}
	if !isCgroupV2 {
		return FallbackCgroupV1
	}
	if err == nil {
		return FallbackNone
	}
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return FallbackCapabilityDenied
	}
	// On kernels with sysctl kernel.unprivileged_bpf_disabled=0 (such as
	// upstream Linux 5.8), unprivileged BPF_MAP_CREATE succeeds, and
	// cilium/ebpf's haveBTF probe then runs BPF_BTF_LOAD, receives EPERM
	// (because BPF_BTF_LOAD requires CAP_SYS_ADMIN), and maps EPERM to
	// UnsupportedFeatureError ("BTF not supported (requires >= 4.18)") even
	// though hasBTF is true.
	msg := err.Error()
	if strings.Contains(msg, "operation not permitted") ||
		strings.Contains(msg, "permission denied") ||
		(hasBTF && (strings.Contains(msg, "BTF not supported") || strings.Contains(msg, "BTF: not supported"))) {
		return FallbackCapabilityDenied
	}
	return FallbackVerifierRejected
}

// CapacityProfile summarizes the bounded BPF map and userspace ledger sizing
// derived from real TUN queue length, CPU count, and reader count, within the
// existing < 45 MB product RAM budget.
type CapacityProfile struct {
	QueueLen                  uint64
	CPUs                      uint64
	Readers                   uint64
	RequiredPacketSlots       uint64
	AllocatedPacketSlots      uint64
	MaxSocketSlots            int
	MaxIdentitySnapshots      int
	MaxIdentityBlobBytes      int
	BPFMapBytes               int
	UserspaceSlotTableBytes   int
	UserspaceLedgerBudget     int
	TotalAttributionBudget    int
	ProductRAMBudgetBytes     int
}

func DeriveCapacityProfile(queue, cpus, readers uint64) (CapacityProfile, error) {
	reqPackets, err := RequiredPacketSlots(queue, cpus, readers)
	if err != nil {
		return CapacityProfile{}, err
	}
	if reqPackets > PacketSlots {
		return CapacityProfile{}, errors.New("required packet slots exceed 2048-slot proof ceiling")
	}
	bpfBytes := int(PacketSlots)*int(unsafe.Sizeof(PacketRecord{})) +
		int(ReaderLimit)*(int(unsafe.Sizeof(ReaderRegistration{}))+int(unsafe.Sizeof(ReaderSlot{}))) +
		int(RecordLimit)*(int(unsafe.Sizeof(ActorKey{}))+int(unsafe.Sizeof(ActorEvidence{}))) +
		DefaultMaxSocketSlots*int(unsafe.Sizeof(SocketStateSlot{}))
	slotBytes := DefaultMaxSocketSlots * int(unsafe.Sizeof(SocketStateSlot{}))
	ledgerBytes := DefaultMaxIdentitySnapshots*int(unsafe.Sizeof(IdentitySnapshot{})) + DefaultMaxIdentityBlobBytes
	total := bpfBytes + ledgerBytes

	return CapacityProfile{
		QueueLen:                queue,
		CPUs:                    cpus,
		Readers:                 readers,
		RequiredPacketSlots:     reqPackets,
		AllocatedPacketSlots:    PacketSlots,
		MaxSocketSlots:          DefaultMaxSocketSlots,
		MaxIdentitySnapshots:    DefaultMaxIdentitySnapshots,
		MaxIdentityBlobBytes:    DefaultMaxIdentityBlobBytes,
		BPFMapBytes:             bpfBytes,
		UserspaceSlotTableBytes: slotBytes,
		UserspaceLedgerBudget:   ledgerBytes,
		TotalAttributionBudget:  total,
		ProductRAMBudgetBytes:   45 << 20,
	}, nil
}
