package ownerbpf

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/AyoubAchour/net-switch/internal/apppath"
)

type SandboxKind string

const (
	SandboxNone     SandboxKind = "native"
	SandboxFlatpak  SandboxKind = "flatpak"
	SandboxSnap     SandboxKind = "snap"
	SandboxAppImage SandboxKind = "appimage"
)

type IdentityStatus string

const (
	IdentityKnown       IdentityStatus = "known_identity"
	IdentityUnknown     IdentityStatus = "unknown_identity"
	IdentityConflicting IdentityStatus = "conflicting_identity"
)

type IdentityReason string

const (
	ReasonValidated             IdentityReason = "validated"
	ReasonInheritedValidated    IdentityReason = "inherited_validated"
	ReasonIdentityUnretained    IdentityReason = "identity_unretained"
	ReasonContextChanged        IdentityReason = "context_changed"
	ReasonSandboxUnverified     IdentityReason = "sandbox_unverified"
	ReasonSubmitterUnobservable IdentityReason = "submitter_unobservable"
	ReasonConflictingApp        IdentityReason = "conflicting_app"
	ReasonBudgetExceeded        IdentityReason = "budget_exceeded"
	ReasonPacketIncomplete      IdentityReason = "packet_incomplete"
)

const (
	DefaultMaxIdentitySnapshots = 4096
	DefaultMaxIdentityBlobBytes = 256 << 10
)

// EncodeKernelDev encodes (major, minor) into the Linux kernel's internal
// dev_t representation ((major << 20) | minor) read from super_block.s_dev
// in bpf/attribution.c.
func EncodeKernelDev(major, minor uint32) uint64 {
	return uint64((major << 20) | (minor & 0xfffff))
}

func DecodeKernelDev(kdev uint64) (major, minor uint32) {
	return uint32(kdev >> 20), uint32(kdev & 0xfffff)
}

type ActorIdentityKey struct {
	TGID          uint32
	StartBoottime uint64
	ExecID        uint64
}

type ExecutionContext struct {
	TGID           uint32
	StartBoottime  uint64
	StartTicks     uint64
	ExecID         uint64
	ExeDev         uint64
	ExeIno         uint64
	MntNSInum      uint64
	NetNSInum      uint64
	PIDNSInum      uint64
	RootMntID      int
	UID            uint32
	GID            uint32
	KernelThread   bool
	AsyncSubmitter bool
}

type MountEntry struct {
	MountID     int
	ParentID    int
	Major       uint32
	Minor       uint32
	Root        string
	MountPoint  string
	FSType      string
	MountSource string
}

type FileIdentity struct {
	Dev     uint64
	Ino     uint64
	Regular bool
}

type RawProcessMaterial struct {
	Before          ExecutionContext
	After           ExecutionContext
	ExePath         string
	FlatpakAppID    string
	FlatpakInfoErr  error
	AppImageEnv     string
	AppDirEnv       string
	AppImageBacking *FileIdentity
	Mounts          []MountEntry
}

type ValidatedIdentity struct {
	Context    ExecutionContext
	Path       string
	AppID      string
	Sandbox    SandboxKind
	ExeDeleted bool
}

type identityBlob struct {
	key      string
	path     string
	appID    string
	sandbox  SandboxKind
	bytes    int
	refCount int
}

type IdentitySnapshot struct {
	Key              ActorIdentityKey
	Context          ExecutionContext
	Path             string
	AppID            string
	Sandbox          SandboxKind
	ExeDeleted       bool
	Reason           IdentityReason
	EvidenceRevision uint64
	blob             *identityBlob
	actorRefs        int
	socketRefs       int
	packetRefs       int
}

type SocketIdentityState struct {
	Cookie       uint64
	Owner        *IdentitySnapshot
	Version      uint64
	Conflicts    uint64
	LastReason   IdentityReason
	Contributors map[ActorIdentityKey]IdentityReason
}

type PacketIdentityDecision struct {
	Status       IdentityStatus
	Reason       IdentityReason
	Cookie       uint64
	OwnerVersion uint64
	Conflicts    uint64
	Snapshot     *IdentitySnapshot
}

type LedgerMetrics struct {
	KnownPackets          uint64
	UnknownPackets        uint64
	ConflictingPackets    uint64
	ColdEnriched          uint64
	WarmRetained          uint64
	ForkInherited         uint64
	IdentityUnretained    uint64
	ContextChanged        uint64
	SandboxUnverified     uint64
	SubmitterUnobservable uint64
	ConflictingApp        uint64
	BudgetExceeded        uint64
	ActiveSnapshots       int
	ActiveBlobs           int
	UsedBlobBytes         int
	ActiveSocketSlots     int
}

func unescapeMountField(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func ParseMountInfo(text string) ([]MountEntry, int, error) {
	var mounts []MountEntry
	rootMntID := 0
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		sep := strings.Index(line, " - ")
		if sep < 0 {
			return nil, 0, fmt.Errorf("malformed mountinfo line (missing separator): %q", line)
		}
		left := strings.Fields(line[:sep])
		right := strings.Fields(line[sep+3:])
		if len(left) < 5 || len(right) < 2 {
			return nil, 0, fmt.Errorf("malformed mountinfo fields: %q", line)
		}
		mntID, err := strconv.Atoi(left[0])
		if err != nil || mntID <= 0 {
			return nil, 0, fmt.Errorf("invalid mount ID in %q", line)
		}
		parentID, err := strconv.Atoi(left[1])
		if err != nil {
			return nil, 0, fmt.Errorf("invalid parent mount ID in %q", line)
		}
		majMin := strings.SplitN(left[2], ":", 2)
		if len(majMin) != 2 {
			return nil, 0, fmt.Errorf("invalid major:minor in %q", line)
		}
		maj, err1 := strconv.ParseUint(majMin[0], 10, 32)
		min, err2 := strconv.ParseUint(majMin[1], 10, 32)
		if err1 != nil || err2 != nil {
			return nil, 0, fmt.Errorf("invalid major:minor numbers in %q", line)
		}
		entry := MountEntry{
			MountID:     mntID,
			ParentID:    parentID,
			Major:       uint32(maj),
			Minor:       uint32(min),
			Root:        unescapeMountField(left[3]),
			MountPoint:  unescapeMountField(left[4]),
			FSType:      unescapeMountField(right[0]),
			MountSource: unescapeMountField(right[1]),
		}
		if entry.MountPoint == "/" {
			rootMntID = entry.MountID
		}
		mounts = append(mounts, entry)
	}
	if len(mounts) == 0 || rootMntID == 0 {
		return nil, 0, errors.New("mountinfo missing root mount entry")
	}
	return mounts, rootMntID, nil
}

func ParseFlatpakInfo(text string) (string, error) {
	section := ""
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line[1 : len(line)-1]
			continue
		}
		if section == "Application" && strings.HasPrefix(line, "name=") {
			name := strings.TrimSpace(strings.TrimPrefix(line, "name="))
			if name == "" || strings.ContainsAny(name, "/ \t") {
				return "", errors.New("invalid flatpak Application name")
			}
			return name, nil
		}
	}
	return "", errors.New("missing [Application] name= in .flatpak-info")
}

func mountCoversPath(mountPoint, target string) bool {
	if mountPoint == "/" {
		return strings.HasPrefix(target, "/")
	}
	cleanMnt := path.Clean(mountPoint)
	cleanTarget := path.Clean(target)
	return cleanTarget == cleanMnt || strings.HasPrefix(cleanTarget, cleanMnt+"/")
}

func deepCoveringMount(mounts []MountEntry, target string) (MountEntry, bool) {
	var best MountEntry
	found := false
	for _, m := range mounts {
		if !mountCoversPath(m.MountPoint, target) {
			continue
		}
		if !found || len(path.Clean(m.MountPoint)) >= len(path.Clean(best.MountPoint)) {
			best = m
			found = true
		}
	}
	return best, found
}

func isAppImageMount(m MountEntry) bool {
	if m.MountPoint == "/" {
		return false
	}
	lowerFS := strings.ToLower(m.FSType)
	lowerSrc := strings.ToLower(m.MountSource)
	baseMnt := strings.ToLower(path.Base(path.Clean(m.MountPoint)))
	if strings.HasPrefix(lowerFS, "fuse.") && strings.Contains(lowerFS, "appimage") {
		return true
	}
	if (lowerFS == "fuse" || lowerFS == "squashfs" || lowerFS == "iso9660") &&
		(strings.Contains(lowerSrc, "appimage") || (strings.HasPrefix(lowerSrc, "/dev/loop") && strings.HasPrefix(baseMnt, ".mount_"))) {
		return true
	}
	if lowerFS == "tmpfs" && strings.HasPrefix(baseMnt, ".mount_") && strings.HasSuffix(lowerSrc, ".appimage") {
		return true
	}
	return false
}

// ValidateProcessIdentity verifies synchronous BPF send evidence against
// before/after /proc execution-generation samples and sandbox/mount evidence.
func ValidateProcessIdentity(key ActorKey, ev ActorEvidence, mat RawProcessMaterial) (ValidatedIdentity, IdentityReason) {
	if key.Cookie == 0 || key.TGID == 0 || key.Start == 0 || ev.ABI != ABI {
		return ValidatedIdentity{}, ReasonIdentityUnretained
	}
	if mat.Before.KernelThread || mat.After.KernelThread || mat.Before.AsyncSubmitter || mat.After.AsyncSubmitter || ev.Inode == 0 {
		return ValidatedIdentity{}, ReasonSubmitterUnobservable
	}
	b, a := mat.Before, mat.After
	if b.TGID != key.TGID || a.TGID != key.TGID ||
		b.StartTicks == 0 || b.StartTicks != a.StartTicks ||
		(b.StartBoottime != 0 && b.StartBoottime != key.Start) ||
		(a.StartBoottime != 0 && a.StartBoottime != key.Start) ||
		(b.ExecID != 0 && b.ExecID != key.Exec) ||
		(a.ExecID != 0 && a.ExecID != key.Exec) ||
		b.ExeDev != ev.Device || a.ExeDev != ev.Device ||
		b.ExeIno != ev.Inode || a.ExeIno != ev.Inode ||
		b.MntNSInum == 0 || b.MntNSInum != a.MntNSInum ||
		b.NetNSInum == 0 || b.NetNSInum != a.NetNSInum ||
		b.PIDNSInum == 0 || b.PIDNSInum != a.PIDNSInum ||
		b.RootMntID <= 0 || b.RootMntID != a.RootMntID ||
		b.UID != a.UID || b.GID != a.GID {
		return ValidatedIdentity{}, ReasonContextChanged
	}

	rawExe := strings.TrimSpace(mat.ExePath)
	deleted := false
	if strings.HasSuffix(rawExe, " (deleted)") {
		rawExe = strings.TrimSuffix(rawExe, " (deleted)")
		deleted = true
	}
	if rawExe == "" || !strings.HasPrefix(rawExe, "/") {
		return ValidatedIdentity{}, ReasonIdentityUnretained
	}
	cleanExe := path.Clean(rawExe)
	canonPath := cleanExe

	if mat.FlatpakInfoErr != nil {
		return ValidatedIdentity{}, ReasonSandboxUnverified
	}
	if strings.HasPrefix(cleanExe, "/app/") && mat.FlatpakAppID == "" {
		// /app/bin/foo without verified confined .flatpak-info is never trusted.
		return ValidatedIdentity{}, ReasonSandboxUnverified
	}

	sandbox := SandboxNone
	appID := apppath.Normalize(cleanExe, apppath.Linux)

	if mat.FlatpakAppID != "" {
		sandbox = SandboxFlatpak
		appID = "flatpak:" + strings.TrimSpace(mat.FlatpakAppID)
	} else if snapName, snapRoot, ok := parseSnapExePath(cleanExe); ok {
		if !verifySnapMount(mat.Mounts, snapRoot, ev.Device) {
			return ValidatedIdentity{}, ReasonSandboxUnverified
		}
		sandbox = SandboxSnap
		appID = "snap:" + snapName
	}

	// Registered AppImage verification: an APPIMAGE environment variable alone is
	// never trusted without a matching active AppImage mount in /proc/<tgid>/mountinfo
	// covering /proc/<tgid>/exe whose device matches synchronous send evidence.
	covMount, hasCovMount := deepCoveringMount(mat.Mounts, cleanExe)
	exeOnAppImageMount := hasCovMount && isAppImageMount(covMount)
	if mat.AppImageEnv != "" || mat.AppDirEnv != "" || exeOnAppImageMount {
		if sandbox != SandboxNone {
			return ValidatedIdentity{}, ReasonSandboxUnverified
		}
		appImgPath := path.Clean(strings.TrimSpace(mat.AppImageEnv))
		if !strings.HasPrefix(appImgPath, "/") || !strings.HasSuffix(strings.ToLower(appImgPath), ".appimage") {
			return ValidatedIdentity{}, ReasonSandboxUnverified
		}
		if mat.AppImageBacking == nil || !mat.AppImageBacking.Regular || mat.AppImageBacking.Ino == 0 {
			return ValidatedIdentity{}, ReasonSandboxUnverified
		}
		if !exeOnAppImageMount {
			return ValidatedIdentity{}, ReasonSandboxUnverified
		}
		if EncodeKernelDev(covMount.Major, covMount.Minor) != ev.Device {
			return ValidatedIdentity{}, ReasonSandboxUnverified
		}
		if mat.AppDirEnv != "" && path.Clean(mat.AppDirEnv) != path.Clean(covMount.MountPoint) {
			return ValidatedIdentity{}, ReasonSandboxUnverified
		}
		base := path.Base(appImgPath)
		name := base[:len(base)-len(".appimage")]
		if name == "" {
			return ValidatedIdentity{}, ReasonSandboxUnverified
		}
		sandbox = SandboxAppImage
		appID = "appimage:" + name
	}

	ctx := b
	ctx.StartBoottime = key.Start
	ctx.ExecID = key.Exec
	return ValidatedIdentity{
		Context:    ctx,
		Path:       canonPath,
		AppID:      appID,
		Sandbox:    sandbox,
		ExeDeleted: deleted,
	}, ReasonValidated
}

func parseSnapExePath(cleanExe string) (name, snapRoot string, ok bool) {
	parts := strings.Split(strings.TrimPrefix(cleanExe, "/"), "/")
	if len(parts) >= 4 && parts[0] == "snap" && parts[1] != "" && parts[2] != "" {
		return parts[1], "/" + path.Join(parts[0], parts[1], parts[2]), true
	}
	if len(parts) >= 7 && parts[0] == "var" && parts[1] == "lib" && parts[2] == "snapd" && parts[3] == "snap" && parts[4] != "" && parts[5] != "" {
		return parts[4], "/" + path.Join(parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]), true
	}
	return "", "", false
}

func verifySnapMount(mounts []MountEntry, snapRoot string, exeDev uint64) bool {
	cov, ok := deepCoveringMount(mounts, snapRoot)
	if !ok {
		return false
	}
	if EncodeKernelDev(cov.Major, cov.Minor) != exeDev {
		return false
	}
	if path.Clean(cov.MountPoint) == path.Clean(snapRoot) {
		return true
	}
	// Inside a confined snap mount namespace where the snap squashfs is mounted,
	// accept when the mount filesystem is squashfs or its source references snap.
	lowerFS := strings.ToLower(cov.FSType)
	lowerSrc := strings.ToLower(cov.MountSource)
	return lowerFS == "squashfs" || strings.Contains(lowerSrc, "snap")
}

type IdentityLedger struct {
	MaxSnapshots int
	MaxBlobBytes int
	revision     uint64
	actors       map[ActorIdentityKey]*IdentitySnapshot
	sockets      map[uint64]*SocketIdentityState
	blobs        map[string]*identityBlob
	slotTable    *SocketSlotTable
	metrics      LedgerMetrics
}

func NewIdentityLedger(maxSnapshots, maxBlobBytes int) *IdentityLedger {
	if maxSnapshots <= 0 {
		maxSnapshots = DefaultMaxIdentitySnapshots
	}
	if maxBlobBytes <= 0 {
		maxBlobBytes = DefaultMaxIdentityBlobBytes
	}
	return &IdentityLedger{
		MaxSnapshots: maxSnapshots,
		MaxBlobBytes: maxBlobBytes,
		actors:       make(map[ActorIdentityKey]*IdentitySnapshot),
		sockets:      make(map[uint64]*SocketIdentityState),
		blobs:        make(map[string]*identityBlob),
	}
}

func (l *IdentityLedger) Metrics() LedgerMetrics {
	m := l.metrics
	m.ActiveSnapshots = len(l.actors)
	m.ActiveBlobs = len(l.blobs)
	if l.slotTable != nil {
		m.ActiveSocketSlots = l.slotTable.Metrics().ActiveSlots
	} else {
		m.ActiveSocketSlots = len(l.sockets)
	}
	return m
}

func (l *IdentityLedger) acquireBlob(canonPath, appID string, sandbox SandboxKind) (*identityBlob, bool) {
	key := string(sandbox) + "\x00" + canonPath + "\x00" + appID
	if existing, ok := l.blobs[key]; ok {
		existing.refCount++
		return existing, true
	}
	cost := len(canonPath) + len(appID) + len(sandbox)
	if l.metrics.UsedBlobBytes+cost > l.MaxBlobBytes {
		return nil, false
	}
	b := &identityBlob{
		key:      key,
		path:     strings.Clone(canonPath),
		appID:    strings.Clone(appID),
		sandbox:  sandbox,
		bytes:    cost,
		refCount: 1,
	}
	l.blobs[key] = b
	l.metrics.UsedBlobBytes += cost
	return b, true
}

func (l *IdentityLedger) releaseBlob(b *identityBlob) {
	if b == nil {
		return
	}
	b.refCount--
	if b.refCount <= 0 {
		delete(l.blobs, b.key)
		l.metrics.UsedBlobBytes -= b.bytes
	}
}

func (l *IdentityLedger) recordFailureMetric(reason IdentityReason) {
	switch reason {
	case ReasonIdentityUnretained:
		l.metrics.IdentityUnretained++
	case ReasonContextChanged:
		l.metrics.ContextChanged++
	case ReasonSandboxUnverified:
		l.metrics.SandboxUnverified++
	case ReasonSubmitterUnobservable:
		l.metrics.SubmitterUnobservable++
	case ReasonBudgetExceeded:
		l.metrics.BudgetExceeded++
	}
}

func (l *IdentityLedger) ensureSocket(cookie uint64) *SocketIdentityState {
	st, ok := l.sockets[cookie]
	if !ok {
		st = &SocketIdentityState{
			Cookie:       cookie,
			Contributors: make(map[ActorIdentityKey]IdentityReason),
		}
		l.sockets[cookie] = st
	}
	return st
}

// applyContributor updates the socket cookie's ownership and sticky conflict
// state using the 5.8 XADD order: conflicts += 1 first, then version += 1.
func (l *IdentityLedger) applyContributor(cookie uint64, actorKey ActorIdentityKey, snap *IdentitySnapshot, reason IdentityReason) {
	if cookie == 0 {
		return
	}
	if l.slotTable != nil {
		var prevAppID string
		var hadValidOwner bool
		if idx, exists := l.slotTable.cookieToSlot[cookie]; exists {
			m := &l.slotTable.meta[idx]
			s := &l.slotTable.slots[idx]
			if m.owner != nil && atomic.LoadUint64(&s.Conflicts) == 0 {
				hadValidOwner = true
				prevAppID = m.owner.AppID
			}
		}
		if !l.slotTable.publishContributor(l, cookie, actorKey, snap, reason) {
			l.metrics.BudgetExceeded++
			return
		}
		if hadValidOwner && snap != nil && prevAppID != snap.AppID {
			l.metrics.ConflictingApp++
		}
		return
	}
	st := l.ensureSocket(cookie)
	if actorKey != (ActorIdentityKey{}) {
		st.Contributors[actorKey] = reason
	}
	if snap == nil {
		// Unresolved contributor on a socket generation invalidates any prior known
		// owner and prevents any later contributor from claiming sole ownership.
		if st.Owner != nil {
			l.decrementSocketRef(st.Owner)
			st.Owner = nil
		}
		st.Conflicts++
		st.Version++
		if st.LastReason == "" || st.LastReason == ReasonValidated || st.LastReason == ReasonInheritedValidated {
			st.LastReason = reason
		}
		return
	}
	if st.Conflicts > 0 {
		st.Conflicts++
		st.Version++
		return
	}
	if st.Owner == nil {
		snap.socketRefs++
		st.Owner = snap
		st.Version = 1
		st.LastReason = snap.Reason
		return
	}
	// Same validated AppID (even across forked PIDs) is same-app, not a conflict.
	if st.Owner.AppID == snap.AppID {
		return
	}
	// Different validated AppID on the same socket cookie is a sticky conflict.
	l.decrementSocketRef(st.Owner)
	st.Owner = nil
	st.Conflicts++
	st.Version++
	st.LastReason = ReasonConflictingApp
	l.metrics.ConflictingApp++
}

func (l *IdentityLedger) enrichActorSnapshotOnly(key ActorKey, ev ActorEvidence, mat RawProcessMaterial) (*IdentitySnapshot, IdentityReason) {
	actorKey := ActorIdentityKey{TGID: key.TGID, StartBoottime: key.Start, ExecID: key.Exec}
	if existing, ok := l.actors[actorKey]; ok {
		if existing.Context.ExeDev == ev.Device && existing.Context.ExeIno == ev.Inode {
			l.metrics.WarmRetained++
			return existing, existing.Reason
		}
		l.recordFailureMetric(ReasonContextChanged)
		return nil, ReasonContextChanged
	}

	val, reason := ValidateProcessIdentity(key, ev, mat)
	if reason != ReasonValidated {
		l.recordFailureMetric(reason)
		return nil, reason
	}
	if len(l.actors) >= l.MaxSnapshots {
		l.recordFailureMetric(ReasonBudgetExceeded)
		return nil, ReasonBudgetExceeded
	}
	blob, ok := l.acquireBlob(val.Path, val.AppID, val.Sandbox)
	if !ok {
		l.recordFailureMetric(ReasonBudgetExceeded)
		return nil, ReasonBudgetExceeded
	}
	l.revision++
	snap := &IdentitySnapshot{
		Key:              actorKey,
		Context:          val.Context,
		Path:             blob.path,
		AppID:            blob.appID,
		Sandbox:          blob.sandbox,
		ExeDeleted:       val.ExeDeleted,
		Reason:           ReasonValidated,
		EvidenceRevision: l.revision,
		blob:             blob,
		actorRefs:        1,
	}
	l.actors[actorKey] = snap
	l.metrics.ColdEnriched++
	return snap, ReasonValidated
}

func (l *IdentityLedger) EnrichActor(key ActorKey, ev ActorEvidence, mat RawProcessMaterial) (*IdentitySnapshot, IdentityReason) {
	actorKey := ActorIdentityKey{TGID: key.TGID, StartBoottime: key.Start, ExecID: key.Exec}
	snap, reason := l.enrichActorSnapshotOnly(key, ev, mat)
	l.applyContributor(key.Cookie, actorKey, snap, reason)
	return snap, reason
}

// ObserveWarmSend binds a new send attempt from an already-validated actor
// generation (even after the process has exited) if and only if its synchronous
// send evidence (TGID, StartBoottime, ExecID, ExeDev, ExeIno) matches.
func (l *IdentityLedger) ObserveWarmSend(key ActorKey, ev ActorEvidence) (*IdentitySnapshot, IdentityReason) {
	actorKey := ActorIdentityKey{TGID: key.TGID, StartBoottime: key.Start, ExecID: key.Exec}
	snap, ok := l.actors[actorKey]
	if !ok {
		l.recordFailureMetric(ReasonIdentityUnretained)
		l.applyContributor(key.Cookie, actorKey, nil, ReasonIdentityUnretained)
		return nil, ReasonIdentityUnretained
	}
	if ev.ABI != ABI || snap.Context.ExeDev != ev.Device || snap.Context.ExeIno != ev.Inode {
		l.recordFailureMetric(ReasonContextChanged)
		l.applyContributor(key.Cookie, actorKey, nil, ReasonContextChanged)
		return nil, ReasonContextChanged
	}
	l.metrics.WarmRetained++
	l.applyContributor(key.Cookie, actorKey, snap, snap.Reason)
	return snap, snap.Reason
}

// InheritFork binds a verified parent snapshot to a forked child incarnation
// when no exec, namespace, root, credential or executable change occurred.
func (l *IdentityLedger) InheritFork(parentKey ActorIdentityKey, childKey ActorKey, childEv ActorEvidence, childCtx ExecutionContext) (*IdentitySnapshot, IdentityReason) {
	childActorKey := ActorIdentityKey{TGID: childKey.TGID, StartBoottime: childKey.Start, ExecID: childKey.Exec}
	parent, ok := l.actors[parentKey]
	if !ok {
		l.recordFailureMetric(ReasonIdentityUnretained)
		l.applyContributor(childKey.Cookie, childActorKey, nil, ReasonIdentityUnretained)
		return nil, ReasonIdentityUnretained
	}
	if childKey.TGID == 0 || childKey.Start == 0 || childEv.ABI != ABI ||
		childCtx.KernelThread || childCtx.AsyncSubmitter {
		reason := ReasonIdentityUnretained
		if childCtx.KernelThread || childCtx.AsyncSubmitter {
			reason = ReasonSubmitterUnobservable
		}
		l.recordFailureMetric(reason)
		l.applyContributor(childKey.Cookie, childActorKey, nil, reason)
		return nil, reason
	}
	pCtx := parent.Context
	if childEv.Device != pCtx.ExeDev || childEv.Inode != pCtx.ExeIno ||
		childCtx.ExeDev != pCtx.ExeDev || childCtx.ExeIno != pCtx.ExeIno ||
		childCtx.MntNSInum == 0 || childCtx.MntNSInum != pCtx.MntNSInum ||
		childCtx.NetNSInum == 0 || childCtx.NetNSInum != pCtx.NetNSInum ||
		childCtx.PIDNSInum == 0 || childCtx.PIDNSInum != pCtx.PIDNSInum ||
		childCtx.RootMntID <= 0 || childCtx.RootMntID != pCtx.RootMntID ||
		childCtx.UID != pCtx.UID || childCtx.GID != pCtx.GID {
		l.recordFailureMetric(ReasonContextChanged)
		l.applyContributor(childKey.Cookie, childActorKey, nil, ReasonContextChanged)
		return nil, ReasonContextChanged
	}
	if existing, exists := l.actors[childActorKey]; exists {
		l.metrics.WarmRetained++
		l.applyContributor(childKey.Cookie, childActorKey, existing, existing.Reason)
		return existing, existing.Reason
	}
	if len(l.actors) >= l.MaxSnapshots {
		l.recordFailureMetric(ReasonBudgetExceeded)
		l.applyContributor(childKey.Cookie, childActorKey, nil, ReasonBudgetExceeded)
		return nil, ReasonBudgetExceeded
	}
	blob, ok := l.acquireBlob(parent.Path, parent.AppID, parent.Sandbox)
	if !ok {
		l.recordFailureMetric(ReasonBudgetExceeded)
		l.applyContributor(childKey.Cookie, childActorKey, nil, ReasonBudgetExceeded)
		return nil, ReasonBudgetExceeded
	}
	l.revision++
	boundCtx := childCtx
	boundCtx.TGID = childKey.TGID
	boundCtx.StartBoottime = childKey.Start
	boundCtx.ExecID = childKey.Exec
	snap := &IdentitySnapshot{
		Key:              childActorKey,
		Context:          boundCtx,
		Path:             blob.path,
		AppID:            blob.appID,
		Sandbox:          blob.sandbox,
		ExeDeleted:       parent.ExeDeleted,
		Reason:           ReasonInheritedValidated,
		EvidenceRevision: l.revision,
		blob:             blob,
		actorRefs:        1,
	}
	l.actors[childActorKey] = snap
	l.metrics.ForkInherited++
	l.applyContributor(childKey.Cookie, childActorKey, snap, ReasonInheritedValidated)
	return snap, ReasonInheritedValidated
}

func (l *IdentityLedger) ObserveColdUnretained(key ActorKey, ev ActorEvidence) {
	actorKey := ActorIdentityKey{TGID: key.TGID, StartBoottime: key.Start, ExecID: key.Exec}
	_ = ev
	l.recordFailureMetric(ReasonIdentityUnretained)
	l.applyContributor(key.Cookie, actorKey, nil, ReasonIdentityUnretained)
}

func (l *IdentityLedger) ObserveUnobservableSubmitter(cookie uint64) {
	l.recordFailureMetric(ReasonSubmitterUnobservable)
	l.applyContributor(cookie, ActorIdentityKey{}, nil, ReasonSubmitterUnobservable)
}

// ResolvePacket performs the coherent seqlock-free version/conflict check
// (v1, c1) -> owner -> (v2, c2) for a validated packet read decision.
func (l *IdentityLedger) ResolvePacket(readDec ReadDecision) PacketIdentityDecision {
	if readDec.Status != ReadCookie || readDec.Rebuild || readDec.Packet.Cookie == 0 {
		l.metrics.UnknownPackets++
		return PacketIdentityDecision{
			Status: IdentityUnknown,
			Reason: ReasonPacketIncomplete,
		}
	}
	cookie := readDec.Packet.Cookie
	if l.slotTable != nil {
		if l.slotTable.metrics.EpochPoisoned {
			l.metrics.UnknownPackets++
			l.metrics.BudgetExceeded++
			return PacketIdentityDecision{
				Status: IdentityUnknown,
				Reason: ReasonBudgetExceeded,
				Cookie: cookie,
			}
		}
		idx, ok := l.slotTable.cookieToSlot[cookie]
		if !ok {
			l.metrics.UnknownPackets++
			l.metrics.IdentityUnretained++
			return PacketIdentityDecision{
				Status: IdentityUnknown,
				Reason: ReasonIdentityUnretained,
				Cookie: cookie,
			}
		}
		s := &l.slotTable.slots[idx]
		m := &l.slotTable.meta[idx]
		v1 := atomic.LoadUint64(&s.Version)
		c1 := atomic.LoadUint64(&s.Conflicts)
		owner := m.owner
		rev := atomic.LoadUint64(&s.EvidenceRevision)
		flags := SocketSlotFlags(atomic.LoadUint32(&s.Flags))
		lastReason := m.lastReason
		v2 := atomic.LoadUint64(&s.Version)
		c2 := atomic.LoadUint64(&s.Conflicts)
		if v1 != v2 || v1 == 0 || c1 != 0 || c2 != 0 ||
			(flags&SocketSlotValid) == 0 ||
			(flags&(SocketSlotIncomplete|SocketSlotConflicting|SocketSlotPoisoned)) != 0 ||
			owner == nil || owner.EvidenceRevision != rev {
			status := IdentityUnknown
			reason := lastReason
			if reason == "" {
				reason = ReasonIdentityUnretained
			}
			if reason == ReasonConflictingApp {
				status = IdentityConflicting
				l.metrics.ConflictingPackets++
			} else {
				l.metrics.UnknownPackets++
			}
			return PacketIdentityDecision{
				Status:       status,
				Reason:       reason,
				Cookie:       cookie,
				OwnerVersion: v2,
				Conflicts:    c2,
			}
		}
		owner.packetRefs++
		l.metrics.KnownPackets++
		return PacketIdentityDecision{
			Status:       IdentityKnown,
			Reason:       owner.Reason,
			Cookie:       cookie,
			OwnerVersion: v1,
			Conflicts:    0,
			Snapshot:     owner,
		}
	}
	st, ok := l.sockets[cookie]
	if !ok {
		l.metrics.UnknownPackets++
		l.metrics.IdentityUnretained++
		return PacketIdentityDecision{
			Status: IdentityUnknown,
			Reason: ReasonIdentityUnretained,
			Cookie: cookie,
		}
	}
	v1, c1 := st.Version, st.Conflicts
	owner := st.Owner
	v2, c2 := st.Version, st.Conflicts
	if v1 != v2 || c1 != 0 || c2 != 0 || owner == nil {
		status := IdentityUnknown
		reason := st.LastReason
		if reason == "" {
			reason = ReasonIdentityUnretained
		}
		if reason == ReasonConflictingApp {
			status = IdentityConflicting
			l.metrics.ConflictingPackets++
		} else {
			l.metrics.UnknownPackets++
		}
		return PacketIdentityDecision{
			Status:       status,
			Reason:       reason,
			Cookie:       cookie,
			OwnerVersion: v2,
			Conflicts:    c2,
		}
	}
	owner.packetRefs++
	l.metrics.KnownPackets++
	return PacketIdentityDecision{
		Status:       IdentityKnown,
		Reason:       owner.Reason,
		Cookie:       cookie,
		OwnerVersion: v1,
		Conflicts:    0,
		Snapshot:     owner,
	}
}

func (l *IdentityLedger) tryReclaimSnapshot(snap *IdentitySnapshot) {
	if snap == nil || snap.actorRefs > 0 || snap.socketRefs > 0 || snap.packetRefs > 0 {
		return
	}
	if cur, ok := l.actors[snap.Key]; ok && cur == snap {
		delete(l.actors, snap.Key)
		l.releaseBlob(snap.blob)
		snap.blob = nil
	}
}

func (l *IdentityLedger) decrementSocketRef(snap *IdentitySnapshot) {
	if snap == nil {
		return
	}
	if snap.socketRefs > 0 {
		snap.socketRefs--
	}
	l.tryReclaimSnapshot(snap)
}

func (l *IdentityLedger) ReleaseActor(key ActorIdentityKey) {
	snap, ok := l.actors[key]
	if !ok {
		return
	}
	if snap.actorRefs > 0 {
		snap.actorRefs--
	}
	l.tryReclaimSnapshot(snap)
}

func (l *IdentityLedger) ReleaseSocket(cookie uint64) {
	if l.slotTable != nil {
		if idx, ok := l.slotTable.cookieToSlot[cookie]; ok {
			m := &l.slotTable.meta[idx]
			s := &l.slotTable.slots[idx]
			m.socketAlive = false
			atomic.StoreUint32(&s.Flags, atomic.LoadUint32(&s.Flags)|uint32(SocketSlotDestroyed))
			l.slotTable.tryReclaimSlot(l, idx)
		}
	}
	st, ok := l.sockets[cookie]
	if !ok {
		return
	}
	owner := st.Owner
	st.Owner = nil
	delete(l.sockets, cookie)
	l.decrementSocketRef(owner)
}

func (l *IdentityLedger) ReleasePacket(snap *IdentitySnapshot) {
	if snap == nil {
		return
	}
	if snap.packetRefs > 0 {
		snap.packetRefs--
	}
	l.tryReclaimSnapshot(snap)
}

const maxAsyncMapsStreamBytes = 16 << 20

// readerContainsToken streams r in fixed chunks with boundary overlap so tokens
// spanning read boundaries or appearing past 64 KiB in /proc/<tgid>/maps are
// never missed without allocating unbounded buffers. If r exceeds maxBytes, it
// fails closed by returning (true, nil).
func readerContainsToken(r io.Reader, token []byte, chunkSize, maxBytes int) (bool, error) {
	if len(token) == 0 {
		return true, nil
	}
	if chunkSize < len(token)*2 {
		chunkSize = len(token) * 2
	}
	overlap := len(token) - 1
	buf := make([]byte, overlap+chunkSize)
	carry := 0
	var total int
	for {
		n, err := r.Read(buf[carry : carry+chunkSize])
		if n > 0 {
			total += n
			window := buf[:carry+n]
			if bytes.Contains(window, token) {
				return true, nil
			}
			if maxBytes > 0 && total > maxBytes {
				return true, nil
			}
			if len(window) >= overlap {
				copy(buf[:overlap], window[len(window)-overlap:])
				carry = overlap
			} else {
				copy(buf[:len(window)], window)
				carry = len(window)
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return false, nil
			}
			return false, err
		}
		if n == 0 {
			return false, nil
		}
	}
}
