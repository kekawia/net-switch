package ownerbpf

import (
	"errors"
	"testing"
)

func validProcessFixture() (ActorKey, ActorEvidence, RawProcessMaterial) {
	dev := EncodeKernelDev(8, 1)
	key := ActorKey{
		Cookie: 101,
		Start:  5000000000,
		Exec:   7,
		TGID:   4242,
	}
	ev := ActorEvidence{
		Inode:      998877,
		Device:     dev,
		ObservedNS: 4026531992,
		ABI:        ABI,
	}
	ctx := ExecutionContext{
		TGID:          4242,
		StartBoottime: 5000000000,
		StartTicks:    500,
		ExecID:        7,
		ExeDev:        dev,
		ExeIno:        998877,
		MntNSInum:     4026531840,
		NetNSInum:     4026531992,
		PIDNSInum:     4026531836,
		RootMntID:     29,
		UID:           1000,
		GID:           1000,
	}
	mounts := []MountEntry{
		{
			MountID:     29,
			ParentID:    1,
			Major:       8,
			Minor:       1,
			Root:        "/",
			MountPoint:  "/",
			FSType:      "ext4",
			MountSource: "/dev/sda1",
		},
	}
	mat := RawProcessMaterial{
		Before:  ctx,
		After:   ctx,
		ExePath: "/usr/bin/DirectSender",
		Mounts:  mounts,
	}
	return key, ev, mat
}

func TestIdentityValidationAndContextBracket(t *testing.T) {
	key, ev, mat := validProcessFixture()
	val, reason := ValidateProcessIdentity(key, ev, mat)
	if reason != ReasonValidated || val.Path != "/usr/bin/DirectSender" || val.AppID != "/usr/bin/DirectSender" || val.Sandbox != SandboxNone || val.ExeDeleted {
		t.Fatalf("valid native identity failed: val=%+v reason=%s", val, reason)
	}

	// Unlinked executable retains valid identity when open inode/device match.
	matDeleted := mat
	matDeleted.ExePath = "/usr/bin/DirectSender (deleted)"
	valDel, reasonDel := ValidateProcessIdentity(key, ev, matDeleted)
	if reasonDel != ReasonValidated || !valDel.ExeDeleted || valDel.Path != "/usr/bin/DirectSender" {
		t.Fatalf("unlinked executable validation failed: val=%+v reason=%s", valDel, reasonDel)
	}

	// Mutating any execution/namespace/root/credential field between Before and After
	// or against synchronous send evidence must reject with ReasonContextChanged.
	mutations := []struct {
		name   string
		mutate func(*ActorKey, *ActorEvidence, *RawProcessMaterial)
	}{
		{"tgid_after", func(_ *ActorKey, _ *ActorEvidence, m *RawProcessMaterial) { m.After.TGID++ }},
		{"start_ticks_drift", func(_ *ActorKey, _ *ActorEvidence, m *RawProcessMaterial) { m.After.StartTicks++ }},
		{"start_boottime_mismatch", func(_ *ActorKey, _ *ActorEvidence, m *RawProcessMaterial) { m.After.StartBoottime++ }},
		{"exec_id_changed", func(_ *ActorKey, _ *ActorEvidence, m *RawProcessMaterial) { m.After.ExecID++ }},
		{"exe_dev_changed", func(_ *ActorKey, _ *ActorEvidence, m *RawProcessMaterial) { m.After.ExeDev++ }},
		{"exe_ino_changed", func(_ *ActorKey, _ *ActorEvidence, m *RawProcessMaterial) { m.After.ExeIno++ }},
		{"mntns_changed", func(_ *ActorKey, _ *ActorEvidence, m *RawProcessMaterial) { m.After.MntNSInum++ }},
		{"netns_changed", func(_ *ActorKey, _ *ActorEvidence, m *RawProcessMaterial) { m.After.NetNSInum++ }},
		{"pidns_changed", func(_ *ActorKey, _ *ActorEvidence, m *RawProcessMaterial) { m.After.PIDNSInum++ }},
		{"root_mnt_id_changed", func(_ *ActorKey, _ *ActorEvidence, m *RawProcessMaterial) { m.After.RootMntID++ }},
		{"uid_changed", func(_ *ActorKey, _ *ActorEvidence, m *RawProcessMaterial) { m.After.UID++ }},
		{"gid_changed", func(_ *ActorKey, _ *ActorEvidence, m *RawProcessMaterial) { m.After.GID++ }},
		{"send_inode_disagrees", func(_ *ActorKey, e *ActorEvidence, _ *RawProcessMaterial) { e.Inode++ }},
		{"send_device_disagrees", func(_ *ActorKey, e *ActorEvidence, _ *RawProcessMaterial) { e.Device++ }},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			k, e, m := validProcessFixture()
			tc.mutate(&k, &e, &m)
			if _, r := ValidateProcessIdentity(k, e, m); r != ReasonContextChanged {
				t.Fatalf("%s: got reason %s, want %s", tc.name, r, ReasonContextChanged)
			}
		})
	}
}

func TestIdentityRegisteredAppImageAndSandboxProofs(t *testing.T) {
	// 1. Registered AppImage with matching FUSE mount in mountinfo succeeds.
	fuseDev := EncodeKernelDev(0, 48)
	key, ev, mat := validProcessFixture()
	ev.Device = fuseDev
	mat.Before.ExeDev = fuseDev
	mat.After.ExeDev = fuseDev
	mat.ExePath = "/tmp/.mount_CoolApp123/usr/bin/cool"
	mat.AppImageEnv = "/opt/apps/CoolApp-x86_64.AppImage"
	mat.AppDirEnv = "/tmp/.mount_CoolApp123"
	mat.AppImageBacking = &FileIdentity{Dev: EncodeKernelDev(8, 1), Ino: 555, Regular: true}
	mat.Mounts = append(mat.Mounts, MountEntry{
		MountID:     94,
		ParentID:    29,
		Major:       0,
		Minor:       48,
		Root:        "/",
		MountPoint:  "/tmp/.mount_CoolApp123",
		FSType:      "fuse.CoolApp-x86_64.AppImage",
		MountSource: "CoolApp-x86_64.AppImage",
	})
	val, reason := ValidateProcessIdentity(key, ev, mat)
	if reason != ReasonValidated || val.Sandbox != SandboxAppImage || val.AppID != "appimage:CoolApp-x86_64" || val.Path != "/tmp/.mount_CoolApp123/usr/bin/cool" {
		t.Fatalf("registered AppImage validation failed: val=%+v reason=%s", val, reason)
	}

	// 2. Spoofed APPIMAGE= environment on an ordinary binary without an AppImage mount fails.
	k2, e2, m2 := validProcessFixture()
	m2.AppImageEnv = "/opt/apps/Spoofed.AppImage"
	m2.AppImageBacking = &FileIdentity{Dev: EncodeKernelDev(8, 1), Ino: 555, Regular: true}
	if _, r := ValidateProcessIdentity(k2, e2, m2); r != ReasonSandboxUnverified {
		t.Fatalf("spoofed APPIMAGE env without registered mount got %s, want %s", r, ReasonSandboxUnverified)
	}

	// 3. Flatpak: /app/bin/foo without verified .flatpak-info fails; with .flatpak-info succeeds and preserves case.
	k3, e3, m3 := validProcessFixture()
	m3.ExePath = "/app/bin/browser"
	if _, r := ValidateProcessIdentity(k3, e3, m3); r != ReasonSandboxUnverified {
		t.Fatalf("/app/bin/browser without .flatpak-info got %s, want %s", r, ReasonSandboxUnverified)
	}
	m3.FlatpakInfoErr = errors.New("ELOOP on .flatpak-info")
	if _, r := ValidateProcessIdentity(k3, e3, m3); r != ReasonSandboxUnverified {
		t.Fatalf("unconfined .flatpak-info got %s, want %s", r, ReasonSandboxUnverified)
	}
	m3.FlatpakInfoErr = nil
	appID, err := ParseFlatpakInfo("[Application]\nname=org.mozilla.Firefox\n")
	if err != nil {
		t.Fatal(err)
	}
	m3.FlatpakAppID = appID
	val3, r3 := ValidateProcessIdentity(k3, e3, m3)
	if r3 != ReasonValidated || val3.Sandbox != SandboxFlatpak || val3.AppID != "flatpak:org.mozilla.Firefox" || val3.Path != "/app/bin/browser" {
		t.Fatalf("verified Flatpak failed: val=%+v reason=%s", val3, r3)
	}

	// 4. Snap: /snap/<name>/<rev>/... requires a matching snap mount in mountinfo.
	snapDev := EncodeKernelDev(7, 4)
	k4, e4, m4 := validProcessFixture()
	e4.Device = snapDev
	m4.Before.ExeDev = snapDev
	m4.After.ExeDev = snapDev
	m4.ExePath = "/snap/brave/240/opt/brave.com/brave/brave"
	if _, r := ValidateProcessIdentity(k4, e4, m4); r != ReasonSandboxUnverified {
		t.Fatalf("unmounted /snap path got %s, want %s", r, ReasonSandboxUnverified)
	}
	m4.Mounts = append(m4.Mounts, MountEntry{
		MountID:     88,
		ParentID:    29,
		Major:       7,
		Minor:       4,
		Root:        "/",
		MountPoint:  "/snap/brave/240",
		FSType:      "squashfs",
		MountSource: "/dev/loop4",
	})
	val4, r4 := ValidateProcessIdentity(k4, e4, m4)
	if r4 != ReasonValidated || val4.Sandbox != SandboxSnap || val4.AppID != "snap:brave" || val4.Path != "/snap/brave/240/opt/brave.com/brave/brave" {
		t.Fatalf("verified Snap failed: val=%+v reason=%s", val4, r4)
	}

	// 5. Linux native path preserves case sensitivity and normalizes version directories via apppath.Linux.
	k5, e5, m5 := validProcessFixture()
	m5.ExePath = "/opt/Example/1.2.3/App"
	val5, r5 := ValidateProcessIdentity(k5, e5, m5)
	if r5 != ReasonValidated || val5.Sandbox != SandboxNone || val5.Path != "/opt/Example/1.2.3/App" || val5.AppID != "/opt/Example/*/App" {
		t.Fatalf("Linux apppath normalization failed: val=%+v reason=%s", val5, r5)
	}
}

func TestIdentityRetainedLifecycleAndForkInheritance(t *testing.T) {
	ledger := NewIdentityLedger(16, 4096)
	key, ev, mat := validProcessFixture()
	snap, reason := ledger.EnrichActor(key, ev, mat)
	if reason != ReasonValidated || snap == nil {
		t.Fatalf("EnrichActor failed: snap=%+v reason=%s", snap, reason)
	}

	// Process exits and socket closes while packet is still queued in TUN ring:
	// retained snapshot remains valid for the queued packet and is reclaimed only
	// after ReleasePacket.
	parentActorKey := ActorIdentityKey{TGID: key.TGID, StartBoottime: key.Start, ExecID: key.Exec}
	forkKey := ActorKey{Cookie: key.Cookie, Start: key.Start + 1000, Exec: key.Exec, TGID: key.TGID + 1}
	forkCtx := mat.Before
	forkCtx.TGID = forkKey.TGID
	forkCtx.StartBoottime = forkKey.Start
	forkSnap, forkReason := ledger.InheritFork(parentActorKey, forkKey, ev, forkCtx)
	if forkReason != ReasonInheritedValidated || forkSnap == nil || forkSnap.AppID != snap.AppID {
		t.Fatalf("InheritFork failed: snap=%+v reason=%s", forkSnap, forkReason)
	}
	if ledger.Metrics().ActiveBlobs != 1 {
		t.Fatalf("expected deduplicated blob count 1 across parent and fork, got %d", ledger.Metrics().ActiveBlobs)
	}

	// Forked child of the same app contributing to the same socket cookie does NOT conflict.
	pktDec := ledger.ResolvePacket(ReadDecision{Status: ReadCookie, Packet: PacketRecord{Cookie: key.Cookie}})
	if pktDec.Status != IdentityKnown || pktDec.Conflicts != 0 || pktDec.Snapshot.AppID != "/usr/bin/DirectSender" {
		t.Fatalf("same-app fork contribution caused conflict or lost identity: %+v", pktDec)
	}

	// Release actor and socket while pktDec still holds a packet reference.
	ledger.ReleaseActor(parentActorKey)
	ledger.ReleaseActor(forkSnap.Key)
	ledger.ReleaseSocket(key.Cookie)
	if ledger.Metrics().ActiveSnapshots != 1 {
		t.Fatalf("snapshot was prematurely reclaimed while packet reference was held: active=%d", ledger.Metrics().ActiveSnapshots)
	}
	ledger.ReleasePacket(pktDec.Snapshot)
	if ledger.Metrics().ActiveSnapshots != 0 || ledger.Metrics().UsedBlobBytes != 0 {
		t.Fatalf("snapshot/blob leaked after last packet reference released: metrics=%+v", ledger.Metrics())
	}

	// Fork that changes mount namespace or executable inode is refused.
	_, _ = ledger.EnrichActor(key, ev, mat)
	changedCtx := forkCtx
	changedCtx.MntNSInum++
	if _, r := ledger.InheritFork(parentActorKey, forkKey, ev, changedCtx); r != ReasonContextChanged {
		t.Fatalf("fork with changed mntns got %s, want %s", r, ReasonContextChanged)
	}
}

func TestIdentitySharedSubmitterAndBudgetBounds(t *testing.T) {
	ledger := NewIdentityLedger(2, 128)
	keyA, evA, matA := validProcessFixture()
	if _, r := ledger.EnrichActor(keyA, evA, matA); r != ReasonValidated {
		t.Fatalf("EnrichActor A failed: %s", r)
	}

	// Initially cookie 101 is known as App A.
	dec1 := ledger.ResolvePacket(ReadDecision{Status: ReadCookie, Packet: PacketRecord{Cookie: keyA.Cookie}})
	if dec1.Status != IdentityKnown || dec1.Snapshot.AppID != "/usr/bin/DirectSender" {
		t.Fatalf("expected known App A before shared submitter: %+v", dec1)
	}
	ledger.ReleasePacket(dec1.Snapshot)

	// Shared SQPOLL / unobservable submitter contributes to cookie 101:
	// must invalidate the prior known owner on cookie 101.
	ledger.ObserveUnobservableSubmitter(keyA.Cookie)
	dec2 := ledger.ResolvePacket(ReadDecision{Status: ReadCookie, Packet: PacketRecord{Cookie: keyA.Cookie}})
	if dec2.Status != IdentityUnknown || dec2.Reason != ReasonSubmitterUnobservable || dec2.Snapshot != nil || dec2.Conflicts == 0 {
		t.Fatalf("unobservable submitter did not invalidate prior known owner: %+v", dec2)
	}

	// Different app contributing to a known cookie produces sticky ConflictingIdentity.
	cookieConflict := uint64(202)
	keyB1, evB1, matB1 := validProcessFixture()
	keyB1.Cookie = cookieConflict
	keyB1.TGID = 5001
	matB1.Before.TGID = 5001
	matB1.After.TGID = 5001
	if _, r := ledger.EnrichActor(keyB1, evB1, matB1); r != ReasonValidated {
		t.Fatalf("EnrichActor B1 failed: %s", r)
	}
	keyB2, evB2, matB2 := validProcessFixture()
	keyB2.Cookie = cookieConflict
	keyB2.TGID = 5002
	evB2.Inode = 112233
	matB2.Before.TGID = 5002
	matB2.After.TGID = 5002
	matB2.Before.ExeIno = 112233
	matB2.After.ExeIno = 112233
	matB2.ExePath = "/usr/bin/OtherApp"
	// MaxSnapshots=2 is already reached (keyA and keyB1), so release keyA first.
	ledger.ReleaseActor(ActorIdentityKey{TGID: keyA.TGID, StartBoottime: keyA.Start, ExecID: keyA.Exec})
	if _, r := ledger.EnrichActor(keyB2, evB2, matB2); r != ReasonValidated {
		t.Fatalf("EnrichActor B2 failed: %s", r)
	}
	decConflict := ledger.ResolvePacket(ReadDecision{Status: ReadCookie, Packet: PacketRecord{Cookie: cookieConflict}})
	if decConflict.Status != IdentityConflicting || decConflict.Reason != ReasonConflictingApp || decConflict.Snapshot != nil {
		t.Fatalf("different app on same cookie did not produce ConflictingIdentity: %+v", decConflict)
	}

	// Third distinct live actor exceeds MaxSnapshots=2 and fails with ReasonBudgetExceeded.
	keyB3, evB3, matB3 := validProcessFixture()
	keyB3.Cookie = 303
	keyB3.TGID = 5003
	matB3.Before.TGID = 5003
	matB3.After.TGID = 5003
	if _, r := ledger.EnrichActor(keyB3, evB3, matB3); r != ReasonBudgetExceeded {
		t.Fatalf("exceeding MaxSnapshots got %s, want %s", r, ReasonBudgetExceeded)
	}
}
