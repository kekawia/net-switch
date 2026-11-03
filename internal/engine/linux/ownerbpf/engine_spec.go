package ownerbpf

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

const (
	bpfMapFlagMmapable = 0x400

	// DefaultEngineMaxActors and DefaultEngineMaxSocketSlots size the production
	// eBPF actor map and mmap socket-slot table to cover host-wide sockets across
	// client, engine-relay, refused, and peer namespaces (~200k simultaneous burst
	// sockets in mixed-caps/overload fixtures) without map/slot poisoning while
	// keeping userspace Go heap metadata compact (~10 MiB).
	DefaultEngineMaxActors      uint32 = 524288
	DefaultEngineMaxSocketSlots int    = 524288
	DefaultEngineMaxSnapshots   int    = 16384
	DefaultEngineMaxBlobBytes   int    = 1 << 20

	// DefaultEngineActorEventQueue sizes the lockless-signaled new-actor BPF
	// queue drained per burst; if a burst ever exceeds it, counters[6] triggers
	// a full actors-map catchup without losing any retained actor record.
	DefaultEngineActorEventQueue uint32 = 65536

	MaxEnginePacketSlots uint64 = 1 << 20
)

// QueuedActorEvent matches the contiguous 64-byte stack frame [rfp-120..rfp-56)
// populated by observe_send: actor_evidence at [rfp-120..rfp-88) followed
// immediately by actor_key at [rfp-88..rfp-56).
type QueuedActorEvent struct {
	Evidence ActorEvidence
	Key      ActorKey
}

var (
	_ [64 - unsafe.Sizeof(QueuedActorEvent{})]byte
	_ [unsafe.Sizeof(QueuedActorEvent{}) - 64]byte
)

// PrepareEngineBridgeSpec loads the embedded normal bridge ELF spec, validates
// its ABI invariants, removes the tracefs-dependent fixture-only perf_consume
// program, and resizes Maps["packets"] to P = next_power_of_two(Q+C+R+32).
func PrepareEngineBridgeSpec(actualQueue, cpus, readers uint64) (*ebpf.CollectionSpec, uint64, error) {
	packetSlots, err := RequiredPacketSlots(actualQueue, cpus, readers)
	if err != nil {
		return nil, 0, err
	}
	if packetSlots > MaxEnginePacketSlots {
		return nil, 0, fmt.Errorf("required packet slots %d exceed engine ceiling %d", packetSlots, MaxEnginePacketSlots)
	}
	spec, err := LoadEmbeddedBridgeSpec()
	if err != nil {
		return nil, 0, err
	}
	wantMaps := map[string][4]uint32{
		"packets":    {uint32(ebpf.Hash), 8, 128, PacketSlots},
		"readers":    {uint32(ebpf.Hash), 8, 48, ReaderLimit},
		"read_slots": {uint32(ebpf.Array), 4, 256, ReaderLimit},
		"config":     {uint32(ebpf.Array), 4, 64, 1},
		"health":     {uint32(ebpf.Array), 4, 64, 1},
		"cpu_state":  {uint32(ebpf.PerCPUArray), 4, 128, 1},
	}
	if len(spec.Maps) != len(wantMaps) || len(spec.Programs) != 5 {
		return nil, 0, errors.New("embedded bridge spec: unexpected map/program count")
	}
	for name, w := range wantMaps {
		m := spec.Maps[name]
		wantFlags := uint32(0)
		if name == "read_slots" || name == "health" {
			wantFlags = bpfMapFlagMmapable
		}
		if m == nil || [4]uint32{uint32(m.Type), m.KeySize, m.ValueSize, m.MaxEntries} != w || m.Flags != wantFlags {
			return nil, 0, fmt.Errorf("embedded bridge spec: map ABI/flags mismatch for %s", name)
		}
	}
	for name, kind := range map[string]ebpf.ProgramType{
		"capture":            ebpf.RawTracepoint,
		"consume":            ebpf.RawTracepoint,
		"freed":              ebpf.RawTracepoint,
		"init_egress_cookie": ebpf.CGroupSKB,
		"perf_consume":       ebpf.TracePoint,
	} {
		p := spec.Programs[name]
		if p == nil || p.Type != kind || p.License != "Dual MIT/GPL" {
			return nil, 0, fmt.Errorf("embedded bridge spec: program mismatch for %s", name)
		}
	}

	delete(spec.Programs, "perf_consume")
	spec.Maps["packets"].MaxEntries = uint32(packetSlots)
	for _, progName := range []string{"consume", "freed"} {
		if err := stripUnusedBridgeTerminalCPUStats(progName, spec.Programs[progName]); err != nil {
			return nil, 0, err
		}
	}
	return spec, packetSlots, nil
}

// stripUnusedBridgeTerminalCPUStats rewrites production consume and freed so
// Maps["packets"] is checked immediately on entry before any config lookup, and
// removes all fixture-only cpu_state lookups, skb->dev probe reads, and counter
// updates. Non-TUN skbs exit after one hash lookup with zero helper calls beyond
// bpf_map_lookup_elem(&packets), minimizing the raw_tracepoint prog->active
// window on Linux 7.0+ where task preemption remains enabled.
func stripUnusedBridgeTerminalCPUStats(name string, prog *ebpf.ProgramSpec) error {
	if prog == nil {
		return fmt.Errorf("embedded bridge %s program missing", name)
	}
	insns := prog.Instructions
	if len(insns) != 279 {
		return fmt.Errorf("embedded bridge %s instruction count = %d, want 279", name, len(insns))
	}
	wantAtomicOffset := int16(56)
	if name == "freed" {
		wantAtomicOffset = 64
	}
	if insns[0].OpCode != asm.LoadMemOp(asm.DWord) || insns[0].Dst != asm.R7 || insns[0].Src != asm.R1 || insns[0].Offset != 0 ||
		insns[1].OpCode != asm.Mov.Op(asm.ImmSource) || insns[1].Dst != asm.R1 || insns[1].Constant != 0 ||
		insns[2].OpCode != asm.StoreMemOp(asm.Word) || insns[2].Dst != asm.RFP || insns[2].Src != asm.R1 || insns[2].Offset != -8 ||
		insns[3].OpCode != asm.StoreMemOp(asm.DWord) || insns[3].Dst != asm.RFP || insns[3].Src != asm.R7 || insns[3].Offset != -16 ||
		!insns[6].IsLoadFromMap() || insns[6].Reference() != "config" ||
		!insns[10].IsLoadFromMap() || insns[10].Reference() != "cpu_state" ||
		insns[13].OpCode != asm.JEq.Op(asm.ImmSource) || insns[13].Dst != asm.R6 || insns[13].Constant != 0 ||
		insns[14].OpCode != asm.JEq.Op(asm.ImmSource) || insns[14].Dst != asm.R0 || insns[14].Constant != 0 ||
		insns[15].OpCode != asm.Mov.Op(asm.RegSource) || insns[15].Dst != asm.R8 || insns[15].Src != asm.R0 ||
		insns[16].OpCode != asm.Mov.Op(asm.ImmSource) || insns[16].Dst != asm.R9 || insns[16].Constant != 0 ||
		insns[58].OpCode != asm.JEq.Op(asm.RegSource) || insns[58].Dst != asm.R2 || insns[58].Src != asm.R1 || insns[58].Offset != 137 ||
		insns[59].OpCode != asm.Mov.Op(asm.RegSource) || insns[59].Dst != asm.R2 || insns[59].Src != asm.RFP ||
		insns[60].OpCode != asm.Add.Op(asm.ImmSource) || insns[60].Dst != asm.R2 || insns[60].Constant != -16 ||
		!insns[61].IsLoadFromMap() || insns[61].Reference() != "packets" ||
		insns[62].OpCode != asm.Call.Op(asm.ImmSource) || insns[62].Constant != int64(asm.FnMapLookupElem) ||
		insns[63].OpCode != asm.JEq.Op(asm.ImmSource) || insns[63].Dst != asm.R0 || insns[63].Constant != 0 {
		return fmt.Errorf("embedded bridge %s pre-lookup fast-path signature mismatch", name)
	}
	for _, callIdx := range []int{24, 37, 45, 54} {
		if insns[callIdx].OpCode != asm.Call.Op(asm.ImmSource) || insns[callIdx].Constant != int64(asm.FnProbeReadKernel) {
			return fmt.Errorf("embedded bridge %s expected probe_read_kernel at insn %d", name, callIdx)
		}
	}
	if insns[104].OpCode != asm.JEq.Op(asm.ImmSource) || insns[104].Dst != asm.R0 || insns[104].Constant != 0 || insns[104].Offset != 13 ||
		insns[116].OpCode != asm.Ja.Op(asm.ImmSource) || insns[116].Offset != 2 ||
		insns[117].OpCode != asm.Mov.Op(asm.ImmSource) || insns[117].Dst != asm.R1 || insns[117].Constant != 1 ||
		insns[118].Dst != asm.R8 || insns[118].Src != asm.R1 || insns[118].Offset != 80 ||
		insns[119].OpCode != asm.Call.Op(asm.ImmSource) || insns[119].Constant != int64(asm.FnGetCurrentPidTgid) {
		return fmt.Errorf("embedded bridge %s packets-erase cpu_state.deleted signature mismatch", name)
	}
	if insns[138].OpCode != asm.LoadMemOp(asm.DWord) || insns[138].Dst != asm.R2 || insns[138].Src != asm.R6 || insns[138].Offset != 8 ||
		insns[139].OpCode != asm.JNE.Op(asm.RegSource) || insns[139].Dst != asm.R9 || insns[139].Src != asm.R2 || insns[139].Offset != 140 ||
		insns[140].OpCode != asm.StoreMemOp(asm.DWord) || insns[140].Dst != asm.RFP || insns[140].Src != asm.R0 || insns[140].Offset != -192 ||
		insns[141].OpCode != asm.StoreMemOp(asm.Word) || insns[141].Dst != asm.RFP || insns[141].Src != asm.R1 || insns[141].Offset != -116 ||
		insns[142].OpCode != asm.Mov.Op(asm.RegSource) || insns[142].Dst != asm.R2 || insns[142].Src != asm.RFP {
		return fmt.Errorf("embedded bridge %s reader-epoch check signature mismatch", name)
	}
	if insns[164].OpCode != asm.LoadMemOp(asm.DWord) || insns[164].Dst != asm.R1 || insns[164].Src != asm.R6 || insns[164].Offset != 32 ||
		insns[165].OpCode != asm.JEq.Op(asm.ImmSource) || insns[165].Dst != asm.R1 || insns[165].Constant != 0 || insns[165].Offset != 4 ||
		insns[166].OpCode != asm.LoadMemOp(asm.DWord) || insns[166].Dst != asm.R2 || insns[166].Src != asm.RFP || insns[166].Offset != -152 ||
		insns[167].OpCode != asm.JNE.Op(asm.RegSource) || insns[167].Dst != asm.R2 || insns[167].Src != asm.R1 || insns[167].Offset != 2 ||
		insns[168].OpCode != asm.Mov.Op(asm.ImmSource) || insns[168].Dst != asm.R1 || insns[168].Constant != 1 ||
		insns[169].Dst != asm.R8 || insns[169].Src != asm.R1 || insns[169].Offset != 120 {
		return fmt.Errorf("embedded bridge %s cpu_state.nested signature mismatch", name)
	}
	if insns[189].OpCode != asm.Ja.Op(asm.ImmSource) || insns[189].Offset != 84 ||
		insns[190].OpCode != asm.LoadMemOp(asm.Word) || insns[190].Dst != asm.R1 || insns[190].Src != asm.R6 || insns[190].Offset != 20 ||
		insns[191].OpCode != asm.LoadMemOp(asm.Word) || insns[191].Dst != asm.R2 || insns[191].Src != asm.RFP || insns[191].Offset != -128 ||
		insns[192].OpCode != asm.JNE.Op(asm.RegSource) || insns[192].Dst != asm.R2 || insns[192].Src != asm.R1 || insns[192].Offset != -140 ||
		insns[193].OpCode != asm.Mov.Op(asm.ImmSource) || insns[193].Dst != asm.R1 || insns[193].Constant != 1 ||
		insns[194].Dst != asm.R8 || insns[194].Src != asm.R1 || insns[194].Offset != wantAtomicOffset ||
		insns[195].OpCode != asm.Ja.Op(asm.ImmSource) || insns[195].Offset != -143 ||
		insns[277].OpCode != asm.Mov.Op(asm.ImmSource) || insns[277].Dst != asm.R0 || insns[277].Constant != 0 ||
		insns[278].OpCode != asm.Exit.Op(asm.ImmSource) {
		return fmt.Errorf("embedded bridge %s cpu_state counter tail signature mismatch", name)
	}

	work := append(asm.Instructions(nil), insns...)
	// Retarget successful bpf_map_delete_elem(&packets, &address) jump past
	// the excised state->deleted increment straight to bpf_get_current_pid_tgid.
	work[104].Offset = 15

	removed := func(idx int) bool {
		return (idx >= 1 && idx <= 2) ||
			(idx >= 4 && idx <= 58) ||
			(idx >= 116 && idx <= 118) ||
			(idx >= 138 && idx <= 139) ||
			idx == 141 ||
			(idx >= 164 && idx <= 169) ||
			(idx >= 190 && idx <= 195)
	}
	patched, err := exciseInstructionsPreservingJumps(work, removed)
	if err != nil {
		return fmt.Errorf("embedded bridge %s excise cpu_state block: %w", name, err)
	}
	if len(patched) != 204 {
		return fmt.Errorf("embedded bridge %s excised len = %d, want 204", name, len(patched))
	}

	const (
		branchToCfgIdx = 78  // orig[140]: *(u64 *)(r10 - 192) = r0
		resumeSlotsIdx = 79  // orig[142]: r2 = r10 (read_slots lookup)
		exitZeroIdx    = 202 // orig[277]: r0 = 0
		cfgCheckIdx    = 204 // appended out-of-line config->epoch verification
	)
	saveReaderMeta := patched[branchToCfgIdx].Metadata
	patched[branchToCfgIdx] = asm.Instruction{
		OpCode:   asm.Ja.Op(asm.ImmSource),
		Metadata: saveReaderMeta,
	}
	patched = append(patched,
		asm.StoreMem(asm.RFP, -192, asm.R0, asm.DWord),
		asm.StoreMem(asm.RFP, -116, asm.R1, asm.Word),
		asm.Mov.Imm(asm.R1, 0),
		asm.StoreMem(asm.RFP, -8, asm.R1, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.LoadMapPtr(asm.R1, 0).WithReference("config"),
		asm.FnMapLookupElem.Call(),
		asm.Instruction{OpCode: asm.JEq.Op(asm.ImmSource), Dst: asm.R0, Constant: 0},
		asm.LoadMem(asm.R2, asm.R0, 8, asm.DWord),
		asm.Instruction{OpCode: asm.JNE.Op(asm.RegSource), Dst: asm.R9, Src: asm.R2},
		asm.Instruction{OpCode: asm.Ja.Op(asm.ImmSource)},
	)

	rawSlot := make([]int, len(patched))
	raw := 0
	for i, ins := range patched {
		rawSlot[i] = raw
		raw += int(ins.Size() / asm.InstructionSize)
	}
	setJumpTarget := func(fromIdx, toIdx int) error {
		width := int(patched[fromIdx].Size() / asm.InstructionSize)
		delta := rawSlot[toIdx] - (rawSlot[fromIdx] + width)
		if delta < -32768 || delta > 32767 {
			return fmt.Errorf("jump delta %d overflows int16 (%d -> %d)", delta, fromIdx, toIdx)
		}
		patched[fromIdx].Offset = int16(delta)
		return nil
	}
	for _, edge := range [][2]int{
		{branchToCfgIdx, cfgCheckIdx},
		{cfgCheckIdx + 8, exitZeroIdx},
		{cfgCheckIdx + 10, exitZeroIdx},
		{cfgCheckIdx + 11, resumeSlotsIdx},
	} {
		if err := setJumpTarget(edge[0], edge[1]); err != nil {
			return fmt.Errorf("embedded bridge %s %w", name, err)
		}
	}

	prog.Instructions = patched
	return nil
}

func isPCRelativeJump(ins asm.Instruction) bool {
	if !ins.OpCode.Class().IsJump() {
		return false
	}
	jop := ins.OpCode.JumpOp()
	return jop != asm.Call && jop != asm.Exit
}

func exciseInstructionsPreservingJumps(insns asm.Instructions, remove func(idx int) bool) (asm.Instructions, error) {
	oldSlot := make([]int, len(insns))
	slotToOldIdx := make(map[int]int, len(insns))
	raw := 0
	for i, ins := range insns {
		oldSlot[i] = raw
		slotToOldIdx[raw] = i
		raw += int(ins.Size() / asm.InstructionSize)
	}

	jumpTargetOldIdx := make(map[int]int)
	oldToNewIdx := make([]int, len(insns))
	out := make(asm.Instructions, 0, len(insns))
	for i, ins := range insns {
		if remove(i) {
			oldToNewIdx[i] = -1
			continue
		}
		if ins.IsFunctionReference() {
			return nil, fmt.Errorf("unexpected bpf-to-bpf function reference at insn %d", i)
		}
		if isPCRelativeJump(ins) && ins.Reference() == "" {
			if ins.OpCode.Class() == asm.Jump32Class {
				return nil, fmt.Errorf("unexpected jump32 at insn %d", i)
			}
			width := int(ins.Size() / asm.InstructionSize)
			targetSlot := oldSlot[i] + width + int(ins.Offset)
			targetIdx, ok := slotToOldIdx[targetSlot]
			if !ok {
				return nil, fmt.Errorf("jump at insn %d targets non-boundary raw slot %d", i, targetSlot)
			}
			jumpTargetOldIdx[len(out)] = targetIdx
		}
		oldToNewIdx[i] = len(out)
		out = append(out, ins)
	}

	newSlot := make([]int, len(out))
	raw = 0
	for i, ins := range out {
		newSlot[i] = raw
		raw += int(ins.Size() / asm.InstructionSize)
	}

	for newIdx, oldTarget := range jumpTargetOldIdx {
		newTarget := oldToNewIdx[oldTarget]
		if newTarget < 0 {
			return nil, fmt.Errorf("surviving jump at new insn %d targets excised old insn %d", newIdx, oldTarget)
		}
		width := int(out[newIdx].Size() / asm.InstructionSize)
		delta := newSlot[newTarget] - (newSlot[newIdx] + width)
		if delta < -32768 || delta > 32767 {
			return nil, fmt.Errorf("recomputed jump delta %d overflows int16 at new insn %d", delta, newIdx)
		}
		out[newIdx].Offset = int16(delta)
	}
	return out, nil
}

// PrepareEngineSenderSpec loads the embedded sender proof ELF spec for arch,
// validates its ABI invariants, strips the unused pilot tuple/egress objects,
// makes counters BPF_F_MMAPABLE for zero-syscall atomic reads, adds the O(1)
// new-actor queue map, and patches observe_send in-place for machine-wide
// cgroup v2 capture (gated on scope[0] != 0) plus new-actor queue notification.
func PrepareEngineSenderSpec(arch string, maxActors, queueEntries uint32) (*ebpf.CollectionSpec, error) {
	if maxActors == 0 {
		maxActors = DefaultEngineMaxActors
	}
	if queueEntries == 0 {
		queueEntries = DefaultEngineActorEventQueue
	}
	spec, err := LoadEmbeddedProofSpec(arch)
	if err != nil {
		return nil, err
	}
	if len(spec.Programs) != 3 || len(spec.Maps) != 4 {
		return nil, errors.New("embedded sender spec: unexpected program/map count")
	}
	for name, want := range map[string][3]uint32{
		"actors":   {32, 32, RecordLimit},
		"tuples":   {12, 16, RecordLimit},
		"counters": {4, 8, 7},
		"scope":    {4, 8, 1},
	} {
		m := spec.Maps[name]
		if m == nil || m.KeySize != want[0] || m.ValueSize != want[1] || m.MaxEntries != want[2] {
			return nil, fmt.Errorf("embedded sender spec: map ABI mismatch for %s", name)
		}
	}
	for name, kind := range map[string]ebpf.ProgramType{
		"initialize_cookie": ebpf.CGroupSock,
		"observe_packet":    ebpf.CGroupSKB,
		"observe_send":      ebpf.Kprobe,
	} {
		p := spec.Programs[name]
		if p == nil || p.Type != kind || p.License != "Dual MIT/GPL" {
			return nil, fmt.Errorf("embedded sender spec: program mismatch for %s", name)
		}
	}

	delete(spec.Programs, "observe_packet")
	delete(spec.Maps, "tuples")

	spec.Maps["actors"].MaxEntries = maxActors
	spec.Maps["counters"].Flags |= bpfMapFlagMmapable
	spec.Maps["actor_events"] = &ebpf.MapSpec{
		Name:       "actor_events",
		Type:       ebpf.Queue,
		KeySize:    0,
		ValueSize:  uint32(unsafe.Sizeof(QueuedActorEvent{})),
		MaxEntries: queueEntries,
	}

	obs := spec.Programs["observe_send"]
	insns := obs.Instructions
	if len(insns) != 187 {
		return nil, fmt.Errorf("embedded observe_send instruction count = %d, want 187", len(insns))
	}
	if insns[8].OpCode != asm.LoadMemOp(asm.DWord) || insns[8].Dst != asm.R6 || insns[8].Src != asm.R0 || insns[8].Offset != 0 ||
		insns[9].OpCode != asm.JEq.Op(asm.ImmSource) || insns[9].Dst != asm.R6 || insns[9].Constant != 0 ||
		insns[10].OpCode != asm.Call.Op(asm.ImmSource) || insns[10].Constant != int64(asm.FnGetCurrentCgroupId) ||
		insns[11].OpCode != asm.JNE.Op(asm.RegSource) || insns[11].Dst != asm.R6 || insns[11].Src != asm.R0 {
		return nil, errors.New("embedded observe_send scope gate signature mismatch")
	}
	if insns[150].OpCode != asm.Mov.Op(asm.RegSource) || insns[150].Dst != asm.R2 || insns[150].Src != asm.RFP ||
		insns[151].OpCode != asm.Add.Op(asm.ImmSource) || insns[151].Dst != asm.R2 || insns[151].Constant != -88 ||
		insns[152].OpCode != asm.Mov.Op(asm.RegSource) || insns[152].Dst != asm.R3 || insns[152].Src != asm.RFP ||
		insns[153].OpCode != asm.Add.Op(asm.ImmSource) || insns[153].Dst != asm.R3 || insns[153].Constant != -120 ||
		!insns[154].IsLoadFromMap() || insns[154].Reference() != "actors" ||
		insns[155].OpCode != asm.Mov.Op(asm.ImmSource) || insns[155].Dst != asm.R4 || insns[155].Constant != 1 ||
		insns[156].OpCode != asm.Call.Op(asm.ImmSource) || insns[156].Constant != int64(asm.FnMapUpdateElem) ||
		insns[157].OpCode != asm.JEq.Op(asm.ImmSource) || insns[157].Dst != asm.R0 || insns[157].Constant != -17 ||
		insns[158].OpCode != asm.JEq.Op(asm.ImmSource) || insns[158].Dst != asm.R0 || insns[158].Constant != 0 || insns[158].Offset != 29 ||
		insns[185].OpCode != asm.Mov.Op(asm.ImmSource) || insns[185].Dst != asm.R0 || insns[185].Constant != 0 ||
		insns[186].OpCode != asm.Exit.Op(asm.ImmSource) {
		return nil, errors.New("embedded observe_send actor-insert tail signature mismatch")
	}

	// Replace exact leaf-cgroup equality check with machine-wide enable gate:
	// scope[0] == 0 exits via insns[9]; scope[0] != 0 sets r0 = r6 so insns[11]
	// falls through without changing any existing instruction index or BTF line.
	movGate := asm.Mov.Reg(asm.R0, asm.R6)
	movGate.Metadata = insns[10].Metadata
	insns[10] = movGate

	// When bpf_map_update_elem(&actors, &key, &value, BPF_NOEXIST) succeeds
	// (r0 == 0), branch past the original epilogue to push the initialized
	// 64-byte stack frame [rfp-120..rfp-56) into actor_events and bump
	// counters[1] (NewActors; counters[6] on queue overflow). Copy BTF line
	// metadata before attaching the symbol reference so Metadata retains both.
	jeqEmit := asm.JEq.Imm(asm.R0, 0, "")
	jeqEmit.Metadata = insns[158].Metadata
	insns[158] = jeqEmit.WithReference("ns_emit_new_actor")

	insns = append(insns,
		asm.LoadMapPtr(asm.R1, 0).WithReference("actor_events").WithSymbol("ns_emit_new_actor"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -120),
		asm.Mov.Imm(asm.R3, 0),
		asm.FnMapPushElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "ns_inc_new_actors"),
		asm.Mov.Imm(asm.R1, 6),
		asm.StoreMem(asm.RFP, -4, asm.R1, asm.Word),
		asm.LoadMapPtr(asm.R1, 0).WithReference("counters"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "ns_inc_new_actors"),
		asm.Mov.Imm(asm.R1, 1),
		asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R1, 1).WithSymbol("ns_inc_new_actors"),
		asm.StoreMem(asm.RFP, -4, asm.R1, asm.Word),
		asm.LoadMapPtr(asm.R1, 0).WithReference("counters"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "ns_emit_done"),
		asm.Mov.Imm(asm.R1, 1),
		asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("ns_emit_done"),
		asm.Return(),
	)
	obs.Instructions = insns
	return spec, nil
}
