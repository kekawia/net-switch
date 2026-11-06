package ownerbpf

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
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

// stripUnusedBridgeTerminalCPUStats rewrites production consume and freed so:
//  1. Non-TUN skbs exit inline after a single lockless bpf_map_lookup_elem(&packets)
//     check (8 instructions, zero spinlocks, zero probe reads).
//  2. Matched TUN skbs read PacketRecord fields directly from the packets map
//     value without an intermediate 128-byte stack copy, fast-path already-stamped
//     readers without bus-locked stamp_guard XADDs, and defer
//     bpf_map_delete_elem(&packets, &address) until immediately before exit so
//     htab_unlock_bucket's local_irq_restore occurs with zero remaining BPF body
//     work while unconditional retirement and delete-fault accounting hold on
//     every matched and unmatched path.
func stripUnusedBridgeTerminalCPUStats(name string, prog *ebpf.ProgramSpec) error {
	if prog == nil {
		return fmt.Errorf("embedded bridge %s program missing", name)
	}
	insns := prog.Instructions
	if len(insns) != 279 {
		return fmt.Errorf("embedded bridge %s instruction count = %d, want 279", name, len(insns))
	}
	var terminalKind int32
	wantAtomicOffset := int16(56)
	switch name {
	case "consume":
		terminalKind = TerminalConsume
	case "freed":
		terminalKind = TerminalFree
		wantAtomicOffset = 64
	default:
		return fmt.Errorf("unexpected bridge terminal program %q", name)
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
	if insns[172].OpCode != asm.Call.Op(asm.ImmSource) || insns[172].Constant != int64(asm.FnGetCurrentTask) ||
		insns[173].OpCode != asm.Mov.Op(asm.ImmSource) || insns[173].Dst != asm.R1 || insns[173].Constant != 0 ||
		btf.CORERelocationMetadata(&insns[173]) == nil ||
		insns[174].OpCode != asm.Add.Op(asm.RegSource) || insns[174].Dst != asm.R0 || insns[174].Src != asm.R1 ||
		insns[179].OpCode != asm.Call.Op(asm.ImmSource) || insns[179].Constant != int64(asm.FnProbeReadKernel) {
		return fmt.Errorf("embedded bridge %s task->start_boottime CO-RE signature mismatch", name)
	}
	for idx := 59; idx < len(insns); idx++ {
		if idx != 173 && btf.CORERelocationMetadata(&insns[idx]) != nil {
			return fmt.Errorf("embedded bridge %s unexpected CO-RE relocation at insn %d", name, idx)
		}
	}
	if insns[194].Dst != asm.R8 || insns[194].Src != asm.R1 || insns[194].Offset != wantAtomicOffset ||
		insns[277].OpCode != asm.Mov.Op(asm.ImmSource) || insns[277].Dst != asm.R0 || insns[277].Constant != 0 ||
		insns[278].OpCode != asm.Exit.Op(asm.ImmSource) {
		return fmt.Errorf("embedded bridge %s cpu_state counter tail signature mismatch", name)
	}

	coreTaskStartOffsetInsn := insns[173]

	type jumpPatch struct {
		fromIdx int
		label   string
	}
	labels := make(map[string]int, 10)
	jumps := make([]jumpPatch, 0, 24)
	out := make(asm.Instructions, 0, 176)
	mark := func(label string) {
		labels[label] = len(out)
	}
	emit := func(seq ...asm.Instruction) {
		out = append(out, seq...)
	}
	emitJump := func(ins asm.Instruction, label string) {
		jumps = append(jumps, jumpPatch{fromIdx: len(out), label: label})
		out = append(out, ins)
	}

	entryLoad := asm.LoadMem(asm.R2, asm.R1, 0, asm.DWord)
	entryLoad.Metadata = insns[0].Metadata
	emit(
		entryLoad,
		asm.StoreMem(asm.RFP, -8, asm.R2, asm.DWord),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.LoadMapPtr(asm.R1, 0).WithReference("packets"),
		asm.FnMapLookupElem.Call(),
	)
	emitJump(asm.Instruction{OpCode: asm.JNE.Op(asm.ImmSource), Dst: asm.R0, Constant: 0}, "tun_hit")
	emit(
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	)

	mark("tun_hit")
	emit(
		asm.Mov.Reg(asm.R7, asm.R0),
		asm.FnGetCurrentPidTgid.Call(),
		asm.StoreMem(asm.RFP, -12, asm.R0, asm.Word),
		asm.RSh.Imm(asm.R0, 32),
		asm.StoreMem(asm.RFP, -16, asm.R0, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -16),
		asm.LoadMapPtr(asm.R1, 0).WithReference("readers"),
		asm.FnMapLookupElem.Call(),
	)
	emitJump(asm.Instruction{OpCode: asm.JEq.Op(asm.ImmSource), Dst: asm.R0, Constant: 0}, "retire_unmatched")
	emit(
		asm.Mov.Reg(asm.R6, asm.R0),
		asm.LoadMem(asm.R1, asm.R6, 0, asm.Word),
	)
	emitJump(asm.Instruction{OpCode: asm.JGT.Op(asm.ImmSource), Dst: asm.R1, Constant: ReaderLimit - 1}, "retire_unmatched")
	emit(
		asm.LoadMem(asm.R9, asm.R7, 8, asm.DWord),
		asm.LoadMem(asm.R2, asm.R6, 24, asm.DWord),
	)
	emitJump(asm.Instruction{OpCode: asm.JNE.Op(asm.RegSource), Dst: asm.R2, Src: asm.R9}, "retire_unmatched")
	emit(
		asm.LoadMem(asm.R2, asm.R6, 4, asm.Word),
		asm.LoadMem(asm.R3, asm.R7, 16, asm.Word),
	)
	emitJump(asm.Instruction{OpCode: asm.JNE.Op(asm.RegSource), Dst: asm.R2, Src: asm.R3}, "retire_unmatched")
	emit(
		asm.LoadMem(asm.R2, asm.R6, 8, asm.Word),
		asm.LoadMem(asm.R3, asm.R7, 20, asm.Word),
	)
	emitJump(asm.Instruction{OpCode: asm.JNE.Op(asm.RegSource), Dst: asm.R2, Src: asm.R3}, "retire_unmatched")

	emit(
		asm.Mov.Imm(asm.R1, 0),
		asm.StoreMem(asm.RFP, -16, asm.R1, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -16),
		asm.LoadMapPtr(asm.R1, 0).WithReference("config"),
		asm.FnMapLookupElem.Call(),
	)
	emitJump(asm.Instruction{OpCode: asm.JEq.Op(asm.ImmSource), Dst: asm.R0, Constant: 0}, "retire_unmatched")
	emit(asm.LoadMem(asm.R2, asm.R0, 8, asm.DWord))
	emitJump(asm.Instruction{OpCode: asm.JNE.Op(asm.RegSource), Dst: asm.R9, Src: asm.R2}, "retire_unmatched")

	emit(
		asm.LoadMem(asm.R1, asm.R6, 0, asm.Word),
		asm.StoreMem(asm.RFP, -16, asm.R1, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -16),
		asm.LoadMapPtr(asm.R1, 0).WithReference("read_slots"),
		asm.FnMapLookupElem.Call(),
	)
	emitJump(asm.Instruction{OpCode: asm.JEq.Op(asm.ImmSource), Dst: asm.R0, Constant: 0}, "retire_unmatched")
	emit(
		asm.Mov.Reg(asm.R8, asm.R0),
		asm.LoadMem(asm.R1, asm.R8, 0, asm.Word),
	)
	emitJump(asm.Instruction{OpCode: asm.JNE.Op(asm.ImmSource), Dst: asm.R1, Constant: ProvenanceABI}, "retire_unmatched")
	emit(asm.LoadMem(asm.R1, asm.R8, 32, asm.DWord))
	emitJump(asm.Instruction{OpCode: asm.JNE.Op(asm.ImmSource), Dst: asm.R1, Constant: 1}, "retire_unmatched")
	emit(
		asm.LoadMem(asm.R1, asm.R6, 16, asm.DWord),
		asm.LoadMem(asm.R2, asm.R8, 8, asm.DWord),
	)
	emitJump(asm.Instruction{OpCode: asm.JNE.Op(asm.RegSource), Dst: asm.R2, Src: asm.R1}, "retire_unmatched")
	emit(asm.LoadMem(asm.R2, asm.R8, 16, asm.DWord))
	emitJump(asm.Instruction{OpCode: asm.JNE.Op(asm.RegSource), Dst: asm.R2, Src: asm.R9}, "retire_unmatched")
	emit(asm.LoadMem(asm.R1, asm.R8, 24, asm.DWord))
	emitJump(asm.Instruction{OpCode: asm.JEq.Op(asm.ImmSource), Dst: asm.R1, Constant: 0}, "retire_unmatched")

	// Count before stamping: a nested attempt must make the read ambiguous.
	emit(
		asm.Mov.Imm(asm.R1, 1),
		asm.AddAtomic.Mem(asm.R8, asm.R1, asm.DWord, 64),
		asm.Mov.Imm(asm.R1, 0),
		asm.StoreMem(asm.RFP, -24, asm.R1, asm.DWord),
		asm.FnGetCurrentTask.Call(),
		coreTaskStartOffsetInsn,
		asm.Add.Reg(asm.R0, asm.R1),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -24),
		asm.Mov.Imm(asm.R2, 8),
		asm.Mov.Reg(asm.R3, asm.R0),
		asm.FnProbeReadKernel.Call(),
	)
	emitJump(asm.Instruction{OpCode: asm.JNE.Op(asm.ImmSource), Dst: asm.R0, Constant: 0}, "stamp_fault")
	emit(asm.LoadMem(asm.R9, asm.RFP, -24, asm.DWord))
	emitJump(asm.Instruction{OpCode: asm.JEq.Op(asm.ImmSource), Dst: asm.R9, Constant: 0}, "stamp_fault")

	// Fast-path already-stamped readers without bus-locked stamp_guard XADDs.
	emit(asm.LoadMem(asm.R1, asm.R6, 40, asm.DWord))
	emitJump(asm.Instruction{OpCode: asm.JNE.Op(asm.ImmSource), Dst: asm.R1, Constant: 0}, "stamp_slow")
	emit(
		asm.LoadMem(asm.R1, asm.R6, 12, asm.Word),
		asm.And.Imm(asm.R1, ReaderStamped),
	)
	emitJump(asm.Instruction{OpCode: asm.JEq.Op(asm.ImmSource), Dst: asm.R1, Constant: 0}, "stamp_slow")
	emit(asm.LoadMem(asm.R2, asm.R6, 32, asm.DWord))
	emitJump(asm.Instruction{OpCode: asm.JNE.Op(asm.RegSource), Dst: asm.R2, Src: asm.R9}, "stamp_slow")
	emitJump(asm.Instruction{OpCode: asm.Ja.Op(asm.ImmSource)}, "publish_slot")

	mark("stamp_slow")
	emit(
		asm.Mov.Imm(asm.R1, 1),
		asm.AddAtomic.Mem(asm.R6, asm.R1, asm.DWord, 40),
		asm.LoadMem(asm.R2, asm.R6, 40, asm.DWord),
	)
	emitJump(asm.Instruction{OpCode: asm.JEq.Op(asm.ImmSource), Dst: asm.R2, Constant: 1}, "stamp_guarded")
	emit(
		asm.Mov.Imm(asm.R1, -1),
		asm.AddAtomic.Mem(asm.R6, asm.R1, asm.DWord, 40),
	)
	emitJump(asm.Instruction{OpCode: asm.Ja.Op(asm.ImmSource)}, "retire_unmatched")

	mark("stamp_guarded")
	emit(
		asm.LoadMem(asm.R1, asm.R6, 12, asm.Word),
		asm.And.Imm(asm.R1, ReaderStamped),
	)
	emitJump(asm.Instruction{OpCode: asm.JNE.Op(asm.ImmSource), Dst: asm.R1, Constant: 0}, "stamp_check_slow")
	emit(
		asm.StoreMem(asm.R6, 32, asm.R9, asm.DWord),
		asm.Mov.Imm(asm.R1, ReaderStamped),
		asm.StoreMem(asm.R6, 12, asm.R1, asm.Word),
	)

	mark("stamp_check_slow")
	emit(
		asm.LoadMem(asm.R2, asm.R6, 32, asm.DWord),
		asm.Mov.Imm(asm.R1, -1),
		asm.AddAtomic.Mem(asm.R6, asm.R1, asm.DWord, 40),
	)
	emitJump(asm.Instruction{OpCode: asm.JNE.Op(asm.RegSource), Dst: asm.R2, Src: asm.R9}, "stamp_fault")

	mark("publish_slot")
	emit(
		asm.LoadMem(asm.R1, asm.R8, 24, asm.DWord),
		asm.StoreMem(asm.R8, 72, asm.R1, asm.DWord),
		asm.LoadMem(asm.R1, asm.R6, 16, asm.DWord),
		asm.StoreMem(asm.R8, 80, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R1, terminalKind),
		asm.StoreMem(asm.R8, 88, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.R7, 4, asm.Word),
		asm.StoreMem(asm.R8, 92, asm.R1, asm.Word),
	)
	for off := int16(0); off < 128; off += 8 {
		emit(
			asm.LoadMem(asm.R1, asm.R7, off, asm.DWord),
			asm.StoreMem(asm.R8, 128+off, asm.R1, asm.DWord),
		)
	}
	emit(
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.LoadMapPtr(asm.R1, 0).WithReference("packets"),
		asm.FnMapDeleteElem.Call(),
	)
	emitJump(asm.Instruction{OpCode: asm.JNE.Op(asm.ImmSource), Dst: asm.R0, Constant: 0}, "delete_fault_matched")
	emit(
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	)

	mark("stamp_fault")
	emit(
		asm.Mov.Imm(asm.R1, 0),
		asm.StoreMem(asm.RFP, -16, asm.R1, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -16),
		asm.LoadMapPtr(asm.R1, 0).WithReference("health"),
		asm.FnMapLookupElem.Call(),
	)
	emitJump(asm.Instruction{OpCode: asm.JEq.Op(asm.ImmSource), Dst: asm.R0, Constant: 0}, "retire_unmatched")
	emit(
		asm.Mov.Imm(asm.R1, 1),
		asm.AddAtomic.Mem(asm.R0, asm.R1, asm.DWord, 0),
		asm.AddAtomic.Mem(asm.R0, asm.R1, asm.DWord, 56),
	)

	mark("retire_unmatched")
	emit(
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.LoadMapPtr(asm.R1, 0).WithReference("packets"),
		asm.FnMapDeleteElem.Call(),
	)
	emitJump(asm.Instruction{OpCode: asm.JNE.Op(asm.ImmSource), Dst: asm.R0, Constant: 0}, "delete_fault_health")
	emit(
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	)

	mark("delete_fault_matched")
	emit(
		asm.Mov.Imm(asm.R1, 0),
		asm.StoreMem(asm.R8, 92, asm.R1, asm.Word),
		asm.StoreMem(asm.R8, 132, asm.R1, asm.Word),
	)

	mark("delete_fault_health")
	emit(
		asm.Mov.Imm(asm.R1, 0),
		asm.StoreMem(asm.RFP, -16, asm.R1, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -16),
		asm.LoadMapPtr(asm.R1, 0).WithReference("health"),
		asm.FnMapLookupElem.Call(),
	)
	emitJump(asm.Instruction{OpCode: asm.JEq.Op(asm.ImmSource), Dst: asm.R0, Constant: 0}, "exit_cold")
	emit(
		asm.Mov.Imm(asm.R1, 1),
		asm.AddAtomic.Mem(asm.R0, asm.R1, asm.DWord, 0),
		asm.AddAtomic.Mem(asm.R0, asm.R1, asm.DWord, 48),
	)

	mark("exit_cold")
	emit(
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	)

	rawSlot := make([]int, len(out))
	raw := 0
	for i, ins := range out {
		rawSlot[i] = raw
		raw += int(ins.Size() / asm.InstructionSize)
	}
	for _, jp := range jumps {
		toIdx, ok := labels[jp.label]
		if !ok {
			return fmt.Errorf("embedded bridge %s missing jump label %q", name, jp.label)
		}
		width := int(out[jp.fromIdx].Size() / asm.InstructionSize)
		delta := rawSlot[toIdx] - (rawSlot[jp.fromIdx] + width)
		if delta < -32768 || delta > 32767 {
			return fmt.Errorf("embedded bridge %s jump delta %d overflows int16 (%d -> %s)", name, delta, jp.fromIdx, jp.label)
		}
		out[jp.fromIdx].Offset = int16(delta)
	}

	prog.Instructions = out
	return nil
}

// ExpandFaultProofHoldQuantum widens the fixture-only proof_hold straight-line
// bpf_ktime_get_ns quantum in fault_x86_bpfel.o / fault_arm64_bpfel.o from 32
// calls to 128 calls per loop iteration without adding any jump instructions.
// This raises the uncontested hold window (~3 ms -> ~12 ms on floor-5.8-amd64
// KVM, still capped at 20 ms via now-start >= 20_000_000) while keeping the
// Linux 5.8 verifier's explored jump-state count unchanged at 4,466 (< 8,192).
func ExpandFaultProofHoldQuantum(spec *ebpf.CollectionSpec) error {
	if spec == nil || spec.Maps["faults"] == nil {
		return nil
	}
	const (
		origTickCalls  = 32
		extraTickCalls = 96
	)
	extra := make(asm.Instructions, extraTickCalls)
	for i := range extra {
		extra[i] = asm.FnKtimeGetNs.Call()
	}
	for _, tc := range []struct {
		name           string
		quantumInitIdx int
	}{
		{"capture", 338},
		{"consume", 377},
		{"freed", 377},
	} {
		prog := spec.Programs[tc.name]
		if prog == nil {
			return fmt.Errorf("fault bridge %s program missing", tc.name)
		}
		insns := prog.Instructions
		qIdx := tc.quantumInitIdx
		firstTickIdx := qIdx + 7
		lastTickIdx := firstTickIdx + origTickCalls - 1
		backJumpIdx := lastTickIdx + 5
		if backJumpIdx >= len(insns) ||
			insns[qIdx].OpCode != asm.Mov.Op(asm.ImmSource) || insns[qIdx].Dst != asm.R9 || insns[qIdx].Constant != 2500 ||
			insns[qIdx+5].OpCode != asm.JNE.Op(asm.ImmSource) || insns[qIdx+5].Dst != asm.R1 || insns[qIdx+5].Constant != 0 || insns[qIdx+5].Offset != 39 ||
			insns[qIdx+6].OpCode != asm.JGT.Op(asm.ImmSource) || insns[qIdx+6].Dst != asm.R0 || insns[qIdx+6].Constant != 19999999 || insns[qIdx+6].Offset != 38 ||
			insns[backJumpIdx].OpCode != asm.JNE.Op(asm.ImmSource) || insns[backJumpIdx].Dst != asm.R1 || insns[backJumpIdx].Constant != 0 || insns[backJumpIdx].Offset != -41 {
			return fmt.Errorf("fault bridge %s proof_hold signature mismatch", tc.name)
		}
		for idx := firstTickIdx; idx <= lastTickIdx; idx++ {
			if insns[idx].OpCode != asm.Call.Op(asm.ImmSource) || insns[idx].Constant != int64(asm.FnKtimeGetNs) {
				return fmt.Errorf("fault bridge %s expected ktime_get_ns call at insn %d", tc.name, idx)
			}
		}
		expanded, err := insertInstructionsPreservingJumps(insns, lastTickIdx, extra)
		if err != nil {
			return fmt.Errorf("fault bridge %s expand proof_hold: %w", tc.name, err)
		}
		prog.Instructions = expanded
	}
	return nil
}

func insertInstructionsPreservingJumps(insns asm.Instructions, afterIdx int, extra asm.Instructions) (asm.Instructions, error) {
	if afterIdx < 0 || afterIdx >= len(insns) {
		return nil, fmt.Errorf("insert index %d out of range [0, %d)", afterIdx, len(insns))
	}
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
	out := make(asm.Instructions, 0, len(insns)+len(extra))
	for i, ins := range insns {
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
		if i == afterIdx {
			out = append(out, extra...)
		}
	}

	newSlot := make([]int, len(out))
	raw = 0
	for i, ins := range out {
		newSlot[i] = raw
		raw += int(ins.Size() / asm.InstructionSize)
	}
	for newIdx, oldTarget := range jumpTargetOldIdx {
		newTarget := oldToNewIdx[oldTarget]
		width := int(out[newIdx].Size() / asm.InstructionSize)
		delta := newSlot[newTarget] - (newSlot[newIdx] + width)
		if delta < -32768 || delta > 32767 {
			return nil, fmt.Errorf("recomputed jump delta %d overflows int16 at new insn %d", delta, newIdx)
		}
		out[newIdx].Offset = int16(delta)
	}
	return out, nil
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
