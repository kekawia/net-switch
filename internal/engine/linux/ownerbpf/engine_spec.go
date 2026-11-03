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
	return spec, packetSlots, nil
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
