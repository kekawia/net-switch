package ownerbpf

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"runtime"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

func TestEmbeddedBPFObjectsMatchManifestAndParse(t *testing.T) {
	manifestBytes, err := os.ReadFile("../../../../docs/linux-owner-provenance-hooks.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Generator struct {
			Objects map[string]struct {
				SHA256 string `json:"sha256"`
			} `json:"objects"`
		} `json:"generator"`
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}

	bridgeRaw, err := EmbeddedBridgeObjectBytes()
	if err != nil {
		t.Fatal("decode embedded bridge:", err)
	}
	bridgeSum := sha256.Sum256(bridgeRaw)
	bridgeHex := hex.EncodeToString(bridgeSum[:])
	if bridgeHex != EmbeddedBridgeSHA256 ||
		bridgeHex != manifest.Generator.Objects["bridge_x86_bpfel.o"].SHA256 ||
		bridgeHex != manifest.Generator.Objects["bridge_arm64_bpfel.o"].SHA256 {
		t.Fatalf("embedded bridge sha256 = %s, want %s", bridgeHex, EmbeddedBridgeSHA256)
	}

	for _, tc := range []struct {
		arch string
		file string
		want string
	}{
		{"amd64", "proof_x86_bpfel.o", EmbeddedProofAMD64SHA256},
		{"arm64", "proof_arm64_bpfel.o", EmbeddedProofARM64SHA256},
	} {
		raw, err := EmbeddedProofObjectBytes(tc.arch)
		if err != nil {
			t.Fatalf("decode embedded proof %s: %v", tc.arch, err)
		}
		sum := sha256.Sum256(raw)
		gotHex := hex.EncodeToString(sum[:])
		if gotHex != tc.want || gotHex != manifest.Generator.Objects[tc.file].SHA256 {
			t.Fatalf("embedded proof %s sha256 = %s, want %s", tc.arch, gotHex, tc.want)
		}
	}

	bridgeSpec, err := LoadEmbeddedBridgeSpec()
	if err != nil {
		t.Fatal("LoadEmbeddedBridgeSpec:", err)
	}
	if bridgeSpec.Maps["packets"] == nil || bridgeSpec.Programs["capture"] == nil ||
		bridgeSpec.Programs["consume"] == nil || bridgeSpec.Programs["freed"] == nil ||
		bridgeSpec.Programs["init_egress_cookie"] == nil {
		t.Fatalf("unexpected embedded bridge spec: maps=%d progs=%d", len(bridgeSpec.Maps), len(bridgeSpec.Programs))
	}

	for _, arch := range []string{"amd64", "arm64"} {
		spec, err := LoadEmbeddedProofSpec(arch)
		if err != nil {
			t.Fatalf("LoadEmbeddedProofSpec(%s): %v", arch, err)
		}
		obs := spec.Programs["observe_send"]
		if obs == nil || spec.Maps["actors"] == nil || spec.Maps["scope"] == nil {
			t.Fatalf("unexpected embedded proof spec (%s)", arch)
		}
		if len(obs.Instructions) < 12 {
			t.Fatalf("unexpected short observe_send program (%s): %d insns", arch, len(obs.Instructions))
		}
	}
}

type fakeFD int

func (f fakeFD) FD() int { return int(f) }

func TestPrepareEngineBridgeAndSenderSpecs(t *testing.T) {
	bridgeSpec, slots, err := PrepareEngineBridgeSpec(16384, 8, ReaderLimit)
	if err != nil {
		t.Fatal("PrepareEngineBridgeSpec:", err)
	}
	if slots != 32768 {
		t.Fatalf("packetSlots = %d, want 32768", slots)
	}
	if bridgeSpec.Programs["perf_consume"] != nil {
		t.Fatal("production bridge spec must strip tracefs-dependent perf_consume")
	}
	if len(bridgeSpec.Programs) != 4 || bridgeSpec.Maps["packets"].MaxEntries != 32768 {
		t.Fatalf("unexpected bridge spec: progs=%d packets.MaxEntries=%d", len(bridgeSpec.Programs), bridgeSpec.Maps["packets"].MaxEntries)
	}
	for _, progName := range []string{"consume", "freed"} {
		cp := bridgeSpec.Programs[progName].Copy()
		insns := cp.Instructions
		if len(insns) != 230 {
			t.Fatalf("%s patched instruction count = %d, want 230", progName, len(insns))
		}
		if btf.FuncMetadata(&insns[0]) == nil || insns[0].Source() == nil {
			t.Fatalf("%s insns[0] lost BTF FuncMetadata or initial LineInfo", progName)
		}
		if !insns[18].IsLoadFromMap() || insns[18].Reference() != "packets" {
			t.Fatalf("%s insns[18] = %v (ref=%q), want LoadMapPtr packets immediately after config/cpu_state lookup", progName, insns[18], insns[18].Reference())
		}
		probeReads := 0
		for idx, ins := range insns {
			if ins.OpCode == asm.Call.Op(asm.ImmSource) && ins.Constant == int64(asm.FnProbeReadKernel) {
				if idx < 18 {
					t.Fatalf("%s retained pre-packets probe_read_kernel at insn %d", progName, idx)
				}
				probeReads++
			}
		}
		if probeReads != 1 {
			t.Fatalf("%s probe_read_kernel count = %d, want 1 (task->start_boottime only)", progName, probeReads)
		}
		assertAllInstructionsReachableAndValidJumps(t, progName, insns)
		for i, mapName := range []string{"config", "cpu_state", "packets", "health", "readers", "read_slots"} {
			if err := cp.Instructions.AssociateMap(mapName, fakeFD(20+i)); err != nil {
				t.Fatalf("%s AssociateMap(%s): %v", progName, mapName, err)
			}
		}
		if runtime.GOOS == "linux" {
			var encoded bytes.Buffer
			if err := cp.Instructions.Marshal(&encoded, binary.LittleEndian); err != nil {
				t.Fatalf("%s Marshal patched instructions: %v", progName, err)
			}
			if encoded.Len() != 239*asm.InstructionSize {
				t.Fatalf("%s encoded byte len = %d, want %d", progName, encoded.Len(), 239*asm.InstructionSize)
			}
		}
	}

	for _, arch := range []string{"amd64", "arm64"} {
		spec, err := PrepareEngineSenderSpec(arch, 0, 0)
		if err != nil {
			t.Fatalf("PrepareEngineSenderSpec(%s): %v", arch, err)
		}
		if spec.Programs["observe_packet"] != nil || spec.Maps["tuples"] != nil {
			t.Fatalf("%s: pilot tuple/egress objects must be stripped", arch)
		}
		if spec.Maps["actors"].MaxEntries != DefaultEngineMaxActors {
			t.Fatalf("%s: actors.MaxEntries = %d, want %d", arch, spec.Maps["actors"].MaxEntries, DefaultEngineMaxActors)
		}
		if (spec.Maps["counters"].Flags & bpfMapFlagMmapable) == 0 {
			t.Fatalf("%s: counters map must carry BPF_F_MMAPABLE", arch)
		}
		if q := spec.Maps["actor_events"]; q == nil || q.KeySize != 0 || q.ValueSize != 64 || q.MaxEntries != DefaultEngineActorEventQueue {
			t.Fatalf("%s: unexpected actor_events queue spec: %+v", arch, q)
		}

		// Verify all map references bind and the patched actor-insert jump
		// retains its symbol reference (never overwritten by BTF metadata).
		cp := spec.Programs["observe_send"].Copy()
		if len(cp.Instructions) != 213 {
			t.Fatalf("%s patched observe_send len = %d, want 213", arch, len(cp.Instructions))
		}
		if ref := cp.Instructions[158].Reference(); ref != "ns_emit_new_actor" {
			t.Fatalf("%s patched observe_send insns[158] reference = %q, want ns_emit_new_actor", arch, ref)
		}
		if sym := cp.Instructions[187].Symbol(); sym != "ns_emit_new_actor" {
			t.Fatalf("%s patched observe_send insns[187] symbol = %q, want ns_emit_new_actor", arch, sym)
		}
		for i, name := range []string{"scope", "counters", "actors", "actor_events"} {
			if err := cp.Instructions.AssociateMap(name, fakeFD(10+i)); err != nil {
				t.Fatalf("%s AssociateMap(%s): %v", arch, name, err)
			}
		}
		if runtime.GOOS == "linux" {
			var rawSlot158, rawSlot187 int
			for idx := 0; idx < 187; idx++ {
				slots := int(cp.Instructions[idx].Size() / 8)
				if idx < 158 {
					rawSlot158 += slots
				}
				rawSlot187 += slots
			}
			var encoded bytes.Buffer
			if err := cp.Instructions.Marshal(&encoded, binary.LittleEndian); err != nil {
				t.Fatalf("%s Marshal patched observe_send: %v", arch, err)
			}
			raw := encoded.Bytes()
			if len(raw) == 0 || len(raw)%8 != 0 {
				t.Fatalf("%s unexpected encoded bytecode len %d", arch, len(raw))
			}
			gotJumpOff := int(int16(binary.LittleEndian.Uint16(raw[rawSlot158*8+2 : rawSlot158*8+4])))
			wantJumpOff := rawSlot187 - (rawSlot158 + 1)
			if gotJumpOff != wantJumpOff {
				t.Fatalf("%s encoded jump offset at raw insn %d = %d, want %d (target raw insn %d)", arch, rawSlot158, gotJumpOff, wantJumpOff, rawSlot187)
			}
		}
	}
}

func assertAllInstructionsReachableAndValidJumps(t *testing.T, name string, insns asm.Instructions) {
	t.Helper()
	rawSlot := make([]int, len(insns))
	slotToIdx := make(map[int]int, len(insns))
	raw := 0
	for i, ins := range insns {
		rawSlot[i] = raw
		slotToIdx[raw] = i
		raw += int(ins.Size() / asm.InstructionSize)
	}
	visited := make([]bool, len(insns))
	stack := []int{0}
	visited[0] = true
	push := func(target int, from int) {
		if target < 0 || target >= len(insns) {
			t.Fatalf("%s: out-of-bounds CFG edge %d -> %d", name, from, target)
		}
		if !visited[target] {
			visited[target] = true
			stack = append(stack, target)
		}
	}
	for len(stack) > 0 {
		idx := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		ins := insns[idx]
		if ins.OpCode.Class().IsJump() {
			jop := ins.OpCode.JumpOp()
			if jop == asm.Exit {
				continue
			}
			if jop == asm.Call {
				push(idx+1, idx)
				continue
			}
			width := int(ins.Size() / asm.InstructionSize)
			targetSlot := rawSlot[idx] + width + int(ins.Offset)
			targetIdx, ok := slotToIdx[targetSlot]
			if !ok {
				t.Fatalf("%s: jump at insn %d targets invalid raw slot %d", name, idx, targetSlot)
			}
			push(targetIdx, idx)
			if jop != asm.Ja {
				push(idx+1, idx)
			}
			continue
		}
		push(idx+1, idx)
	}
	for i, ok := range visited {
		if !ok {
			t.Fatalf("%s: unreachable instruction at index %d (raw slot %d): %v", name, i, rawSlot[i], insns[i])
		}
	}
}
