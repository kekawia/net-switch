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

		// Verify all map references bind and (on Linux) all symbol jumps marshal.
		cp := spec.Programs["observe_send"].Copy()
		if len(cp.Instructions) != 213 {
			t.Fatalf("%s patched observe_send len = %d, want 213", arch, len(cp.Instructions))
		}
		for i, name := range []string{"scope", "counters", "actors", "actor_events"} {
			if err := cp.Instructions.AssociateMap(name, fakeFD(10+i)); err != nil {
				t.Fatalf("%s AssociateMap(%s): %v", arch, name, err)
			}
		}
		if runtime.GOOS == "linux" {
			var encoded bytes.Buffer
			if err := cp.Instructions.Marshal(&encoded, binary.LittleEndian); err != nil {
				t.Fatalf("%s Marshal patched observe_send: %v", arch, err)
			}
			if encoded.Len() == 0 || encoded.Len()%8 != 0 {
				t.Fatalf("%s unexpected encoded bytecode len %d", arch, encoded.Len())
			}
		}
	}
}
