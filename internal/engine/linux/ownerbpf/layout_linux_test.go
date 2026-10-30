package ownerbpf

import (
	"bytes"
	"encoding/binary"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestProvenanceCInterchange(t *testing.T) {
	// Required on Linux: missing compiler or failed layout assertions are fatal.
	// Compiler output is a test artifact; the source is committed, not generated.
	bin := filepath.Join(t.TempDir(), "layout")
	if out, err := exec.Command("cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "testdata/layout.c", "-o", bin).CombinedOutput(); err != nil {
		t.Fatalf("C ABI fixture compile: %v\n%s", err, out)
	}
	out, err := exec.Command(bin).Output()
	if err != nil || len(out) != 256 {
		t.Fatalf("C ABI fixture: bytes=%d err=%v", len(out), err)
	}
	var got ReaderSlot
	if err := binary.Read(bytes.NewReader(out), binary.NativeEndian, &got); err != nil {
		t.Fatal(err)
	}
	want := ReaderSlot{
		Control: ReadControl{ABI: 3, Registration: 0x1020304050607080,
			Epoch: 0x1122334455667788, Sequence: 0x8877665544332211, Armed: 0},
		Completion: ReadCompletion{Count: 1, Sequence: 0x8877665544332211,
			Registration: 0x1020304050607080, Terminal: 1, Status: 1},
		Packet: PacketRecord{ABI: 3, Status: 1, Epoch: 0x1122334455667788,
			Ifindex: 0x12345678, NetNS: 0x87654321, CPU: 7, Classification: 0x10293847,
			Serial: 0xabcdef0123456789, Cookie: 0x123456789abcdef0, Length: 1500, Users: 1},
	}
	if got != want {
		t.Fatalf("C to Go ABI mismatch:\ngot  %+v\nwant %+v", got, want)
	}
	t.Log("PROVENANCE abi=3 c_static_assertions=pass c_to_go_bytes=256 interchange=pass")
}
