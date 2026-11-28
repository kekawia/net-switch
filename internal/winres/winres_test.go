package winres

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

var sample = Info{
	Version:          Version{1, 2, 3},
	ProductName:      "Net Switch",
	FileDescription:  "Net Switch routing engine",
	CompanyName:      "Net Switch",
	InternalName:     "netswitch-engine",
	OriginalFilename: "netswitch-engine.exe",
}

func TestParseVersionTakesOnlyThreePlainNumbersWindowsCanHold(t *testing.T) {
	for text, want := range map[string]Version{"1.0.0": {1, 0, 0}, "0.99.17": {0, 99, 17}, "65535.0.65535": {65535, 0, 65535}} {
		got, err := ParseVersion(text)
		if err != nil || got != want || got.String() != text {
			t.Errorf("ParseVersion(%q) = %v, %v; want %v", text, got, err, want)
		}
	}
	for _, text := range []string{"", "1.0", "1.0.0.0", "v1.0.0", "1.0.0-rc.1", "01.0.0", "1.0.0 ", "65536.0.0", "1.99999999999.0"} {
		if _, err := ParseVersion(text); err == nil {
			t.Errorf("ParseVersion(%q) accepted it", text)
		}
	}
}

// The object is read back the way the linker and Windows read it: debug/pe
// for the COFF structure, then the resource tree to the one data entry, then
// the version tree, decoded here independently of the writer.
func TestObjectHoldsOneVersionResourceForEachArchitecture(t *testing.T) {
	for arch, want := range map[string]struct{ machine, relocation uint16 }{"amd64": {0x8664, 3}, "arm64": {0xAA64, 2}} {
		t.Run(arch, func(t *testing.T) {
			object, err := Object(arch, sample)
			if err != nil {
				t.Fatal(err)
			}
			f, err := pe.NewFile(bytes.NewReader(object))
			if err != nil {
				t.Fatal(err)
			}
			if f.Machine != want.machine || len(f.Sections) != 1 {
				t.Fatalf("machine %#x with %d sections; want %#x with one", f.Machine, len(f.Sections), want.machine)
			}
			section := f.Sections[0]
			if section.Name != ".rsrc" || section.Characteristics != 0x40000040 {
				t.Fatalf("section %q %#x; want .rsrc, initialized read-only data", section.Name, section.Characteristics)
			}
			if len(f.COFFSymbols) != 2 || f.COFFSymbols[0].StorageClass != 3 || f.COFFSymbols[0].SectionNumber != 1 ||
				f.COFFSymbols[0].Type != 0 || f.COFFSymbols[0].NumberOfAuxSymbols != 1 || string(f.COFFSymbols[0].Name[:5]) != ".rsrc" {
				t.Fatalf("symbols %+v; want the .rsrc section symbol and its auxiliary record", f.COFFSymbols)
			}
			data, err := section.Data()
			if err != nil {
				t.Fatal(err)
			}

			level := func(directory uint32, id uint32, subdirectory bool) uint32 {
				t.Helper()
				named, ids := u16(data, directory+12), u16(data, directory+14)
				if named != 0 || ids != 1 || u32(data, directory+16) != id {
					t.Fatalf("directory at %d: %d named, %d IDs, first ID %d; want one entry with ID %d", directory, named, ids, u32(data, directory+16), id)
				}
				target := u32(data, directory+20)
				if (target&0x80000000 != 0) != subdirectory {
					t.Fatalf("entry %d points at %#x; subdirectory %v", id, target, subdirectory)
				}
				return target &^ 0x80000000
			}
			entry := level(level(level(0, 16, true), 1, true), 0x409, false)
			if len(section.Relocs) != 1 || section.Relocs[0].VirtualAddress != entry ||
				section.Relocs[0].SymbolTableIndex != 0 || section.Relocs[0].Type != want.relocation {
				t.Fatalf("relocations %+v; want one image-relative relocation of the data entry at %d", section.Relocs, entry)
			}
			offset, size := u32(data, entry), u32(data, entry+4)
			if offset%4 != 0 || int(offset+size) > len(data) {
				t.Fatalf("data at %d, %d bytes, in a %d byte section", offset, size, len(data))
			}
			checkVersionTree(t, data[offset:offset+size], sample)
		})
	}
}

func TestObjectIsTheSameForTheSameInput(t *testing.T) {
	a, err := Object("arm64", sample)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Object("arm64", sample)
	if !bytes.Equal(a, b) {
		t.Fatal("two objects from the same input differ")
	}
	other := sample
	other.Version.Patch++
	c, _ := Object("arm64", other)
	if bytes.Equal(a, c) {
		t.Fatal("a different version gave the same object")
	}
}

func TestObjectLeavesOutAnEmptyCompanyAndRefusesOtherGaps(t *testing.T) {
	info := sample
	info.CompanyName = ""
	object, err := Object("amd64", info)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(object, utf16Bytes("CompanyName")) {
		t.Fatal("an empty CompanyName was written")
	}
	for name, change := range map[string]func(*Info){
		"no description":   func(i *Info) { i.FileDescription = "" },
		"no product":       func(i *Info) { i.ProductName = "" },
		"no file name":     func(i *Info) { i.OriginalFilename = "" },
		"no internal name": func(i *Info) { i.InternalName = "" },
		"padded product":   func(i *Info) { i.ProductName = "Net Switch " },
		"NUL in a value":   func(i *Info) { i.FileDescription = "Net\x00Switch" },
		"overlong value":   func(i *Info) { i.FileDescription = strings.Repeat("x", 256) },
		"padded company":   func(i *Info) { i.CompanyName = " Net Switch" },
	} {
		bad := sample
		change(&bad)
		if _, err := Object("amd64", bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Object("386", sample); err == nil {
		t.Error("386: accepted an architecture Net Switch doesn't ship")
	}
}

type versionNode struct {
	key         string
	valueLength uint16
	text        bool
	value       []byte
	children    []versionNode
}

// parseNode reads one VS_VERSIONINFO-style node as Microsoft documents it:
// wLength, wValueLength, wType, the NUL-terminated key, padding to 32 bits,
// the value (wValueLength UTF-16 units for text, bytes otherwise), then each
// child on a 32-bit boundary until wLength.
func parseNode(t *testing.T, b []byte) versionNode {
	t.Helper()
	if len(b) < 6 {
		t.Fatalf("node of %d bytes", len(b))
	}
	length, valueLength, kind := int(u16(b, 0)), u16(b, 2), u16(b, 4)
	if length > len(b) || kind > 1 {
		t.Fatalf("node claims %d bytes of %d, type %d", length, len(b), kind)
	}
	b = b[:length]
	n := versionNode{valueLength: valueLength, text: kind == 1}
	at := 6
	var key []uint16
	for ; ; at += 2 {
		unit := u16(b, uint32(at))
		if unit == 0 {
			at += 2
			break
		}
		key = append(key, unit)
	}
	n.key = string(utf16.Decode(key))
	at = (at + 3) &^ 3
	size := int(valueLength)
	if n.text {
		size *= 2
	}
	n.value = b[at : at+size]
	at = (at + size + 3) &^ 3
	for at < length {
		child := parseNode(t, b[at:])
		n.children = append(n.children, child)
		at = (at + int(u16(b, uint32(at))) + 3) &^ 3
	}
	return n
}

func checkVersionTree(t *testing.T, blob []byte, info Info) {
	t.Helper()
	root := parseNode(t, blob)
	if root.key != "VS_VERSION_INFO" || root.text || len(root.value) != 52 || len(root.children) != 2 {
		t.Fatalf("root %q, text %v, %d value bytes, %d children", root.key, root.text, len(root.value), len(root.children))
	}
	fixed := root.value
	ms := uint32(info.Version.Major)<<16 | uint32(info.Version.Minor)
	ls := uint32(info.Version.Patch) << 16
	for i, want := range []uint32{0xFEEF04BD, 0x00010000, ms, ls, ms, ls, 0x3F, 0, 0x00040004, 1, 0, 0, 0} {
		if got := u32(fixed, uint32(i*4)); got != want {
			t.Errorf("fixed field %d = %#x; want %#x", i, got, want)
		}
	}

	stringInfo, varInfo := root.children[0], root.children[1]
	if stringInfo.key != "StringFileInfo" || len(stringInfo.children) != 1 || stringInfo.children[0].key != "040904B0" {
		t.Fatalf("string info %q with %d tables", stringInfo.key, len(stringInfo.children))
	}
	got := map[string]string{}
	for _, s := range stringInfo.children[0].children {
		units := make([]uint16, len(s.value)/2)
		for i := range units {
			units[i] = u16(s.value, uint32(i*2))
		}
		if !s.text || len(units) == 0 || units[len(units)-1] != 0 {
			t.Errorf("%s isn't NUL-terminated text: %v", s.key, units)
			continue
		}
		got[s.key] = string(utf16.Decode(units[:len(units)-1]))
	}
	want := map[string]string{
		"CompanyName": info.CompanyName, "FileDescription": info.FileDescription, "FileVersion": info.Version.String(),
		"InternalName": info.InternalName, "OriginalFilename": info.OriginalFilename,
		"ProductName": info.ProductName, "ProductVersion": info.Version.String(),
	}
	if len(got) != len(want) {
		t.Errorf("strings %v; want %v", got, want)
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("%s = %q; want %q", key, got[key], value)
		}
	}

	if varInfo.key != "VarFileInfo" || len(varInfo.children) != 1 {
		t.Fatalf("var info %q with %d children", varInfo.key, len(varInfo.children))
	}
	translation := varInfo.children[0]
	if translation.key != "Translation" || translation.text || !bytes.Equal(translation.value, []byte{0x09, 0x04, 0xB0, 0x04}) {
		t.Fatalf("translation %q %x; want English (US), Unicode", translation.key, translation.value)
	}
}

func u16(b []byte, at uint32) uint16 { return binary.LittleEndian.Uint16(b[at:]) }
func u32(b []byte, at uint32) uint32 { return binary.LittleEndian.Uint32(b[at:]) }

func utf16Bytes(s string) []byte {
	var b []byte
	for _, unit := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, unit)
	}
	return b
}
