// Package winres writes a Windows version resource as a COFF object (.syso)
// that the Go linker adds to a program. Explorer's Details tab, Task Manager
// and code signing services read a program's name and version from it; Go
// programs have none unless one is linked in.
//
// The layout follows Microsoft's documentation of VS_VERSIONINFO
// (https://learn.microsoft.com/windows/win32/menurc/vs-versioninfo) and of
// the .rsrc section in COFF objects
// (https://learn.microsoft.com/windows/win32/debug/pe-format#the-rsrc-section).
// The Go linker (cmd/link/internal/loadpe) copies a host object's .rsrc
// section into the program and resolves its image-relative relocations.
package winres

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Version is a product version of three plain numbers, as Net Switch
// releases use. Windows keeps each part in 16 bits.
type Version struct{ Major, Minor, Patch uint16 }

var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// ParseVersion reads "1.2.3". It refuses suffixes and parts above 65535,
// which Windows' fixed version fields can't hold.
func ParseVersion(text string) (Version, error) {
	parts := versionPattern.FindStringSubmatch(text)
	if parts == nil {
		return Version{}, fmt.Errorf("version %q is not three plain numbers like 1.0.0", text)
	}
	var numbers [3]uint16
	for i, part := range parts[1:] {
		n, err := strconv.ParseUint(part, 10, 16)
		if err != nil {
			return Version{}, fmt.Errorf("version %q: each part must be at most 65535", text)
		}
		numbers[i] = uint16(n)
	}
	return Version{numbers[0], numbers[1], numbers[2]}, nil
}

func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch) }

// Info is what one program's version resource says.
type Info struct {
	Version          Version
	ProductName      string // the same on every program, e.g. "Net Switch"
	FileDescription  string // what Task Manager shows for the running program
	CompanyName      string // optional
	InternalName     string // the file name without .exe
	OriginalFilename string // the file name, e.g. "netswitch.exe"
}

// Machine types and image-relative relocation types for the architectures
// Net Switch ships on Windows.
var machines = map[string]struct{ machine, addr32nb uint16 }{
	"amd64": {0x8664, 0x0003}, // IMAGE_FILE_MACHINE_AMD64, IMAGE_REL_AMD64_ADDR32NB
	"arm64": {0xAA64, 0x0002}, // IMAGE_FILE_MACHINE_ARM64, IMAGE_REL_ARM64_ADDR32NB
}

// Object returns a COFF object for goarch ("amd64" or "arm64") that holds
// info as the program's version resource.
func Object(goarch string, info Info) ([]byte, error) {
	target, ok := machines[goarch]
	if !ok {
		return nil, fmt.Errorf("unsupported architecture %q (want amd64 or arm64)", goarch)
	}
	blob, err := versionInfo(info)
	if err != nil {
		return nil, err
	}
	section, relocation := resourceSection(blob)
	return coffObject(target.machine, target.addr32nb, section, relocation), nil
}

const (
	langEnglishUS   = 0x0409
	codePageUnicode = 0x04B0 // 1200, UTF-16LE
	rtVersion       = 16
)

// One node of the VS_VERSIONINFO tree: a header (wLength, wValueLength,
// wType), a NUL-terminated UTF-16 key, padding to 32 bits, the value, then
// each child aligned to 32 bits. wLength leaves out padding after the node.
type node struct {
	key      string
	value    []byte
	text     bool // wType 1: a text value, measured in UTF-16 units
	children []node
}

func (n node) bytes() []byte {
	b := make([]byte, 6, 64)
	b = appendUTF16(b, n.key)
	b = pad(b, 4)
	b = append(b, n.value...)
	for _, child := range n.children {
		b = pad(b, 4)
		b = append(b, child.bytes()...)
	}
	valueLength, kind := len(n.value), uint16(0)
	if n.text {
		valueLength, kind = len(n.value)/2, 1
	}
	binary.LittleEndian.PutUint16(b[0:], uint16(len(b)))
	binary.LittleEndian.PutUint16(b[2:], uint16(valueLength))
	binary.LittleEndian.PutUint16(b[4:], kind)
	return b
}

func appendUTF16(b []byte, s string) []byte {
	for _, unit := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, unit)
	}
	return binary.LittleEndian.AppendUint16(b, 0)
}

func pad(b []byte, to int) []byte {
	for len(b)%to != 0 {
		b = append(b, 0)
	}
	return b
}

func versionInfo(info Info) ([]byte, error) {
	fields := []struct{ key, value string }{
		{"CompanyName", info.CompanyName},
		{"FileDescription", info.FileDescription},
		{"FileVersion", info.Version.String()},
		{"InternalName", info.InternalName},
		{"OriginalFilename", info.OriginalFilename},
		{"ProductName", info.ProductName},
		{"ProductVersion", info.Version.String()},
	}
	table := node{key: fmt.Sprintf("%04X%04X", langEnglishUS, codePageUnicode), text: true}
	for _, s := range fields {
		if s.value == "" {
			if s.key == "CompanyName" {
				continue
			}
			return nil, fmt.Errorf("%s is empty", s.key)
		}
		if err := checkText(s.key, s.value); err != nil {
			return nil, err
		}
		table.children = append(table.children, node{key: s.key, value: appendUTF16(nil, s.value), text: true})
	}

	ms := uint32(info.Version.Major)<<16 | uint32(info.Version.Minor)
	ls := uint32(info.Version.Patch) << 16
	fixed := binary.LittleEndian.AppendUint32(nil, 0xFEEF04BD) // dwSignature
	for _, field := range []uint32{
		0x00010000, // dwStrucVersion
		ms,         // dwFileVersionMS
		ls,         // dwFileVersionLS
		ms,         // dwProductVersionMS
		ls,         // dwProductVersionLS
		0x3F,       // dwFileFlagsMask
		0,          // dwFileFlags: a release build
		0x00040004, // dwFileOS: VOS_NT_WINDOWS32
		1,          // dwFileType: VFT_APP
		0,          // dwFileSubtype
		0,          // dwFileDateMS: no date, so builds repeat byte for byte
		0,          // dwFileDateLS
	} {
		fixed = binary.LittleEndian.AppendUint32(fixed, field)
	}

	translation := binary.LittleEndian.AppendUint16(nil, langEnglishUS)
	translation = binary.LittleEndian.AppendUint16(translation, codePageUnicode)
	root := node{key: "VS_VERSION_INFO", value: fixed, children: []node{
		{key: "StringFileInfo", text: true, children: []node{table}},
		{key: "VarFileInfo", text: true, children: []node{{key: "Translation", value: translation}}},
	}}
	return root.bytes(), nil
}

func checkText(key, value string) error {
	if strings.ContainsRune(value, 0) || strings.TrimSpace(value) != value {
		return fmt.Errorf("%s %q has a NUL or surrounding spaces", key, value)
	}
	if len(value) > 255 {
		return fmt.Errorf("%s is longer than 255 bytes", key)
	}
	return nil
}

// resourceSection lays out the three-level resource tree (type, name,
// language) that leads to one data entry, followed by the data. Directory
// offsets are relative to the section; the data entry's OffsetToData is an
// address in the final program, so it holds the data's offset in the
// section and gets an image-relative relocation (returned) for the linker.
func resourceSection(blob []byte) ([]byte, uint32) {
	var b []byte
	directory := func(id, target uint32) {
		b = append(b, make([]byte, 12)...)         // Characteristics, TimeDateStamp, MajorVersion, MinorVersion
		b = binary.LittleEndian.AppendUint16(b, 0) // NumberOfNamedEntries
		b = binary.LittleEndian.AppendUint16(b, 1) // NumberOfIdEntries
		b = binary.LittleEndian.AppendUint32(b, id)
		b = binary.LittleEndian.AppendUint32(b, target)
	}
	const subdirectory = 0x80000000
	directory(rtVersion, subdirectory|24) // type RT_VERSION
	directory(1, subdirectory|48)         // name 1
	directory(langEnglishUS, 72)          // language, pointing at the data entry
	relocation := uint32(len(b))
	data := uint32(len(b) + 16)
	b = binary.LittleEndian.AppendUint32(b, data) // OffsetToData, relocated
	b = binary.LittleEndian.AppendUint32(b, uint32(len(blob)))
	b = binary.LittleEndian.AppendUint32(b, 0) // CodePage
	b = binary.LittleEndian.AppendUint32(b, 0) // Reserved
	b = append(b, blob...)
	return pad(b, 8), relocation
}

// coffObject wraps the section in a COFF object with one relocation against
// the section's own symbol and an empty string table. The timestamp stays
// zero so the same input gives the same bytes.
func coffObject(machine, relocationType uint16, section []byte, relocation uint32) []byte {
	const headers = 20 + 40
	relocations := uint32(headers + len(section))
	symbols := relocations + 10

	var b bytes.Buffer
	put := func(v any) { _ = binary.Write(&b, binary.LittleEndian, v) }
	name := func(s string) { var n [8]byte; copy(n[:], s); b.Write(n[:]) }

	// File header.
	put(machine)
	put(uint16(1)) // NumberOfSections
	put(uint32(0)) // TimeDateStamp
	put(symbols)   // PointerToSymbolTable
	put(uint32(2)) // NumberOfSymbols: the section symbol and its auxiliary record
	put(uint16(0)) // SizeOfOptionalHeader
	put(uint16(0)) // Characteristics

	// Section header.
	name(".rsrc")
	put(uint32(0))            // VirtualSize
	put(uint32(0))            // VirtualAddress
	put(uint32(len(section))) // SizeOfRawData
	put(uint32(headers))      // PointerToRawData
	put(relocations)          // PointerToRelocations
	put(uint32(0))            // PointerToLinenumbers
	put(uint16(1))            // NumberOfRelocations
	put(uint16(0))            // NumberOfLinenumbers
	put(uint32(0x40000040))   // IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ

	b.Write(section)

	// The relocation: OffsetToData becomes the section's address plus the
	// offset it already holds.
	put(relocation)
	put(uint32(0)) // SymbolTableIndex: the section symbol
	put(relocationType)

	// Section symbol, then its section-definition auxiliary record.
	name(".rsrc")
	put(uint32(0)) // Value
	put(int16(1))  // SectionNumber
	put(uint16(0)) // Type
	put(uint8(3))  // StorageClass: IMAGE_SYM_CLASS_STATIC
	put(uint8(1))  // NumberOfAuxSymbols
	put(uint32(len(section)))
	put(uint16(1)) // NumberOfRelocations
	put(uint16(0)) // NumberOfLinenumbers
	put(uint32(0)) // CheckSum
	put(uint16(0)) // Number
	put(uint8(0))  // Selection
	b.Write(make([]byte, 3))

	put(uint32(4)) // string table size: empty
	return b.Bytes()
}
