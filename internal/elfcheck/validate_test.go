package elfcheck

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type symMode int

const (
	symNone  symMode = iota // no .symtab section at all
	symEmpty                // .symtab with only the null entry (0 real symbols)
	symOne                  // .symtab with one real symbol
)

type elfBuilder struct {
	hdr            []byte
	strtab         []byte
	sectionData    []byte
	sectionHeaders []byte
	shnum          uint16
	offset         uint64
}

func newELFBuilder(class byte, machine uint16) *elfBuilder {
	hdr := make([]byte, 64)
	copy(hdr[0:4], []byte{0x7f, 'E', 'L', 'F'})
	hdr[4] = class
	hdr[5] = 1
	hdr[6] = 1
	binary.LittleEndian.PutUint16(hdr[16:18], 1)
	binary.LittleEndian.PutUint16(hdr[18:20], machine)
	binary.LittleEndian.PutUint32(hdr[20:24], 1)
	binary.LittleEndian.PutUint16(hdr[52:54], 64)
	binary.LittleEndian.PutUint16(hdr[58:60], 64)
	return &elfBuilder{hdr: hdr, strtab: []byte{0}, offset: 64}
}

func (b *elfBuilder) addStrtabEntry(name string) int {
	off := len(b.strtab)
	b.strtab = append(b.strtab, name...)
	b.strtab = append(b.strtab, 0)
	return off
}

func (b *elfBuilder) padStrtab() {
	for len(b.strtab)%8 != 0 {
		b.strtab = append(b.strtab, 0)
	}
}

func (b *elfBuilder) appendData(data []byte) uint64 {
	off := b.offset + uint64(len(b.sectionData))
	b.sectionData = append(b.sectionData, data...)
	return off
}

func (b *elfBuilder) padData() {
	for len(b.sectionData)%8 != 0 {
		b.sectionData = append(b.sectionData, 0)
	}
}

func (b *elfBuilder) appendSH(nameOff int, shType uint32, flags uint64, shOffset, size uint64, link, info uint32, entsize uint64) {
	sh := make([]byte, 64)
	binary.LittleEndian.PutUint32(sh[0:4], uint32(nameOff))
	binary.LittleEndian.PutUint32(sh[4:8], shType)
	binary.LittleEndian.PutUint64(sh[8:16], flags)
	binary.LittleEndian.PutUint64(sh[24:32], shOffset)
	binary.LittleEndian.PutUint64(sh[32:40], size)
	binary.LittleEndian.PutUint32(sh[40:44], link)
	binary.LittleEndian.PutUint32(sh[44:48], info)
	binary.LittleEndian.PutUint64(sh[48:56], 8)
	binary.LittleEndian.PutUint64(sh[56:64], entsize)
	b.sectionHeaders = append(b.sectionHeaders, sh...)
	b.shnum++
}

func (b *elfBuilder) addSymtab(sym symMode, symtabNameOff, symstrtabNameOff int) {
	if sym == symNone {
		return
	}

	symStrtabData := []byte{0}
	if sym == symOne {
		symStrtabData = append(symStrtabData, "test_sym\x00"...)
	}
	for len(symStrtabData)%8 != 0 {
		symStrtabData = append(symStrtabData, 0)
	}
	symStrtabOff := b.appendData(symStrtabData)

	symtabOff := b.offset + uint64(len(b.sectionData))
	nullSym := make([]byte, 24)
	b.sectionData = append(b.sectionData, nullSym...)
	symtabSize := uint64(24)
	if sym == symOne {
		realSym := make([]byte, 24)
		binary.LittleEndian.PutUint32(realSym[0:4], 1)
		realSym[4] = 0x12
		b.sectionData = append(b.sectionData, realSym...)
		symtabSize = 48
	}

	symStrtabSHIdx := b.shnum
	b.appendSH(symstrtabNameOff, 3, 0, symStrtabOff, uint64(len(symStrtabData)), 0, 0, 0)

	info := uint32(1)
	if sym == symEmpty {
		info = 0
	}
	b.appendSH(symtabNameOff, 2, 0, symtabOff, symtabSize, uint32(symStrtabSHIdx), info, 24)
}

func (b *elfBuilder) finalize(shstrtabNameOff int) []byte {
	shstrtabOff := b.appendData(b.strtab)
	shstrtabIdx := b.shnum
	b.appendSH(shstrtabNameOff, 3, 0, shstrtabOff, uint64(len(b.strtab)), 0, 0, 0)

	shoff := b.offset + uint64(len(b.sectionData))
	binary.LittleEndian.PutUint64(b.hdr[40:48], shoff)
	binary.LittleEndian.PutUint16(b.hdr[60:62], b.shnum)
	binary.LittleEndian.PutUint16(b.hdr[62:64], shstrtabIdx)

	var out []byte
	out = append(out, b.hdr...)
	out = append(out, b.sectionData...)
	out = append(out, b.sectionHeaders...)
	return out
}

func buildELF(class byte, machine uint16, addCode bool, sym symMode) []byte {
	b := newELFBuilder(class, machine)

	codeNameOff := 0
	if addCode {
		codeNameOff = b.addStrtabEntry(".text")
	}
	symtabNameOff, symstrtabNameOff := 0, 0
	if sym != symNone {
		symtabNameOff = b.addStrtabEntry(".symtab")
		symstrtabNameOff = b.addStrtabEntry(".strtab")
	}
	shstrtabNameOff := b.addStrtabEntry(".shstrtab")
	b.padStrtab()

	b.appendSH(0, 0, 0, 0, 0, 0, 0, 0) // null section

	if addCode {
		codeData := []byte{0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		codeOff := b.appendData(codeData)
		b.padData()
		b.appendSH(codeNameOff, 1, 6, codeOff, uint64(len(codeData)), 0, 0, 0)
	}

	b.addSymtab(sym, symtabNameOff, symstrtabNameOff)
	return b.finalize(shstrtabNameOff)
}

func buildELFWithMaps(class byte, machine uint16, addCode bool, sym symMode, mapsExec bool) []byte {
	b := newELFBuilder(class, machine)

	codeNameOff := 0
	if addCode {
		codeNameOff = b.addStrtabEntry(".text")
	}
	mapsNameOff := b.addStrtabEntry(".maps")
	symtabNameOff, symstrtabNameOff := 0, 0
	if sym != symNone {
		symtabNameOff = b.addStrtabEntry(".symtab")
		symstrtabNameOff = b.addStrtabEntry(".strtab")
	}
	shstrtabNameOff := b.addStrtabEntry(".shstrtab")
	b.padStrtab()

	b.appendSH(0, 0, 0, 0, 0, 0, 0, 0) // null section

	if addCode {
		codeData := []byte{0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		codeOff := b.appendData(codeData)
		b.padData()
		b.appendSH(codeNameOff, 1, 6, codeOff, uint64(len(codeData)), 0, 0, 0)
	}

	mapsData := make([]byte, 40)
	mapsDataOff := b.appendData(mapsData)
	mapsFlags := uint64(3)
	if mapsExec {
		mapsFlags |= 4
	}
	b.appendSH(mapsNameOff, 1, mapsFlags, mapsDataOff, uint64(len(mapsData)), 0, 0, 0)

	b.addSymtab(sym, symtabNameOff, symstrtabNameOff)
	return b.finalize(shstrtabNameOff)
}

func writeELF(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		path    func(t *testing.T) string
		wantErr string // empty = expect success
	}{
		{
			name: "valid BPF ELF",
			path: func(t *testing.T) string {
				t.Helper()
				return writeELF(t, "valid.o", buildELF(2, 0x00F7, true, symOne))
			},
		},
		{
			name: "non-ELF file",
			path: func(t *testing.T) string {
				t.Helper()
				p := filepath.Join(t.TempDir(), "not-elf.o")
				os.WriteFile(p, []byte("not an elf"), 0o644)
				return p
			},
			wantErr: "ELF",
		},
		{
			name: "wrong class (32-bit)",
			path: func(t *testing.T) string {
				t.Helper()
				return writeELF(t, "class32.o", buildELF(1, 0x00F7, true, symOne))
			},
			wantErr: "ELFCLASS64",
		},
		{
			name: "wrong machine (x86_64)",
			path: func(t *testing.T) string {
				t.Helper()
				return writeELF(t, "x86.o", buildELF(2, 0x003E, true, symOne))
			},
			wantErr: "EM_BPF",
		},
		{
			name: "missing code section",
			path: func(t *testing.T) string {
				t.Helper()
				return writeELF(t, "nocode.o", buildELF(2, 0x00F7, false, symOne))
			},
			wantErr: "executable program section",
		},
		{
			name: "empty symbol table",
			path: func(t *testing.T) string {
				t.Helper()
				return writeELF(t, "emptysym.o", buildELF(2, 0x00F7, true, symEmpty))
			},
			wantErr: "no symbols",
		},
		{
			name: "executable maps section",
			path: func(t *testing.T) string {
				t.Helper()
				return writeELF(t, "execmaps.o", buildELFWithMaps(2, 0x00F7, true, symOne, true))
			},
			wantErr: ".maps section has executable flag",
		},
		{
			name: "valid with non-exec maps section",
			path: func(t *testing.T) string {
				t.Helper()
				return writeELF(t, "goodmaps.o", buildELFWithMaps(2, 0x00F7, true, symOne, false))
			},
		},
		{
			name: "missing file",
			path: func(t *testing.T) string {
				t.Helper()
				return "/does/not/exist.o"
			},
			wantErr: "no such file",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.path(t))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected success, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}
