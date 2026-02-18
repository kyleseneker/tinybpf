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

func buildELF(class byte, machine uint16, addCode bool, sym symMode) []byte {
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

	strtab := []byte{0}
	codeNameOff := 0
	symtabNameOff := 0
	symstrtabNameOff := 0

	if addCode {
		codeNameOff = len(strtab)
		strtab = append(strtab, ".text\x00"...)
	}
	if sym != symNone {
		symtabNameOff = len(strtab)
		strtab = append(strtab, ".symtab\x00"...)
		symstrtabNameOff = len(strtab)
		strtab = append(strtab, ".strtab\x00"...)
	}
	shstrtabNameOff := len(strtab)
	strtab = append(strtab, ".shstrtab\x00"...)
	for len(strtab)%8 != 0 {
		strtab = append(strtab, 0)
	}

	offset := uint64(64)
	var sectionData []byte

	var codeData []byte
	if addCode {
		codeData = []byte{0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		sectionData = append(sectionData, codeData...)
		for len(sectionData)%8 != 0 {
			sectionData = append(sectionData, 0)
		}
	}

	symStrtabOff := uint64(0)
	var symStrtabData []byte
	if sym != symNone {
		symStrtabData = []byte{0}
		if sym == symOne {
			symStrtabData = append(symStrtabData, "test_sym\x00"...)
		}
		for len(symStrtabData)%8 != 0 {
			symStrtabData = append(symStrtabData, 0)
		}
		symStrtabOff = offset + uint64(len(sectionData))
		sectionData = append(sectionData, symStrtabData...)
	}

	symtabOff := uint64(0)
	symtabSize := uint64(0)
	if sym != symNone {
		symtabOff = offset + uint64(len(sectionData))
		nullSym := make([]byte, 24)
		sectionData = append(sectionData, nullSym...)
		symtabSize = 24
		if sym == symOne {
			realSym := make([]byte, 24)
			binary.LittleEndian.PutUint32(realSym[0:4], 1)
			realSym[4] = 0x12
			sectionData = append(sectionData, realSym...)
			symtabSize = 48
		}
	}

	shstrtabOff := offset + uint64(len(sectionData))
	sectionData = append(sectionData, strtab...)

	shnum := uint16(0)
	var sectionHeaders []byte
	appendSH := func(nameOff int, shType uint32, flags uint64, shOffset, size uint64, link, info uint32, entsize uint64) {
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
		sectionHeaders = append(sectionHeaders, sh...)
		shnum++
	}

	appendSH(0, 0, 0, 0, 0, 0, 0, 0)

	if addCode {
		appendSH(codeNameOff, 1, 6, offset, uint64(len(codeData)), 0, 0, 0)
	}

	symStrtabSHIdx := uint16(0)
	if sym != symNone {
		symStrtabSHIdx = shnum
		appendSH(symstrtabNameOff, 3, 0, symStrtabOff, uint64(len(symStrtabData)), 0, 0, 0)
	}

	if sym != symNone {
		info := uint32(1)
		if sym == symEmpty {
			info = 0
		}
		appendSH(symtabNameOff, 2, 0, symtabOff, symtabSize, uint32(symStrtabSHIdx), info, 24)
	}

	shstrtabIdx := shnum
	appendSH(shstrtabNameOff, 3, 0, shstrtabOff, uint64(len(strtab)), 0, 0, 0)

	shoff := offset + uint64(len(sectionData))
	binary.LittleEndian.PutUint64(hdr[40:48], shoff)
	binary.LittleEndian.PutUint16(hdr[60:62], shnum)
	binary.LittleEndian.PutUint16(hdr[62:64], shstrtabIdx)

	var out []byte
	out = append(out, hdr...)
	out = append(out, sectionData...)
	out = append(out, sectionHeaders...)
	return out
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
