package cli

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kyleseneker/tinybpf/internal/testutil"
)

func minimalBPFELF() []byte {
	hdr := make([]byte, 64)
	copy(hdr[0:4], []byte{0x7f, 'E', 'L', 'F'})
	hdr[4] = 2                                      // ELFCLASS64
	hdr[5] = 1                                      // ELFDATA2LSB
	hdr[6] = 1                                      // EV_CURRENT
	binary.LittleEndian.PutUint16(hdr[16:18], 1)    // ET_REL
	binary.LittleEndian.PutUint16(hdr[18:20], 0xF7) // EM_BPF
	binary.LittleEndian.PutUint32(hdr[20:24], 1)    // EV_CURRENT
	binary.LittleEndian.PutUint16(hdr[52:54], 64)   // e_ehsize
	binary.LittleEndian.PutUint16(hdr[58:60], 64)   // e_shentsize

	strtab := []byte("\x00.text\x00.symtab\x00.strtab\x00.shstrtab\x00")
	for len(strtab)%8 != 0 {
		strtab = append(strtab, 0)
	}

	code := []byte{0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} // BPF exit

	symStrtab := []byte("\x00test_sym\x00")
	for len(symStrtab)%8 != 0 {
		symStrtab = append(symStrtab, 0)
	}
	nullSym := make([]byte, 24)
	realSym := make([]byte, 24)
	binary.LittleEndian.PutUint32(realSym[0:4], 1)
	realSym[4] = 0x12 // STT_FUNC | STB_GLOBAL

	off := uint64(64)
	codeOff := off
	off += uint64(len(code))
	symStrtabOff := off
	off += uint64(len(symStrtab))
	symtabOff := off
	off += uint64(len(nullSym) + len(realSym))
	shstrtabOff := off
	off += uint64(len(strtab))
	shOff := off

	makeSH := func(nameOff int, shType uint32, flags uint64, shOffset, size uint64, link, info uint32, entsize uint64) []byte {
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
		return sh
	}

	var sections []byte
	sections = append(sections, makeSH(0, 0, 0, 0, 0, 0, 0, 0)...)                                           // null
	sections = append(sections, makeSH(1, 1, 6, codeOff, uint64(len(code)), 0, 0, 0)...)                     // .text
	sections = append(sections, makeSH(7, 3, 0, symStrtabOff, uint64(len(symStrtab)), 0, 0, 0)...)           // .strtab
	sections = append(sections, makeSH(15, 2, 0, symtabOff, uint64(len(nullSym)+len(realSym)), 2, 1, 24)...) // .symtab
	sections = append(sections, makeSH(23, 3, 0, shstrtabOff, uint64(len(strtab)), 0, 0, 0)...)              // .shstrtab

	binary.LittleEndian.PutUint64(hdr[40:48], shOff)
	binary.LittleEndian.PutUint16(hdr[60:62], 5) // e_shnum
	binary.LittleEndian.PutUint16(hdr[62:64], 4) // e_shstrndx

	var out []byte
	out = append(out, hdr...)
	out = append(out, code...)
	out = append(out, symStrtab...)
	out = append(out, nullSym...)
	out = append(out, realSym...)
	out = append(out, strtab...)
	out = append(out, sections...)
	return out
}

func writeTestELF(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "test.o")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunVerify(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T) []string
		wantCode int
		wantOut  string
		wantErr  string
	}{
		{
			name:     "--help",
			setup:    func(t *testing.T) []string { t.Helper(); return []string{"verify", "--help"} },
			wantCode: 0,
			wantErr:  "Usage:",
		},
		{
			name:     "missing input",
			setup:    func(t *testing.T) []string { t.Helper(); return []string{"verify"} },
			wantCode: 2,
			wantErr:  "--input is required",
		},
		{
			name: "valid BPF ELF",
			setup: func(t *testing.T) []string {
				t.Helper()
				p := writeTestELF(t, minimalBPFELF())
				return []string{"verify", "--input", p}
			},
			wantCode: 0,
			wantOut:  "valid BPF ELF object",
		},
		{
			name: "non-ELF file",
			setup: func(t *testing.T) []string {
				t.Helper()
				p := filepath.Join(t.TempDir(), "bad.o")
				os.WriteFile(p, []byte("not an elf"), 0o644)
				return []string{"verify", "--input", p}
			},
			wantCode: 1,
			wantErr:  "elf-validate",
		},
		{
			name: "missing file",
			setup: func(t *testing.T) []string {
				t.Helper()
				return []string{"verify", "--input", testutil.BadPath("no-such.o")}
			},
			wantCode: 1,
			wantErr:  "elf-validate",
		},
		{
			name: "-i shorthand",
			setup: func(t *testing.T) []string {
				t.Helper()
				p := writeTestELF(t, minimalBPFELF())
				return []string{"verify", "-i", p}
			},
			wantCode: 0,
			wantOut:  "valid BPF ELF object",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.setup(t)
			stdout, stderr, code := runCLI(t, args...)
			if code != tt.wantCode {
				t.Fatalf("exit code: got %d, want %d, stderr=%s", code, tt.wantCode, stderr)
			}
			if tt.wantOut != "" && !strings.Contains(stdout, tt.wantOut) {
				t.Fatalf("expected %q in stdout, got: %s", tt.wantOut, stdout)
			}
			if tt.wantErr != "" && !strings.Contains(stderr, tt.wantErr) {
				t.Fatalf("expected %q in stderr, got: %s", tt.wantErr, stderr)
			}
		})
	}
}
