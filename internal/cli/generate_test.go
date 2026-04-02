package cli

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bpfELFWithProgram builds a minimal BPF ELF with one program symbol properly
// bound to an executable section, suitable for codegen extraction.
func bpfELFWithProgram(t *testing.T) string {
	t.Helper()

	shstrtab := "\x00.text\x00.symtab\x00.strtab\x00.shstrtab\x00"
	for len(shstrtab)%8 != 0 {
		shstrtab += "\x00"
	}

	symstrtab := "\x00test_prog\x00"
	for len(symstrtab)%8 != 0 {
		symstrtab += "\x00"
	}

	code := []byte{0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	off := uint64(64)
	codeOff := off
	off += uint64(len(code))
	symstrtabOff := off
	off += uint64(len(symstrtab))
	symtabOff := off

	nullSym := make([]byte, 24)
	progSym := make([]byte, 24)
	binary.LittleEndian.PutUint32(progSym[0:4], 1)
	progSym[4] = 0x12                              // STT_FUNC | STB_GLOBAL
	binary.LittleEndian.PutUint16(progSym[6:8], 1) // st_shndx = 1 (.text)

	off += uint64(len(nullSym) + len(progSym))
	shstrtabOff := off
	off += uint64(len(shstrtab))
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
	sections = append(sections, makeSH(0, 0, 0, 0, 0, 0, 0, 0)...)
	sections = append(sections, makeSH(1, 1, 6, codeOff, uint64(len(code)), 0, 0, 0)...)
	sections = append(sections, makeSH(7, 3, 0, symstrtabOff, uint64(len(symstrtab)), 0, 0, 0)...)
	sections = append(sections, makeSH(15, 2, 0, symtabOff, uint64(len(nullSym)+len(progSym)), 2, 1, 24)...)
	sections = append(sections, makeSH(23, 3, 0, shstrtabOff, uint64(len(shstrtab)), 0, 0, 0)...)

	hdr := make([]byte, 64)
	copy(hdr[0:4], []byte{0x7f, 'E', 'L', 'F'})
	hdr[4] = 2
	hdr[5] = 1
	hdr[6] = 1
	binary.LittleEndian.PutUint16(hdr[16:18], 1)
	binary.LittleEndian.PutUint16(hdr[18:20], 0xF7)
	binary.LittleEndian.PutUint32(hdr[20:24], 1)
	binary.LittleEndian.PutUint16(hdr[52:54], 64)
	binary.LittleEndian.PutUint16(hdr[58:60], 64)
	binary.LittleEndian.PutUint64(hdr[40:48], shOff)
	binary.LittleEndian.PutUint16(hdr[60:62], 5)
	binary.LittleEndian.PutUint16(hdr[62:64], 4)

	var out []byte
	out = append(out, hdr...)
	out = append(out, code...)
	out = append(out, []byte(symstrtab)...)
	out = append(out, nullSym...)
	out = append(out, progSym...)
	out = append(out, []byte(shstrtab)...)
	out = append(out, sections...)

	p := filepath.Join(t.TempDir(), "test.bpf.o")
	if err := os.WriteFile(p, out, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunGenerate(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T) []string
		wantCode int
		wantOut  string
		wantErr  string
	}{
		{
			name:     "--help",
			setup:    func(t *testing.T) []string { t.Helper(); return []string{"generate", "--help"} },
			wantCode: 0,
			wantErr:  "Usage:",
		},
		{
			name:     "missing argument",
			setup:    func(t *testing.T) []string { t.Helper(); return []string{"generate"} },
			wantCode: 2,
			wantErr:  "exactly one BPF object argument is required",
		},
		{
			name: "too many arguments",
			setup: func(t *testing.T) []string {
				t.Helper()
				return []string{"generate", "a.o", "b.o"}
			},
			wantCode: 2,
			wantErr:  "exactly one BPF object argument is required",
		},
		{
			name: "non-existent file",
			setup: func(t *testing.T) []string {
				t.Helper()
				return []string{"generate", "/no/such/file.bpf.o"}
			},
			wantCode: 1,
			wantErr:  "open ELF",
		},
		{
			name: "not an ELF",
			setup: func(t *testing.T) []string {
				t.Helper()
				p := filepath.Join(t.TempDir(), "bad.o")
				os.WriteFile(p, []byte("not elf"), 0o644)
				return []string{"generate", p}
			},
			wantCode: 1,
			wantErr:  "open ELF",
		},
		{
			name: "valid BPF ELF generates output",
			setup: func(t *testing.T) []string {
				t.Helper()
				elfPath := bpfELFWithProgram(t)
				outDir := t.TempDir()
				outPath := filepath.Join(outDir, "test_bpf.go")
				return []string{"generate", "--output", outPath, "--package", "testpkg", elfPath}
			},
			wantCode: 0,
			wantOut:  "wrote",
		},
		{
			name: "default output name from object path",
			setup: func(t *testing.T) []string {
				t.Helper()
				elfPath := bpfELFWithProgram(t)
				outDir := t.TempDir()
				outPath := filepath.Join(outDir, "probe_bpf.go")
				return []string{"generate", "--package", "loader", "--output", outPath, elfPath}
			},
			wantCode: 0,
			wantOut:  "1 programs",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.setup(t)
			stdout, stderr, code := runCLI(t, args...)
			if code != tt.wantCode {
				t.Fatalf("exit code: got %d, want %d\nstdout=%s\nstderr=%s", code, tt.wantCode, stdout, stderr)
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

func TestRunGenerateOutputContent(t *testing.T) {
	tests := []struct {
		name     string
		pkg      string
		contains []string
	}{
		{
			name: "generated file has expected content",
			pkg:  "loader",
			contains: []string{
				"// Code generated by tinybpf; DO NOT EDIT.",
				"package loader",
				"type Objects struct",
				"type Programs struct",
				"type Maps struct",
				"func Load(objectPath string)",
				"func (o *Objects) Close()",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			elfPath := bpfELFWithProgram(t)
			outDir := t.TempDir()
			outPath := filepath.Join(outDir, "objects_bpf.go")

			_, _, code := runCLI(t, "generate", "--output", outPath, "--package", tt.pkg, elfPath)
			if code != 0 {
				t.Fatalf("expected exit code 0, got %d", code)
			}

			data, err := os.ReadFile(outPath)
			if err != nil {
				t.Fatalf("read output: %v", err)
			}

			text := string(data)
			for _, s := range tt.contains {
				if !strings.Contains(text, s) {
					t.Errorf("output file missing %q", s)
				}
			}
		})
	}
}

func TestComputeEmbedPath(t *testing.T) {
	tests := []struct {
		name       string
		objectPath string
		outputPath string
		want       string
	}{
		{
			name:       "object in subdirectory of output dir",
			objectPath: "build/probe.bpf.o",
			outputPath: "loader_bpf.go",
			want:       filepath.Join("build", "probe.bpf.o"),
		},
		{
			name:       "object in same directory as output",
			objectPath: "probe.bpf.o",
			outputPath: "loader_bpf.go",
			want:       "probe.bpf.o",
		},
		{
			name:       "object unreachable without dotdot",
			objectPath: "../other/probe.bpf.o",
			outputPath: "internal/loader/loader_bpf.go",
			want:       "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeEmbedPath(tt.objectPath, tt.outputPath)
			if got != tt.want {
				t.Errorf("computeEmbedPath(%q, %q) = %q, want %q", tt.objectPath, tt.outputPath, got, tt.want)
			}
		})
	}
}
