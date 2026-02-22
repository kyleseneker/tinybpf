package pipeline

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kyleseneker/tinybpf/internal/diag"
	"github.com/kyleseneker/tinybpf/internal/llvm"
)

// fakeAr creates a fake llvm-ar script in dir.
func fakeAr(t *testing.T, dir, listOutput, printOutput string) string {
	t.Helper()
	body := "#!/bin/sh\ncmd=\"$1\"\n"
	if listOutput != "" {
		body += fmt.Sprintf("if [ \"$cmd\" = \"t\" ]; then printf '%s'; exit 0; fi\n", listOutput)
	}
	if printOutput != "" {
		body += fmt.Sprintf("if [ \"$cmd\" = \"p\" ]; then printf '%s'; exit 0; fi\n", printOutput)
	}
	body += "echo fail >&2; exit 1\n"
	p := filepath.Join(dir, "llvm-ar")
	os.WriteFile(p, []byte(body), 0o755)
	return p
}

// fakeObjcopy creates a fake llvm-objcopy that writes content to the
// --dump-section output path.
func fakeObjcopy(t *testing.T, dir, content string) string {
	t.Helper()
	var script string
	if content != "" {
		script = `for a in "$@"; do case "$a" in --dump-section=.llvmbc=*) out="${a#--dump-section=.llvmbc=}"; printf '` + content + `' > "$out";; esac; done`
	} else {
		script = "exit 0"
	}
	p := filepath.Join(dir, "llvm-objcopy")
	os.WriteFile(p, []byte("#!/bin/sh\n"+script+"\n"), 0o755)
	return p
}

func TestNormalizePassthrough(t *testing.T) {
	tests := []struct {
		name    string
		ext     string
		content string
	}{
		{"ll file", ".ll", "target triple = \"bpf\"\n"},
		{"bc file", ".bc", "BC"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp := t.TempDir()
			f := filepath.Join(tmp, "input"+tt.ext)
			os.WriteFile(f, []byte(tt.content), 0o644)

			out, err := normalizeInputs(context.Background(),
				Config{Inputs: []string{f}, Timeout: 1 * time.Second}, llvm.Tools{}, tmp)
			if err != nil {
				t.Fatal(err)
			}
			if len(out) != 1 || out[0] != f {
				t.Fatalf("expected passthrough, got %v", out)
			}
		})
	}
}

func TestNormalizeSingleEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		run       func(t *testing.T) error
		wantErr   bool
		wantStage diag.Stage
	}{
		{
			name: "unknown extension returns nil",
			run: func(t *testing.T) error {
				t.Helper()
				paths, err := normalizeSingle(context.Background(),
					Config{Timeout: 1 * time.Second}, llvm.Tools{}, t.TempDir(), "unknown.xyz", 0)
				if err != nil {
					return err
				}
				if paths != nil {
					t.Fatalf("expected nil for unknown extension, got %v", paths)
				}
				return nil
			},
		},
		{
			name: "seq empty result",
			run: func(t *testing.T) error {
				t.Helper()
				tmp := t.TempDir()
				_, err := normalizeInputsSeq(context.Background(),
					Config{Inputs: []string{filepath.Join(tmp, "test.xyz")}, Timeout: 1 * time.Second},
					llvm.Tools{}, tmp)
				return err
			},
			wantErr:   true,
			wantStage: diag.StageInput,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run(t)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if tt.wantStage != "" && !diag.IsStage(err, tt.wantStage) {
					t.Fatalf("expected stage %v, got: %v", tt.wantStage, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func writeObj(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "input.o")
	os.WriteFile(p, []byte("obj"), 0o644)
	return p
}

func TestNormalizeObject(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T, dir string) llvm.Tools
		wantErr   bool
		wantStage diag.Stage
		check     func(t *testing.T, out []string)
	}{
		{
			name:      "requires objcopy",
			setup:     func(t *testing.T, dir string) llvm.Tools { t.Helper(); return llvm.Tools{} },
			wantErr:   true,
			wantStage: diag.StageInput,
		},
		{
			name: "success with objcopy",
			setup: func(t *testing.T, dir string) llvm.Tools {
				t.Helper()
				return llvm.Tools{Objcopy: fakeObjcopy(t, dir, "BC")}
			},
			check: func(t *testing.T, out []string) {
				t.Helper()
				if len(out) != 1 || filepath.Ext(out[0]) != ".bc" {
					t.Fatalf("expected 1 .bc output, got %v", out)
				}
			},
		},
		{
			name: "no llvmbc section",
			setup: func(t *testing.T, dir string) llvm.Tools {
				t.Helper()
				return llvm.Tools{Objcopy: fakeObjcopy(t, dir, "")}
			},
			wantErr: true,
		},
		{
			name: "empty llvmbc section",
			setup: func(t *testing.T, dir string) llvm.Tools {
				t.Helper()
				p := filepath.Join(dir, "llvm-objcopy")
				os.WriteFile(p, []byte("#!/bin/sh\n"+
					`for a in "$@"; do case "$a" in --dump-section=.llvmbc=*) touch "${a#--dump-section=.llvmbc=}";; esac; done`+"\n"), 0o755)
				return llvm.Tools{Objcopy: p}
			},
			wantErr: true,
		},
		{
			name: "objcopy failure",
			setup: func(t *testing.T, dir string) llvm.Tools {
				t.Helper()
				p := filepath.Join(dir, "llvm-objcopy")
				os.WriteFile(p, []byte("#!/bin/sh\necho fail >&2; exit 1\n"), 0o755)
				return llvm.Tools{Objcopy: p}
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp := t.TempDir()
			obj := writeObj(t, tmp)
			tools := tt.setup(t, tmp)

			out, err := normalizeInputs(context.Background(),
				Config{Inputs: []string{obj}, Timeout: 2 * time.Second},
				tools, tmp)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if tt.wantStage != "" && !diag.IsStage(err, tt.wantStage) {
					t.Fatalf("expected stage %v, got: %v", tt.wantStage, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.check != nil {
				tt.check(t, out)
			}
		})
	}
}

func writeArchive(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "input.a")
	os.WriteFile(p, []byte("ar"), 0o644)
	return p
}

func TestNormalizeArchive(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T, dir string) (llvm.Tools, string)
		wantErr   bool
		wantStage diag.Stage
		check     func(t *testing.T, out []string)
	}{
		{
			name: "requires llvm-ar",
			setup: func(t *testing.T, dir string) (llvm.Tools, string) {
				t.Helper()
				return llvm.Tools{}, dir
			},
			wantErr:   true,
			wantStage: diag.StageInput,
		},
		{
			name: "expands bc member",
			setup: func(t *testing.T, dir string) (llvm.Tools, string) {
				t.Helper()
				ar := fakeAr(t, dir, "member.bc\\n", "BC\\n")
				return llvm.Tools{LLVMAr: ar}, dir
			},
			check: func(t *testing.T, out []string) {
				t.Helper()
				if len(out) != 1 || filepath.Ext(out[0]) != ".bc" {
					t.Fatalf("expected 1 .bc output, got %v", out)
				}
			},
		},
		{
			name: "expands o member with objcopy",
			setup: func(t *testing.T, dir string) (llvm.Tools, string) {
				t.Helper()
				ar := fakeAr(t, dir, "member.o\\n", "obj")
				objcopy := fakeObjcopy(t, dir, "BC")
				return llvm.Tools{LLVMAr: ar, Objcopy: objcopy}, dir
			},
			check: func(t *testing.T, out []string) {
				t.Helper()
				if len(out) != 1 {
					t.Fatalf("expected 1 output, got %d", len(out))
				}
			},
		},
		{
			name: "no module members",
			setup: func(t *testing.T, dir string) (llvm.Tools, string) {
				t.Helper()
				ar := fakeAr(t, dir, "readme.txt\\n", "text content\\n")
				return llvm.Tools{LLVMAr: ar}, dir
			},
			wantErr: true,
		},
		{
			name: "skips empty member lines",
			setup: func(t *testing.T, dir string) (llvm.Tools, string) {
				t.Helper()
				ar := fakeAr(t, dir, "a.bc\\n\\nb.bc\\n", "BC\\n")
				return llvm.Tools{LLVMAr: ar}, dir
			},
			check: func(t *testing.T, out []string) {
				t.Helper()
				if len(out) != 2 {
					t.Fatalf("expected 2 outputs (empty line skipped), got %d: %v", len(out), out)
				}
			},
		},
		{
			name: "list failure",
			setup: func(t *testing.T, dir string) (llvm.Tools, string) {
				t.Helper()
				ar := filepath.Join(dir, "llvm-ar")
				os.WriteFile(ar, []byte("#!/bin/sh\necho fail >&2; exit 1\n"), 0o755)
				return llvm.Tools{LLVMAr: ar}, dir
			},
			wantErr: true,
		},
		{
			name: "print failure",
			setup: func(t *testing.T, dir string) (llvm.Tools, string) {
				t.Helper()
				ar := fakeAr(t, dir, "member.bc\\n", "")
				return llvm.Tools{LLVMAr: ar}, dir
			},
			wantErr: true,
		},
		{
			name: "write error",
			setup: func(t *testing.T, dir string) (llvm.Tools, string) {
				t.Helper()
				ar := fakeAr(t, dir, "member.bc\\n", "BC\\n")
				return llvm.Tools{LLVMAr: ar}, "/does/not/exist/workdir"
			},
			wantErr: true,
		},
		{
			name: "nested objcopy failure",
			setup: func(t *testing.T, dir string) (llvm.Tools, string) {
				t.Helper()
				ar := fakeAr(t, dir, "member.o\\n", "obj")
				objcopy := filepath.Join(dir, "llvm-objcopy")
				os.WriteFile(objcopy, []byte("#!/bin/sh\necho fail >&2; exit 1\n"), 0o755)
				return llvm.Tools{LLVMAr: ar, Objcopy: objcopy}, dir
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp := t.TempDir()
			archive := writeArchive(t, tmp)
			tools, workDir := tt.setup(t, tmp)

			out, err := normalizeInputs(context.Background(),
				Config{Inputs: []string{archive}, Timeout: 2 * time.Second},
				tools, workDir)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if tt.wantStage != "" && !diag.IsStage(err, tt.wantStage) {
					t.Fatalf("expected stage %v, got: %v", tt.wantStage, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.check != nil {
				tt.check(t, out)
			}
		})
	}
}

func TestNormalizeInputsParallel(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T, dir string) []string
		jobs    int
		usePar  bool
		wantErr bool
		check   func(t *testing.T, out, inputs []string)
	}{
		{
			name: "preserves order",
			setup: func(t *testing.T, dir string) []string {
				t.Helper()
				var inputs []string
				for i := range 10 {
					f := filepath.Join(dir, fmt.Sprintf("%02d.bc", i))
					os.WriteFile(f, []byte("bc"), 0o644)
					inputs = append(inputs, f)
				}
				return inputs
			},
			jobs: 4,
			check: func(t *testing.T, out, inputs []string) {
				t.Helper()
				for i, got := range out {
					if got != inputs[i] {
						t.Fatalf("order mismatch at %d: got %s, want %s", i, got, inputs[i])
					}
				}
			},
		},
		{
			name: "ll passthrough",
			setup: func(t *testing.T, dir string) []string {
				t.Helper()
				var inputs []string
				for _, name := range []string{"a.ll", "b.ll", "c.ll"} {
					f := filepath.Join(dir, name)
					os.WriteFile(f, []byte("target triple = \"bpf\"\n"), 0o644)
					inputs = append(inputs, f)
				}
				return inputs
			},
			jobs: 2,
			check: func(t *testing.T, out, _ []string) {
				t.Helper()
				if len(out) != 3 {
					t.Fatalf("expected 3, got %d", len(out))
				}
			},
		},
		{
			name: "error propagation",
			setup: func(t *testing.T, dir string) []string {
				t.Helper()
				ll := filepath.Join(dir, "good.ll")
				os.WriteFile(ll, []byte("target triple = \"bpf\"\n"), 0o644)
				obj := filepath.Join(dir, "bad.o")
				os.WriteFile(obj, []byte("not-elf"), 0o644)
				return []string{ll, obj}
			},
			jobs:    2,
			usePar:  true,
			wantErr: true,
		},
		{
			name: "empty result",
			setup: func(t *testing.T, dir string) []string {
				t.Helper()
				return []string{filepath.Join(dir, "a.xyz")}
			},
			jobs:    2,
			usePar:  true,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp := t.TempDir()
			inputs := tt.setup(t, tmp)

			var out []string
			var err error
			cfg := Config{Inputs: inputs, Timeout: 5 * time.Second, Jobs: tt.jobs}
			if tt.usePar {
				out, err = normalizeInputsParallel(context.Background(), cfg, llvm.Tools{}, tmp)
			} else {
				out, err = normalizeInputs(context.Background(), cfg, llvm.Tools{}, tmp)
			}
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.check != nil {
				tt.check(t, out, inputs)
			}
		})
	}
}

func TestSanitizeName(t *testing.T) {
	tests := []struct{ in, want string }{
		{"foo/bar", "foo_bar"},
		{"foo\\bar", "foo_bar"},
		{"foo bar", "foo_bar"},
		{"simple", "simple"},
	}
	for _, tt := range tests {
		if got := sanitizeName(tt.in); got != tt.want {
			t.Errorf("sanitizeName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
