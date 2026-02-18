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
		ext     string
		content string
	}{
		{".ll", "target triple = \"bpf\"\n"},
		{".bc", "BC"},
	}
	for _, tt := range tests {
		t.Run(tt.ext, func(t *testing.T) {
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

func TestNormalizeObject(t *testing.T) {
	writeObj := func(t *testing.T, dir string) string {
		t.Helper()
		p := filepath.Join(dir, "input.o")
		os.WriteFile(p, []byte("obj"), 0o644)
		return p
	}

	t.Run("requires objcopy", func(t *testing.T) {
		tmp := t.TempDir()
		obj := writeObj(t, tmp)
		_, err := normalizeInputs(context.Background(),
			Config{Inputs: []string{obj}, Timeout: 1 * time.Second}, llvm.Tools{}, tmp)
		if err == nil {
			t.Fatal("expected error")
		}
		if !diag.IsStage(err, diag.StageInput) {
			t.Fatalf("expected input stage error, got: %v", err)
		}
	})

	t.Run("success with objcopy", func(t *testing.T) {
		tmp := t.TempDir()
		obj := writeObj(t, tmp)
		objcopy := fakeObjcopy(t, tmp, "BC")

		out, err := normalizeInputs(context.Background(),
			Config{Inputs: []string{obj}, Timeout: 2 * time.Second},
			llvm.Tools{Objcopy: objcopy}, tmp)
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 1 || filepath.Ext(out[0]) != ".bc" {
			t.Fatalf("expected 1 .bc output, got %v", out)
		}
	})

	t.Run("no llvmbc section", func(t *testing.T) {
		tmp := t.TempDir()
		obj := writeObj(t, tmp)
		objcopy := fakeObjcopy(t, tmp, "")

		_, err := normalizeInputs(context.Background(),
			Config{Inputs: []string{obj}, Timeout: 2 * time.Second},
			llvm.Tools{Objcopy: objcopy}, tmp)
		if err == nil {
			t.Fatal("expected error for missing .llvmbc section")
		}
	})

	t.Run("empty llvmbc section", func(t *testing.T) {
		tmp := t.TempDir()
		obj := writeObj(t, tmp)
		p := filepath.Join(tmp, "llvm-objcopy")
		os.WriteFile(p, []byte("#!/bin/sh\n"+
			`for a in "$@"; do case "$a" in --dump-section=.llvmbc=*) touch "${a#--dump-section=.llvmbc=}";; esac; done`+"\n"), 0o755)

		_, err := normalizeInputs(context.Background(),
			Config{Inputs: []string{obj}, Timeout: 2 * time.Second},
			llvm.Tools{Objcopy: p}, tmp)
		if err == nil {
			t.Fatal("expected error for empty .llvmbc section")
		}
	})

	t.Run("objcopy failure", func(t *testing.T) {
		tmp := t.TempDir()
		obj := writeObj(t, tmp)
		p := filepath.Join(tmp, "llvm-objcopy")
		os.WriteFile(p, []byte("#!/bin/sh\necho fail >&2; exit 1\n"), 0o755)

		_, err := normalizeInputs(context.Background(),
			Config{Inputs: []string{obj}, Timeout: 2 * time.Second},
			llvm.Tools{Objcopy: p}, tmp)
		if err == nil {
			t.Fatal("expected error from objcopy failure")
		}
	})
}

func TestNormalizeArchive(t *testing.T) {
	writeArchive := func(t *testing.T, dir string) string {
		t.Helper()
		p := filepath.Join(dir, "input.a")
		os.WriteFile(p, []byte("ar"), 0o644)
		return p
	}

	t.Run("requires llvm-ar", func(t *testing.T) {
		tmp := t.TempDir()
		archive := writeArchive(t, tmp)
		_, err := normalizeInputs(context.Background(),
			Config{Inputs: []string{archive}, Timeout: 1 * time.Second}, llvm.Tools{}, tmp)
		if err == nil {
			t.Fatal("expected error")
		}
		if !diag.IsStage(err, diag.StageInput) {
			t.Fatalf("expected input stage error, got: %v", err)
		}
	})

	t.Run("expands bc member", func(t *testing.T) {
		tmp := t.TempDir()
		archive := writeArchive(t, tmp)
		ar := fakeAr(t, tmp, "member.bc\\n", "BC\\n")

		out, err := normalizeInputs(context.Background(),
			Config{Inputs: []string{archive}, Timeout: 2 * time.Second},
			llvm.Tools{LLVMAr: ar}, tmp)
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 1 || filepath.Ext(out[0]) != ".bc" {
			t.Fatalf("expected 1 .bc output, got %v", out)
		}
	})

	t.Run("expands o member with objcopy", func(t *testing.T) {
		tmp := t.TempDir()
		archive := writeArchive(t, tmp)
		ar := fakeAr(t, tmp, "member.o\\n", "obj")
		objcopy := fakeObjcopy(t, tmp, "BC")

		out, err := normalizeInputs(context.Background(),
			Config{Inputs: []string{archive}, Timeout: 2 * time.Second},
			llvm.Tools{LLVMAr: ar, Objcopy: objcopy}, tmp)
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 1 {
			t.Fatalf("expected 1 output, got %d", len(out))
		}
	})

	t.Run("no module members", func(t *testing.T) {
		tmp := t.TempDir()
		archive := writeArchive(t, tmp)
		ar := fakeAr(t, tmp, "readme.txt\\n", "text content\\n")

		_, err := normalizeInputs(context.Background(),
			Config{Inputs: []string{archive}, Timeout: 2 * time.Second},
			llvm.Tools{LLVMAr: ar}, tmp)
		if err == nil {
			t.Fatal("expected error for archive with no LLVM module members")
		}
	})

	t.Run("skips empty member lines", func(t *testing.T) {
		tmp := t.TempDir()
		archive := writeArchive(t, tmp)
		ar := fakeAr(t, tmp, "a.bc\\n\\nb.bc\\n", "BC\\n")

		out, err := normalizeInputs(context.Background(),
			Config{Inputs: []string{archive}, Timeout: 2 * time.Second},
			llvm.Tools{LLVMAr: ar}, tmp)
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 2 {
			t.Fatalf("expected 2 outputs (empty line skipped), got %d: %v", len(out), out)
		}
	})

	t.Run("list failure", func(t *testing.T) {
		tmp := t.TempDir()
		archive := writeArchive(t, tmp)
		ar := filepath.Join(tmp, "llvm-ar")
		os.WriteFile(ar, []byte("#!/bin/sh\necho fail >&2; exit 1\n"), 0o755)

		_, err := normalizeInputs(context.Background(),
			Config{Inputs: []string{archive}, Timeout: 2 * time.Second},
			llvm.Tools{LLVMAr: ar}, tmp)
		if err == nil {
			t.Fatal("expected error from llvm-ar t failure")
		}
	})

	t.Run("print failure", func(t *testing.T) {
		tmp := t.TempDir()
		archive := writeArchive(t, tmp)
		ar := fakeAr(t, tmp, "member.bc\\n", "") // print subcommand fails

		_, err := normalizeInputs(context.Background(),
			Config{Inputs: []string{archive}, Timeout: 2 * time.Second},
			llvm.Tools{LLVMAr: ar}, tmp)
		if err == nil {
			t.Fatal("expected error from llvm-ar p failure")
		}
	})

	t.Run("write error", func(t *testing.T) {
		tmp := t.TempDir()
		archive := writeArchive(t, tmp)
		ar := fakeAr(t, tmp, "member.bc\\n", "BC\\n")

		_, err := expandArchive(context.Background(),
			Config{Timeout: 2 * time.Second},
			llvm.Tools{LLVMAr: ar}, archive, "/does/not/exist/workdir")
		if err == nil {
			t.Fatal("expected error from write failure")
		}
	})

	t.Run("nested objcopy failure", func(t *testing.T) {
		tmp := t.TempDir()
		archive := writeArchive(t, tmp)
		ar := fakeAr(t, tmp, "member.o\\n", "obj")
		objcopy := filepath.Join(tmp, "llvm-objcopy")
		os.WriteFile(objcopy, []byte("#!/bin/sh\necho fail >&2; exit 1\n"), 0o755)

		_, err := normalizeInputs(context.Background(),
			Config{Inputs: []string{archive}, Timeout: 2 * time.Second},
			llvm.Tools{LLVMAr: ar, Objcopy: objcopy}, tmp)
		if err == nil {
			t.Fatal("expected error from nested objcopy failure")
		}
	})
}

func TestNormalizeInputsParallel(t *testing.T) {
	t.Run("preserves order", func(t *testing.T) {
		tmp := t.TempDir()
		var inputs []string
		for i := range 10 {
			f := filepath.Join(tmp, fmt.Sprintf("%02d.bc", i))
			os.WriteFile(f, []byte("bc"), 0o644)
			inputs = append(inputs, f)
		}
		out, err := normalizeInputs(context.Background(),
			Config{Inputs: inputs, Timeout: 5 * time.Second, Jobs: 4},
			llvm.Tools{}, tmp)
		if err != nil {
			t.Fatal(err)
		}
		for i, got := range out {
			if got != inputs[i] {
				t.Fatalf("order mismatch at %d: got %s, want %s", i, got, inputs[i])
			}
		}
	})

	t.Run("ll passthrough", func(t *testing.T) {
		tmp := t.TempDir()
		var inputs []string
		for _, name := range []string{"a.ll", "b.ll", "c.ll"} {
			f := filepath.Join(tmp, name)
			os.WriteFile(f, []byte("target triple = \"bpf\"\n"), 0o644)
			inputs = append(inputs, f)
		}
		out, err := normalizeInputs(context.Background(),
			Config{Inputs: inputs, Timeout: 5 * time.Second, Jobs: 2},
			llvm.Tools{}, tmp)
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 3 {
			t.Fatalf("expected 3, got %d", len(out))
		}
	})

	t.Run("error propagation", func(t *testing.T) {
		tmp := t.TempDir()
		ll := filepath.Join(tmp, "good.ll")
		os.WriteFile(ll, []byte("target triple = \"bpf\"\n"), 0o644)
		obj := filepath.Join(tmp, "bad.o")
		os.WriteFile(obj, []byte("not-elf"), 0o644)

		_, err := normalizeInputsParallel(context.Background(),
			Config{Inputs: []string{ll, obj}, Timeout: 2 * time.Second, Jobs: 2},
			llvm.Tools{}, tmp)
		if err == nil {
			t.Fatal("expected error from parallel normalization")
		}
	})

	t.Run("empty result", func(t *testing.T) {
		tmp := t.TempDir()
		_, err := normalizeInputsParallel(context.Background(),
			Config{Inputs: []string{filepath.Join(tmp, "a.xyz")}, Timeout: 1 * time.Second, Jobs: 2},
			llvm.Tools{}, tmp)
		if err == nil {
			t.Fatal("expected error for empty result")
		}
		if !diag.IsStage(err, diag.StageInput) {
			t.Fatalf("expected input stage error, got: %v", err)
		}
	})
}

func TestNormalizeSingleUnknownExtension(t *testing.T) {
	paths, err := normalizeSingle(context.Background(),
		Config{Timeout: 1 * time.Second}, llvm.Tools{}, t.TempDir(), "unknown.xyz", 0)
	if err != nil {
		t.Fatal(err)
	}
	if paths != nil {
		t.Fatalf("expected nil for unknown extension, got %v", paths)
	}
}

func TestNormalizeInputsSeqEmptyResult(t *testing.T) {
	tmp := t.TempDir()
	_, err := normalizeInputsSeq(context.Background(),
		Config{Inputs: []string{filepath.Join(tmp, "test.xyz")}, Timeout: 1 * time.Second},
		llvm.Tools{}, tmp)
	if err == nil {
		t.Fatal("expected error for empty normalization result")
	}
	if !diag.IsStage(err, diag.StageInput) {
		t.Fatalf("expected input stage error, got: %v", err)
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
