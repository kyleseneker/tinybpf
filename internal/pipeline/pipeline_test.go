package pipeline

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kyleseneker/tinybpf/internal/diag"
	"github.com/kyleseneker/tinybpf/internal/llvm"
)

// makeFakeTool creates a shell script in dir and returns its absolute path.
func makeFakeTool(t *testing.T, dir, name, script string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// copyToolScript is a shell snippet that copies the input file to the -o output.
const copyToolScript = `
out=""; in=""
for arg in "$@"; do case "$arg" in -o) n=1;; -passes=*|-S|-march=*|-mcpu=*|-filetype=*) ;; *) if [ "${n:-}" = 1 ]; then out="$arg"; n=0; else in="$arg"; fi;; esac; done
[ -n "$in" ] && [ -n "$out" ] && cp "$in" "$out"; exit 0`

// llcElfScript is a shell snippet that produces a minimal valid BPF ELF.
const llcElfScript = `
out=""
for arg in "$@"; do case "$arg" in -o) n=1;; *) [ "${n:-}" = 1 ] && { out="$arg"; n=0; };; esac; done
python3 -c "
import struct,sys
h=bytearray(64);h[0:4]=b'\\x7fELF';h[4]=2;h[5]=1;h[6]=1
struct.pack_into('<H',h,16,1);struct.pack_into('<H',h,18,247);struct.pack_into('<I',h,20,1)
struct.pack_into('<H',h,52,64);struct.pack_into('<H',h,58,64)
c=b'\\x95\\x00\\x00\\x00\\x00\\x00\\x00\\x00'
st=b'\\x00test\\x00\\x00\\x00\\x00'
ns=b'\\x00'*24;rs=struct.pack('<IBBHQQ',1,18,0,0,0,0)
ss=b'\\x00.text\\x00.symtab\\x00.strtab\\x00.shstrtab\\x00\\x00\\x00\\x00'
o=64;d=c;sto=o+len(d);d+=st;syo=o+len(d);d+=ns+rs;sso=o+len(d);d+=ss;so=o+len(d)
def s(n,t,f,off,sz,l=0,i=0,e=0):
 r=bytearray(64);struct.pack_into('<I',r,0,n);struct.pack_into('<I',r,4,t);struct.pack_into('<Q',r,8,f)
 struct.pack_into('<Q',r,24,off);struct.pack_into('<Q',r,32,sz);struct.pack_into('<I',r,40,l)
 struct.pack_into('<I',r,44,i);struct.pack_into('<Q',r,48,8);struct.pack_into('<Q',r,56,e);return bytes(r)
sh=s(0,0,0,0,0)+s(1,1,6,o,len(c))+s(7,3,0,sto,len(st))+s(15,2,0,syo,48,2,1,24)+s(23,3,0,sso,len(ss))
struct.pack_into('<Q',h,40,so);struct.pack_into('<H',h,60,5);struct.pack_into('<H',h,62,4)
sys.stdout.buffer.write(bytes(h)+d+sh)" > "$out"
exit 0`

// testIR returns LLVM IR with a single program function.
const testIR = `target datalayout = "e-m:o-p270:32:32"
target triple = "arm64-apple-macosx11.0.0"

define i32 @handle_connect(ptr %ctx) {
entry:
  ret i32 0
}
`

// pipelineEnv holds a reusable fake LLVM toolchain directory.
type pipelineEnv struct {
	Dir     string
	ToolDir string
	Input   string
	Output  string
	Tools   llvm.ToolOverrides
}

// newPipelineEnv creates a temp directory with fake LLVM tools and a valid IR input file.
func newPipelineEnv(t *testing.T) *pipelineEnv {
	t.Helper()
	tmp := t.TempDir()
	toolDir := filepath.Join(tmp, "tools")
	os.MkdirAll(toolDir, 0o755)

	input := filepath.Join(tmp, "input.ll")
	os.WriteFile(input, []byte(testIR), 0o644)

	makeFakeTool(t, toolDir, "llvm-link", copyToolScript)
	makeFakeTool(t, toolDir, "opt", copyToolScript)
	makeFakeTool(t, toolDir, "llc", llcElfScript)

	return &pipelineEnv{
		Dir:     tmp,
		ToolDir: toolDir,
		Input:   input,
		Output:  filepath.Join(tmp, "output.o"),
		Tools: llvm.ToolOverrides{
			LLVMLink: filepath.Join(toolDir, "llvm-link"),
			Opt:      filepath.Join(toolDir, "opt"),
			LLC:      filepath.Join(toolDir, "llc"),
		},
	}
}

// cfg returns a Config pre-filled with the env's paths.
func (e *pipelineEnv) cfg() Config {
	return Config{
		Inputs:  []string{e.Input},
		Output:  e.Output,
		Tools:   e.Tools,
		Timeout: 10 * time.Second,
		Stdout:  &bytes.Buffer{},
		Stderr:  &bytes.Buffer{},
	}
}

func TestRunValidation(t *testing.T) {
	tests := []struct {
		name  string
		cfg   Config
		stage diag.Stage
	}{
		{
			name:  "no inputs",
			cfg:   Config{Output: "out.o"},
			stage: diag.StageInput,
		},
		{
			name: "empty output",
			cfg: Config{
				Inputs: []string{filepath.Join(t.TempDir(), "in.ll")},
				Output: "   ",
			},
			stage: diag.StageInput,
		},
		{
			name: "unsupported input extension",
			cfg: func() Config {
				tmp := t.TempDir()
				p := filepath.Join(tmp, "foo.txt")
				os.WriteFile(p, []byte("nope"), 0o644)
				return Config{Inputs: []string{p}, Output: filepath.Join(tmp, "out.o")}
			}(),
			stage: diag.StageInput,
		},
		{
			name: "missing tool",
			cfg: func() Config {
				tmp := t.TempDir()
				p := filepath.Join(tmp, "in.ll")
				os.WriteFile(p, []byte("target triple = \"bpf\"\n"), 0o644)
				return Config{
					Inputs: []string{p},
					Output: filepath.Join(tmp, "out.o"),
					Tools:  llvm.ToolOverrides{LLVMLink: "/does/not/exist/llvm-link"},
				}
			}(),
			stage: diag.StageDiscover,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Run(context.Background(), tt.cfg)
			if err == nil {
				t.Fatal("expected error")
			}
			if !diag.IsStage(err, tt.stage) {
				t.Fatalf("expected stage %v, got: %v", tt.stage, err)
			}
		})
	}
}

func TestEnsureInputSupported(t *testing.T) {
	for _, ext := range []string{".ll", ".bc", ".o", ".a"} {
		if err := ensureInputSupported("test" + ext); err != nil {
			t.Errorf("expected %s supported: %v", ext, err)
		}
	}
	for _, ext := range []string{".txt", ".go", ".json", ""} {
		if err := ensureInputSupported("test" + ext); err == nil {
			t.Errorf("expected %s rejected", ext)
		}
	}
}

func TestRunStageFailures(t *testing.T) {
	tests := []struct {
		name      string
		failTool  string
		wantStage diag.Stage
	}{
		{"link", "llvm-link", diag.StageLink},
		{"opt", "opt", diag.StageOpt},
		{"codegen", "llc", diag.StageCodegen},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newPipelineEnv(t)
			makeFakeTool(t, env.ToolDir, tt.failTool, "echo fail >&2; exit 1")

			_, err := Run(context.Background(), env.cfg())
			if err == nil {
				t.Fatal("expected error")
			}
			if !diag.IsStage(err, tt.wantStage) {
				t.Fatalf("expected stage %v, got: %v", tt.wantStage, err)
			}
		})
	}
}

func TestRunTransformError(t *testing.T) {
	env := newPipelineEnv(t)

	os.WriteFile(env.Input, []byte("@x = global i32 0\n"), 0o644)

	_, err := Run(context.Background(), env.cfg())
	if err == nil {
		t.Fatal("expected transform error")
	}
	if !diag.IsStage(err, diag.StageTransform) {
		t.Fatalf("expected transform stage error, got: %v", err)
	}
}

func TestRunElfcheckError(t *testing.T) {
	env := newPipelineEnv(t)
	makeFakeTool(t, env.ToolDir, "llc", `
out=""
for arg in "$@"; do case "$arg" in -o) n=1;; *) [ "${n:-}" = 1 ] && { out="$arg"; n=0; };; esac; done
echo "not-an-elf" > "$out"; exit 0`)

	_, err := Run(context.Background(), env.cfg())
	if err == nil {
		t.Fatal("expected elfcheck error")
	}
}

func TestRunMakeWorkDirError(t *testing.T) {
	env := newPipelineEnv(t)
	cfg := env.cfg()
	cfg.TempDir = "/dev/null/impossible"

	_, err := Run(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error")
	}
	if !diag.IsStage(err, diag.StageInput) {
		t.Fatalf("expected input stage error, got: %v", err)
	}
}

func TestRunNormalizeError(t *testing.T) {
	env := newPipelineEnv(t)
	cfg := env.cfg()
	objInput := filepath.Join(env.Dir, "input.o")
	os.WriteFile(objInput, []byte("obj-data"), 0o644)
	cfg.Inputs = []string{objInput}

	_, err := Run(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected normalization error for .o without objcopy")
	}
}

func TestRunOutputMkdirAllError(t *testing.T) {
	env := newPipelineEnv(t)
	cfg := env.cfg()
	cfg.Output = "/dev/null/impossible/out.o"

	_, err := Run(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error")
	}
	if !diag.IsStage(err, diag.StageFinalize) {
		t.Fatalf("expected finalize stage error, got: %v", err)
	}
}

func TestRunFullPipelineFakeTools(t *testing.T) {
	env := newPipelineEnv(t)
	cfg := env.cfg()
	cfg.Sections = map[string]string{"handle_connect": "kprobe/sys_connect"}
	cfg.Verbose = true

	stdout := cfg.Stdout.(*bytes.Buffer)
	artifacts, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pipeline failed: %v", err)
	}
	if artifacts == nil {
		t.Fatal("expected artifacts")
	}
	if _, err := os.Stat(env.Output); err != nil {
		t.Fatalf("output not created: %v", err)
	}
	if !strings.Contains(stdout.String(), "[llvm-link]") {
		t.Errorf("expected verbose stage output, got: %q", stdout.String())
	}
}

func TestRunPipelineWithBTF(t *testing.T) {
	env := newPipelineEnv(t)
	makeFakeTool(t, env.ToolDir, "pahole", "exit 0")
	cfg := env.cfg()
	cfg.EnableBTF = true
	cfg.Tools.Pahole = filepath.Join(env.ToolDir, "pahole")

	_, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pipeline with BTF failed: %v", err)
	}
}

func TestRunPipelineWithBTFFailure(t *testing.T) {
	env := newPipelineEnv(t)
	makeFakeTool(t, env.ToolDir, "pahole", "echo btf-fail >&2; exit 1")
	cfg := env.cfg()
	cfg.EnableBTF = true
	cfg.Tools.Pahole = filepath.Join(env.ToolDir, "pahole")

	_, err := Run(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected BTF failure")
	}
	if !diag.IsStage(err, diag.StageBTF) {
		t.Fatalf("expected BTF stage error, got: %v", err)
	}
}

func TestRunPipelineWithCustomPasses(t *testing.T) {
	env := newPipelineEnv(t)
	cfg := env.cfg()
	cfg.CustomPasses = []string{"-inline", "-dse"}

	_, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pipeline with custom passes failed: %v", err)
	}
}

func TestRunPipelineWithInvalidCustomPasses(t *testing.T) {
	env := newPipelineEnv(t)
	cfg := env.cfg()
	cfg.CustomPasses = []string{"-inline;rm -rf /"}

	_, err := Run(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for invalid custom passes")
	}
	if !diag.IsStage(err, diag.StageOpt) {
		t.Fatalf("expected opt stage error, got: %v", err)
	}
}

func TestMakeWorkDir(t *testing.T) {
	t.Run("explicit dir", func(t *testing.T) {
		base := filepath.Join(t.TempDir(), "explicit")
		dir, cleanup, err := makeWorkDir(base, false)
		if err != nil {
			t.Fatal(err)
		}
		defer cleanup()
		if dir != base {
			t.Fatalf("expected %s, got %s", base, dir)
		}
	})

	t.Run("explicit dir permissions", func(t *testing.T) {
		base := filepath.Join(t.TempDir(), "workdir")
		dir, cleanup, err := makeWorkDir(base, false)
		if err != nil {
			t.Fatal(err)
		}
		defer cleanup()
		info, _ := os.Stat(dir)
		if perm := info.Mode().Perm(); perm != 0o700 {
			t.Fatalf("expected 0700, got %o", perm)
		}
	})

	t.Run("temp dir cleanup", func(t *testing.T) {
		dir, cleanup, err := makeWorkDir("", false)
		if err != nil {
			t.Fatal(err)
		}
		cleanup()
		if _, err := os.Stat(dir); err == nil {
			t.Fatal("temp dir should be removed after cleanup")
		}
	})

	t.Run("temp dir keepTemp", func(t *testing.T) {
		dir, cleanup, err := makeWorkDir("", true)
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)
		cleanup()
		if _, err := os.Stat(dir); err != nil {
			t.Fatal("temp dir should be kept with keepTemp")
		}
	})

	t.Run("bad path", func(t *testing.T) {
		_, _, err := makeWorkDir("/dev/null/impossible", false)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("bad TMPDIR", func(t *testing.T) {
		t.Setenv("TMPDIR", "/does/not/exist/tmpdir")
		_, _, err := makeWorkDir("", false)
		if err == nil {
			t.Fatal("expected error for bad TMPDIR")
		}
	})

	t.Run("inside file", func(t *testing.T) {
		tmp := t.TempDir()
		file := filepath.Join(tmp, "not-a-dir")
		os.WriteFile(file, []byte("x"), 0o644)
		_, _, err := makeWorkDir(filepath.Join(file, "sub"), false)
		if err == nil {
			t.Fatal("expected error creating dir inside a file")
		}
	})
}

func TestRunStage(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		bin := makeFakeTool(t, t.TempDir(), "ok-tool", "echo done")
		cfg := Config{Timeout: 5 * time.Second, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
		if err := runStage(context.Background(), cfg, diag.StageLink, bin, nil, "hint"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("verbose", func(t *testing.T) {
		bin := makeFakeTool(t, t.TempDir(), "verbose-tool", "echo out; echo err >&2")
		var stdout, stderr bytes.Buffer
		cfg := Config{Timeout: 5 * time.Second, Verbose: true, Stdout: &stdout, Stderr: &stderr}
		if err := runStage(context.Background(), cfg, diag.StageLink, bin, nil, "hint"); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(stdout.String(), "llvm-link") {
			t.Errorf("expected stage name in verbose output, got: %q", stdout.String())
		}
	})

	t.Run("failure", func(t *testing.T) {
		bin := makeFakeTool(t, t.TempDir(), "fail-tool", "echo bad >&2; exit 1")
		cfg := Config{Timeout: 5 * time.Second, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
		err := runStage(context.Background(), cfg, diag.StageLink, bin, nil, "fix it")
		if err == nil {
			t.Fatal("expected error")
		}
		if !diag.IsStage(err, diag.StageLink) {
			t.Fatalf("expected link stage error, got: %v", err)
		}
	})
}

func TestBuildLLCArgs(t *testing.T) {
	args := buildLLCArgs("v4", "in.ll", "out.o")
	want := []string{"-march=bpf", "-mcpu=v4", "-filetype=obj", "in.ll", "-o", "out.o"}
	if len(args) != len(want) {
		t.Fatalf("arg count: got=%d want=%d", len(args), len(want))
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args[%d]: got=%q want=%q", i, args[i], want[i])
		}
	}
}

func TestCopyFile(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		tmp := t.TempDir()
		src := filepath.Join(tmp, "src")
		dst := filepath.Join(tmp, "dst")
		os.WriteFile(src, []byte("hello"), 0o644)
		if err := copyFile(src, dst); err != nil {
			t.Fatal(err)
		}
		got, _ := os.ReadFile(dst)
		if string(got) != "hello" {
			t.Fatalf("content mismatch: %q", got)
		}
	})

	t.Run("missing source", func(t *testing.T) {
		if err := copyFile("/does/not/exist", filepath.Join(t.TempDir(), "dst")); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestStripHostPaths(t *testing.T) {
	t.Run("replaces temp dir", func(t *testing.T) {
		tmp := t.TempDir()
		ll := filepath.Join(tmp, "test.ll")
		content := `source_filename = "` + tmp + `/input.ll"` + "\ndefine void @f() { ret void }\n"
		os.WriteFile(ll, []byte(content), 0o644)

		if err := stripHostPaths(ll, tmp); err != nil {
			t.Fatal(err)
		}
		got, _ := os.ReadFile(ll)
		if strings.Contains(string(got), tmp) {
			t.Fatalf("temp dir not stripped: %s", got)
		}
		if !strings.Contains(string(got), "./input.ll") {
			t.Fatalf("expected relative path: %s", got)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		if err := stripHostPaths("/does/not/exist.ll", "/tmp"); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestParseSectionFlags(t *testing.T) {
	tests := []struct {
		name    string
		flags   []string
		want    map[string]string
		wantErr string
	}{
		{"nil", nil, nil, ""},
		{"valid entries", []string{"handle_connect=kprobe/sys_connect", "xdp_filter=xdp"}, map[string]string{"handle_connect": "kprobe/sys_connect", "xdp_filter": "xdp"}, ""},
		{"rejects missing equals", []string{"no-equals"}, nil, "invalid --section"},
		{"rejects empty key", []string{"=kprobe/sys_connect"}, nil, "invalid --section"},
		{"rejects empty value", []string{"handle_connect="}, nil, "invalid --section"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := ParseSectionFlags(tt.flags)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected %q in error, got: %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.want == nil {
				if m != nil {
					t.Fatalf("expected nil, got %v", m)
				}
				return
			}
			for k, v := range tt.want {
				if m[k] != v {
					t.Fatalf("key %q: got %q, want %q", k, m[k], v)
				}
			}
		})
	}
}

func TestRunE2ESmoke(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("BPF validation requires Linux")
	}
	for _, tool := range []string{"llvm-link", "opt", "llc"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("missing %s", tool)
		}
	}

	wd, _ := os.Getwd()
	input := filepath.Join(wd, "..", "..", "testdata", "minimal.ll")
	if _, err := os.Stat(input); err != nil {
		t.Fatalf("missing test fixture: %v", err)
	}

	output := filepath.Join(t.TempDir(), "prog.o")
	artifacts, err := Run(context.Background(), Config{
		Inputs: []string{input}, Output: output, Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if artifacts == nil {
		t.Fatal("expected artifacts")
	}
}

func TestRunInvalidIRFixture(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("BPF validation requires Linux")
	}
	for _, tool := range []string{"llvm-link", "opt", "llc"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("missing %s", tool)
		}
	}

	wd, _ := os.Getwd()
	input := filepath.Join(wd, "..", "..", "testdata", "invalid.ll")
	_, err := Run(context.Background(), Config{
		Inputs: []string{input}, Output: filepath.Join(t.TempDir(), "prog.o"),
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !diag.IsStage(err, diag.StageLink) {
		t.Fatalf("expected link stage error, got: %v", err)
	}
}
