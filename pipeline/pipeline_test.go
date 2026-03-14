package pipeline

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kyleseneker/tinybpf/diag"
	"github.com/kyleseneker/tinybpf/internal/testutil"
	"github.com/kyleseneker/tinybpf/llvm"
)

func makeFakeTool(t *testing.T, dir, name, script string) string {
	t.Helper()
	return testutil.MakeFakeTool(t, dir, name, script)
}

var (
	copyToolScript = testutil.CopyToolScript
	llcElfScript   = testutil.LLCELFScript
	testIR         = testutil.SampleIR("handle_connect")
)

type pipelineEnv struct {
	Dir     string
	ToolDir string
	Input   string
	Output  string
	Tools   llvm.ToolOverrides
}

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
					Tools:  llvm.ToolOverrides{LLVMLink: testutil.BadPath("llvm-link")},
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

func TestRunErrors(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T, env *pipelineEnv, cfg *Config)
		wantStage diag.Stage
	}{
		{
			name: "transform error",
			setup: func(t *testing.T, env *pipelineEnv, cfg *Config) {
				t.Helper()
				os.WriteFile(env.Input, []byte("@x = global i32 0\n"), 0o644)
			},
			wantStage: diag.StageTransform,
		},
		{
			name: "elfcheck error",
			setup: func(t *testing.T, env *pipelineEnv, cfg *Config) {
				t.Helper()
				makeFakeTool(t, env.ToolDir, "llc", `
out=""
for arg in "$@"; do case "$arg" in -o) n=1;; *) [ "${n:-}" = 1 ] && { out="$arg"; n=0; };; esac; done
echo "not-an-elf" > "$out"; exit 0`)
			},
		},
		{
			name: "custom ValidateELF rejects",
			setup: func(t *testing.T, _ *pipelineEnv, cfg *Config) {
				t.Helper()
				cfg.ValidateELF = func(string) error {
					return fmt.Errorf("custom validator rejected")
				}
			},
		},
		{
			name: "make workdir error",
			setup: func(t *testing.T, _ *pipelineEnv, cfg *Config) {
				t.Helper()
				cfg.TempDir = testutil.BadPath()
			},
			wantStage: diag.StageInput,
		},
		{
			name: "normalize error",
			setup: func(t *testing.T, env *pipelineEnv, cfg *Config) {
				t.Helper()
				objInput := filepath.Join(env.Dir, "input.o")
				os.WriteFile(objInput, []byte("obj-data"), 0o644)
				cfg.Inputs = []string{objInput}
			},
		},
		{
			name: "output mkdirall error",
			setup: func(t *testing.T, _ *pipelineEnv, cfg *Config) {
				t.Helper()
				cfg.Output = testutil.BadPath("out.o")
			},
			wantStage: diag.StageFinalize,
		},
		{
			name: "BTF failure",
			setup: func(t *testing.T, env *pipelineEnv, cfg *Config) {
				t.Helper()
				makeFakeTool(t, env.ToolDir, "pahole", "echo btf-fail >&2; exit 1")
				cfg.EnableBTF = true
				cfg.Tools.Pahole = filepath.Join(env.ToolDir, "pahole")
			},
			wantStage: diag.StageBTF,
		},
		{
			name: "invalid custom passes",
			setup: func(t *testing.T, _ *pipelineEnv, cfg *Config) {
				t.Helper()
				cfg.CustomPasses = []string{"-inline;rm -rf /"}
			},
			wantStage: diag.StageOpt,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newPipelineEnv(t)
			cfg := env.cfg()
			if tt.setup != nil {
				tt.setup(t, env, &cfg)
			}
			_, err := Run(context.Background(), cfg)
			if err == nil {
				t.Fatal("expected error")
			}
			if tt.wantStage != "" && !diag.IsStage(err, tt.wantStage) {
				t.Fatalf("expected stage %v, got: %v", tt.wantStage, err)
			}
		})
	}
}

func TestRunSuccess(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, env *pipelineEnv, cfg *Config)
		check func(t *testing.T, artifacts *Artifacts, stdout string)
	}{
		{
			name: "full pipeline fake tools",
			setup: func(t *testing.T, _ *pipelineEnv, cfg *Config) {
				t.Helper()
				cfg.Sections = map[string]string{"handle_connect": "kprobe/sys_connect"}
				cfg.Verbose = true
			},
			check: func(t *testing.T, a *Artifacts, stdout string) {
				t.Helper()
				if !strings.Contains(stdout, "[llvm-link]") {
					t.Errorf("expected verbose stage output, got: %q", stdout)
				}
			},
		},
		{
			name: "pipeline with BTF",
			setup: func(t *testing.T, env *pipelineEnv, cfg *Config) {
				t.Helper()
				makeFakeTool(t, env.ToolDir, "pahole", "exit 0")
				cfg.EnableBTF = true
				cfg.Tools.Pahole = filepath.Join(env.ToolDir, "pahole")
			},
		},
		{
			name: "pipeline with custom passes",
			setup: func(t *testing.T, _ *pipelineEnv, cfg *Config) {
				t.Helper()
				cfg.CustomPasses = []string{"-inline", "-dse"}
			},
		},
		{
			name: "custom ValidateELF accepts",
			setup: func(t *testing.T, _ *pipelineEnv, cfg *Config) {
				t.Helper()
				cfg.ValidateELF = func(string) error { return nil }
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newPipelineEnv(t)
			cfg := env.cfg()
			if tt.setup != nil {
				tt.setup(t, env, &cfg)
			}
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
			if tt.check != nil {
				tt.check(t, artifacts, stdout.String())
			}
		})
	}
}

func TestSetupDumpIR(t *testing.T) {
	tests := []struct {
		name    string
		dumpIR  bool
		verbose bool
		badDir  bool
		wantDir bool
		wantLog string
		wantErr bool
	}{
		{
			name:   "disabled",
			dumpIR: false,
		},
		{
			name:    "enabled creates dir",
			dumpIR:  true,
			wantDir: true,
		},
		{
			name:    "enabled verbose logs path",
			dumpIR:  true,
			verbose: true,
			wantDir: true,
			wantLog: "[dump-ir]",
		},
		{
			name:    "bad workdir",
			dumpIR:  true,
			badDir:  true,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workDir := t.TempDir()
			if tt.badDir {
				workDir = testutil.BadPath()
			}
			var stdout bytes.Buffer
			cfg := Config{DumpIR: tt.dumpIR, Verbose: tt.verbose, Stdout: &stdout}
			dir, err := setupDumpIR(cfg, workDir)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if !diag.IsStage(err, diag.StageTransform) {
					t.Fatalf("expected stage transform, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.wantDir {
				if dir == "" {
					t.Fatal("expected non-empty dir")
				}
				info, statErr := os.Stat(dir)
				if statErr != nil {
					t.Fatalf("dump dir not created: %v", statErr)
				}
				if !info.IsDir() {
					t.Fatal("expected directory")
				}
			} else if dir != "" {
				t.Fatalf("expected empty dir, got %q", dir)
			}
			if tt.wantLog != "" && !strings.Contains(stdout.String(), tt.wantLog) {
				t.Errorf("expected %q in stdout, got %q", tt.wantLog, stdout.String())
			}
		})
	}
}

func TestValidateRequiredFields(t *testing.T) {
	tests := []struct {
		name      string
		cfg       Config
		wantStage diag.Stage
		wantErr   string
	}{
		{
			name:      "no inputs",
			cfg:       Config{Output: "out.o"},
			wantStage: diag.StageInput,
			wantErr:   "no inputs provided",
		},
		{
			name:      "empty output",
			cfg:       Config{Inputs: []string{"in.ll"}, Output: "   "},
			wantStage: diag.StageInput,
			wantErr:   "no output path provided",
		},
		{
			name:      "unsupported extension",
			cfg:       Config{Inputs: []string{"bad.txt"}, Output: "out.o"},
			wantStage: diag.StageInput,
			wantErr:   "unsupported input format",
		},
		{
			name: "valid config passes",
			cfg:  Config{Inputs: []string{"in.ll"}, Output: "out.o"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRequiredFields(&tt.cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error")
			}
			if !diag.IsStage(err, tt.wantStage) {
				t.Errorf("expected stage %v, got: %v", tt.wantStage, err)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected %q in error, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestApplyConfigDefaults(t *testing.T) {
	tests := []struct {
		name  string
		cfg   Config
		check func(t *testing.T, cfg *Config)
	}{
		{
			name: "CPU defaults to v3",
			cfg:  Config{},
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				if cfg.CPU != "v3" {
					t.Errorf("CPU = %q, want %q", cfg.CPU, "v3")
				}
			},
		},
		{
			name: "CPU preserved when set",
			cfg:  Config{CPU: "v4"},
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				if cfg.CPU != "v4" {
					t.Errorf("CPU = %q, want %q", cfg.CPU, "v4")
				}
			},
		},
		{
			name: "Timeout defaults to 30s",
			cfg:  Config{},
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				if cfg.Timeout != 30*time.Second {
					t.Errorf("Timeout = %v, want %v", cfg.Timeout, 30*time.Second)
				}
			},
		},
		{
			name: "Timeout preserved when set",
			cfg:  Config{Timeout: 10 * time.Second},
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				if cfg.Timeout != 10*time.Second {
					t.Errorf("Timeout = %v, want %v", cfg.Timeout, 10*time.Second)
				}
			},
		},
		{
			name: "Stdout defaults to non-nil",
			cfg:  Config{},
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				if cfg.Stdout == nil {
					t.Error("Stdout should not be nil after defaults")
				}
			},
		},
		{
			name: "Stderr defaults to non-nil",
			cfg:  Config{},
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				if cfg.Stderr == nil {
					t.Error("Stderr should not be nil after defaults")
				}
			},
		},
		{
			name: "ValidateELF defaults to non-nil",
			cfg:  Config{},
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				if cfg.ValidateELF == nil {
					t.Error("ValidateELF should not be nil after defaults")
				}
			},
		},
		{
			name: "ValidateELF preserved when set",
			cfg:  Config{ValidateELF: func(string) error { return nil }},
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				if cfg.ValidateELF == nil {
					t.Error("ValidateELF should be preserved")
				}
				if err := cfg.ValidateELF("any"); err != nil {
					t.Errorf("custom ValidateELF returned error: %v", err)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			applyConfigDefaults(&cfg)
			tt.check(t, &cfg)
		})
	}
}

func TestEnsureInputSupported(t *testing.T) {
	tests := []struct {
		ext     string
		wantErr bool
	}{
		{".ll", false},
		{".bc", false},
		{".o", false},
		{".a", false},
		{".txt", true},
		{".go", true},
		{".json", true},
		{"", true},
	}
	for _, tt := range tests {
		t.Run(tt.ext, func(t *testing.T) {
			err := ensureInputSupported("test" + tt.ext)
			if (err != nil) != tt.wantErr {
				t.Errorf("ensureInputSupported(%q): err=%v, wantErr=%v", "test"+tt.ext, err, tt.wantErr)
			}
		})
	}
}

func TestRunStage(t *testing.T) {
	tests := []struct {
		name      string
		script    string
		verbose   bool
		wantErr   bool
		wantStage diag.Stage
		check     func(t *testing.T, stdout string)
	}{
		{
			name:   "success",
			script: "echo done",
		},
		{
			name:    "verbose",
			script:  "echo out; echo err >&2",
			verbose: true,
			check: func(t *testing.T, stdout string) {
				t.Helper()
				if !strings.Contains(stdout, "llvm-link") {
					t.Errorf("expected stage name in verbose output, got: %q", stdout)
				}
			},
		},
		{
			name:      "failure",
			script:    "echo bad >&2; exit 1",
			wantErr:   true,
			wantStage: diag.StageLink,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bin := makeFakeTool(t, t.TempDir(), "test-tool", tt.script)
			var stdout, stderr bytes.Buffer
			cfg := Config{Timeout: 5 * time.Second, Verbose: tt.verbose, Stdout: &stdout, Stderr: &stderr}
			err := runStage(context.Background(), cfg, diag.StageLink, bin, nil, "hint")
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
				tt.check(t, stdout.String())
			}
		})
	}
}

func TestMakeWorkDir(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) (dir string, keepTemp bool)
		wantErr bool
		check   func(t *testing.T, dir string, cleanup func())
	}{
		{
			name:  "explicit dir",
			setup: func(t *testing.T) (string, bool) { t.Helper(); return filepath.Join(t.TempDir(), "explicit"), false },
			check: func(t *testing.T, dir string, cleanup func()) {
				t.Helper()
				defer cleanup()
				if !strings.HasSuffix(dir, "explicit") {
					t.Fatal("expected explicit dir name")
				}
			},
		},
		{
			name:  "explicit dir permissions",
			setup: func(t *testing.T) (string, bool) { t.Helper(); return filepath.Join(t.TempDir(), "workdir"), false },
			check: func(t *testing.T, dir string, cleanup func()) {
				t.Helper()
				defer cleanup()
				info, _ := os.Stat(dir)
				if perm := info.Mode().Perm(); perm != 0o700 {
					t.Fatalf("expected 0700, got %o", perm)
				}
			},
		},
		{
			name:  "temp dir cleanup",
			setup: func(t *testing.T) (string, bool) { t.Helper(); return "", false },
			check: func(t *testing.T, dir string, cleanup func()) {
				t.Helper()
				cleanup()
				if _, err := os.Stat(dir); err == nil {
					t.Fatal("temp dir should be removed after cleanup")
				}
			},
		},
		{
			name:  "temp dir keepTemp",
			setup: func(t *testing.T) (string, bool) { t.Helper(); return "", true },
			check: func(t *testing.T, dir string, cleanup func()) {
				t.Helper()
				defer os.RemoveAll(dir)
				cleanup()
				if _, err := os.Stat(dir); err != nil {
					t.Fatal("temp dir should be kept with keepTemp")
				}
			},
		},
		{
			name:    "bad path",
			setup:   func(t *testing.T) (string, bool) { t.Helper(); return testutil.BadPath(), false },
			wantErr: true,
		},
		{
			name: "bad TMPDIR",
			setup: func(t *testing.T) (string, bool) {
				t.Helper()
				t.Setenv("TMPDIR", testutil.BadPath("tmpdir"))
				return "", false
			},
			wantErr: true,
		},
		{
			name: "inside file",
			setup: func(t *testing.T) (string, bool) {
				t.Helper()
				tmp := t.TempDir()
				file := filepath.Join(tmp, "not-a-dir")
				os.WriteFile(file, []byte("x"), 0o644)
				return filepath.Join(file, "sub"), false
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dirArg, keepTemp := tt.setup(t)
			dir, cleanup, err := makeWorkDir(dirArg, keepTemp)
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
				tt.check(t, dir, cleanup)
			}
		})
	}
}

func TestStripHostPaths(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) (ll, workDir string)
		wantErr bool
		check   func(t *testing.T, ll, workDir string)
	}{
		{
			name: "replaces temp dir",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				tmp := t.TempDir()
				ll := filepath.Join(tmp, "test.ll")
				content := `source_filename = "` + tmp + `/input.ll"` + "\ndefine void @f() { ret void }\n"
				os.WriteFile(ll, []byte(content), 0o644)
				return ll, tmp
			},
			check: func(t *testing.T, ll, workDir string) {
				t.Helper()
				got, _ := os.ReadFile(ll)
				if strings.Contains(string(got), workDir) {
					t.Fatalf("temp dir not stripped: %s", got)
				}
				if !strings.Contains(string(got), "./input.ll") {
					t.Fatalf("expected relative path: %s", got)
				}
			},
		},
		{
			name: "missing file",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				return testutil.BadPath("input.ll"), "/tmp"
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ll, workDir := tt.setup(t)
			err := stripHostPaths(ll, workDir)
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
				tt.check(t, ll, workDir)
			}
		})
	}
}

func TestBuildLLCArgs(t *testing.T) {
	tests := []struct {
		name   string
		cpu    string
		input  string
		output string
		want   []string
	}{
		{
			name:   "v4",
			cpu:    "v4",
			input:  "in.ll",
			output: "out.o",
			want:   []string{"-march=bpf", "-mcpu=v4", "-filetype=obj", "in.ll", "-o", "out.o"},
		},
		{
			name:   "v3",
			cpu:    "v3",
			input:  "prog.ll",
			output: "prog.o",
			want:   []string{"-march=bpf", "-mcpu=v3", "-filetype=obj", "prog.ll", "-o", "prog.o"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildLLCArgs(tt.cpu, tt.input, tt.output)
			if len(got) != len(tt.want) {
				t.Fatalf("arg count: got=%d want=%d", len(got), len(tt.want))
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("args[%d]: got=%q want=%q", i, got[i], tt.want[i])
				}
			}
		})
	}
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
		{"duplicate key last wins", []string{"a=x", "a=y"}, map[string]string{"a": "y"}, ""},
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

func TestCopyFile(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) (src, dst string)
		wantErr bool
		check   func(t *testing.T, dst string)
	}{
		{
			name: "success",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				tmp := t.TempDir()
				src := filepath.Join(tmp, "src")
				os.WriteFile(src, []byte("hello"), 0o644)
				return src, filepath.Join(tmp, "dst")
			},
			check: func(t *testing.T, dst string) {
				t.Helper()
				got, _ := os.ReadFile(dst)
				if string(got) != "hello" {
					t.Fatalf("content mismatch: %q", got)
				}
			},
		},
		{
			name: "missing source",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				return testutil.BadPath("src"), filepath.Join(t.TempDir(), "dst")
			},
			wantErr: true,
		},
		{
			name: "destination write failure",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				tmp := t.TempDir()
				src := filepath.Join(tmp, "src")
				os.WriteFile(src, []byte("data"), 0o644)
				return src, filepath.Join(testutil.BadPath(), "dst")
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src, dst := tt.setup(t)
			err := copyFile(src, dst)
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
				tt.check(t, dst)
			}
		})
	}
}
