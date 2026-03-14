package doctor

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kyleseneker/tinybpf/internal/testutil"
	"github.com/kyleseneker/tinybpf/llvm"
)

func fakeToolOverrides(t *testing.T, script string) llvm.ToolOverrides {
	t.Helper()
	dir := t.TempDir()
	makeTool := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	return llvm.ToolOverrides{
		LLVMLink: makeTool("llvm-link"),
		Opt:      makeTool("opt"),
		LLC:      makeTool("llc"),
	}
}

func noExternalTools() pathLookup {
	return func(string) (string, error) { return "", os.ErrNotExist }
}

func fakeExternalTools(t *testing.T, tools map[string]string) pathLookup {
	t.Helper()
	dir := t.TempDir()
	paths := make(map[string]string, len(tools))
	for name, script := range tools {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte("#!/bin/sh\n"+script+"\n"), 0o755)
		paths[name] = p
	}
	return func(name string) (string, error) {
		if p, ok := paths[name]; ok {
			return p, nil
		}
		return "", os.ErrNotExist
	}
}

func TestNormalizeConfig(t *testing.T) {
	tests := []struct {
		name  string
		cfg   Config
		check func(t *testing.T, cfg Config)
	}{
		{
			name: "nil writers default to non-nil",
			cfg:  Config{},
			check: func(t *testing.T, cfg Config) {
				t.Helper()
				if cfg.Stdout == nil || cfg.Stderr == nil {
					t.Error("expected non-nil writers")
				}
			},
		},
		{
			name: "zero timeout defaults to 10s",
			cfg:  Config{},
			check: func(t *testing.T, cfg Config) {
				t.Helper()
				if cfg.Timeout != 10*time.Second {
					t.Errorf("Timeout = %v, want 10s", cfg.Timeout)
				}
			},
		},
		{
			name: "negative timeout defaults to 10s",
			cfg:  Config{Timeout: -1},
			check: func(t *testing.T, cfg Config) {
				t.Helper()
				if cfg.Timeout != 10*time.Second {
					t.Errorf("Timeout = %v, want 10s", cfg.Timeout)
				}
			},
		},
		{
			name: "explicit values preserved",
			cfg:  Config{Stdout: io.Discard, Stderr: io.Discard, Timeout: 30 * time.Second},
			check: func(t *testing.T, cfg Config) {
				t.Helper()
				if cfg.Timeout != 30*time.Second {
					t.Errorf("Timeout = %v, want 30s", cfg.Timeout)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			normalizeConfig(&cfg)
			tt.check(t, cfg)
		})
	}
}

func TestRunWith(t *testing.T) {
	tests := []struct {
		name        string
		tools       func(t *testing.T) llvm.ToolOverrides
		lookup      func(t *testing.T) pathLookup
		nilWriters  bool
		wantErr     bool
		wantStdout  []string
		wantStderr  []string
		notInStdout []string
	}{
		{
			name: "prints tool paths and versions",
			tools: func(t *testing.T) llvm.ToolOverrides {
				t.Helper()
				return fakeToolOverrides(t, "echo fake-tool 1.0.0")
			},
			wantStdout: []string{"tinybpf doctor", "llvm-link:", "[OK]", "fake-tool 1.0.0"},
		},
		{
			name: "reports missing optional tools",
			tools: func(t *testing.T) llvm.ToolOverrides {
				t.Helper()
				tools := fakeToolOverrides(t, "echo fake-tool 1.0.0")
				t.Setenv("PATH", t.TempDir())
				return tools
			},
			wantStdout: []string{"(not found"},
		},
		{
			name: "fails when required tool missing",
			tools: func(t *testing.T) llvm.ToolOverrides {
				t.Helper()
				return llvm.ToolOverrides{LLVMLink: testutil.BadPath("llvm-link")}
			},
			wantErr: true,
		},
		{
			name: "version check failure",
			tools: func(t *testing.T) llvm.ToolOverrides {
				t.Helper()
				return fakeToolOverrides(t, "exit 1")
			},
			wantStderr: []string{"[FAIL]"},
		},
		{
			name:       "nil writers and default timeout",
			nilWriters: true,
			tools: func(t *testing.T) llvm.ToolOverrides {
				t.Helper()
				return fakeToolOverrides(t, "echo ok")
			},
		},
		{
			name: "LLVM version on stderr",
			tools: func(t *testing.T) llvm.ToolOverrides {
				t.Helper()
				return fakeToolOverrides(t, "echo version-on-stderr >&2")
			},
			wantStdout: []string{"version-on-stderr"},
		},
		{
			name: "no LLVM version output",
			tools: func(t *testing.T) llvm.ToolOverrides {
				t.Helper()
				return fakeToolOverrides(t, "exit 0")
			},
			wantStdout: []string{"(no version output)"},
		},
		{
			name: "discovers optional tools",
			tools: func(t *testing.T) llvm.ToolOverrides {
				t.Helper()
				tools := fakeToolOverrides(t, "echo fake-tool 1.0.0")
				dir := filepath.Dir(tools.LLVMLink)
				for _, name := range []string{"llvm-ar", "llvm-objcopy"} {
					os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\necho fake-tool 1.0.0\n"), 0o755)
				}
				tools.LLVMAr = filepath.Join(dir, "llvm-ar")
				tools.Objcopy = filepath.Join(dir, "llvm-objcopy")
				return tools
			},
			wantStdout: []string{"llvm-ar:", "llvm-objcopy:"},
		},
		{
			name: "warns on old LLVM version",
			tools: func(t *testing.T) llvm.ToolOverrides {
				t.Helper()
				return fakeToolOverrides(t, "echo 'Ubuntu LLVM version 18.1.8'")
			},
			wantStdout: []string{"warnings:", "LLVM 18", "warning(s)"},
		},
		{
			name: "tinygo found",
			tools: func(t *testing.T) llvm.ToolOverrides {
				t.Helper()
				return fakeToolOverrides(t, "echo 'LLVM version 20.1.1'")
			},
			lookup: func(t *testing.T) pathLookup {
				t.Helper()
				return fakeExternalTools(t, map[string]string{
					"tinygo": "echo 'tinygo version 0.40.1'",
				})
			},
			wantStdout: []string{"tinygo:", "[OK]   tinygo:", "0.40.1"},
		},
		{
			name: "tinygo not found",
			tools: func(t *testing.T) llvm.ToolOverrides {
				t.Helper()
				return fakeToolOverrides(t, "echo 'LLVM version 20.1.1'")
			},
			wantStdout: []string{"tinygo:", "(not found)", "TinyGo is not installed"},
		},
		{
			name: "tinygo version check failure",
			tools: func(t *testing.T) llvm.ToolOverrides {
				t.Helper()
				return fakeToolOverrides(t, "echo 'LLVM version 20.1.1'")
			},
			lookup: func(t *testing.T) pathLookup {
				t.Helper()
				return fakeExternalTools(t, map[string]string{"tinygo": "exit 1"})
			},
			wantStderr: []string{"[FAIL] tinygo"},
		},
		{
			name: "tinygo version on stderr",
			tools: func(t *testing.T) llvm.ToolOverrides {
				t.Helper()
				return fakeToolOverrides(t, "echo 'LLVM version 20.1.1'")
			},
			lookup: func(t *testing.T) pathLookup {
				t.Helper()
				return fakeExternalTools(t, map[string]string{"tinygo": "echo 'tinygo version 0.40.1' >&2"})
			},
			wantStdout: []string{"0.40.1"},
		},
		{
			name: "tinygo no version output",
			tools: func(t *testing.T) llvm.ToolOverrides {
				t.Helper()
				return fakeToolOverrides(t, "echo 'LLVM version 20.1.1'")
			},
			lookup: func(t *testing.T) pathLookup {
				t.Helper()
				return fakeExternalTools(t, map[string]string{"tinygo": "exit 0"})
			},
			wantStdout: []string{"(no version output)"},
		},
		{
			name: "pahole found",
			tools: func(t *testing.T) llvm.ToolOverrides {
				t.Helper()
				return fakeToolOverrides(t, "echo 'LLVM version 20.1.1'")
			},
			lookup: func(t *testing.T) pathLookup {
				t.Helper()
				return fakeExternalTools(t, map[string]string{
					"tinygo": "echo 'tinygo version 0.40.1'",
					"pahole": "echo 'v1.27'",
				})
			},
			wantStdout: []string{"pahole:", "[OK]   pahole:", "v1.27"},
		},
		{
			name: "pahole not found warns",
			tools: func(t *testing.T) llvm.ToolOverrides {
				t.Helper()
				return fakeToolOverrides(t, "echo 'LLVM version 20.1.1'")
			},
			lookup: func(t *testing.T) pathLookup {
				t.Helper()
				return fakeExternalTools(t, map[string]string{
					"tinygo": "echo 'tinygo version 0.40.1'",
				})
			},
			wantStdout: []string{"pahole:", "(not found)", "dwarves"},
		},
		{
			name: "all checks passed",
			tools: func(t *testing.T) llvm.ToolOverrides {
				t.Helper()
				return fakeToolOverrides(t, "echo 'LLVM version 20.1.1'")
			},
			lookup: func(t *testing.T) pathLookup {
				t.Helper()
				return fakeExternalTools(t, map[string]string{
					"tinygo": "echo 'tinygo version 0.40.1'",
					"pahole": "echo 'v1.27'",
				})
			},
			wantStdout:  []string{"all checks passed"},
			notInStdout: []string{"warnings:"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lookup := noExternalTools()
			if tt.lookup != nil {
				lookup = tt.lookup(t)
			}

			var stdout, stderr bytes.Buffer
			cfg := Config{
				Tools:   tt.tools(t),
				Stdout:  &stdout,
				Stderr:  &stderr,
				Timeout: 5 * time.Second,
			}
			if tt.nilWriters {
				cfg.Stdout = nil
				cfg.Stderr = nil
				cfg.Timeout = 0
			}

			err := runWith(context.Background(), cfg, lookup)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for _, want := range tt.wantStdout {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("stdout missing %q, got:\n%s", want, stdout.String())
				}
			}
			for _, want := range tt.wantStderr {
				if !strings.Contains(stderr.String(), want) {
					t.Errorf("stderr missing %q, got:\n%s", want, stderr.String())
				}
			}
			for _, absent := range tt.notInStdout {
				if strings.Contains(stdout.String(), absent) {
					t.Errorf("stdout should not contain %q, got:\n%s", absent, stdout.String())
				}
			}
		})
	}
}

func TestRun(t *testing.T) {
	tools := fakeToolOverrides(t, "echo ok")
	err := Run(context.Background(), Config{
		Tools:   tools,
		Stdout:  io.Discard,
		Stderr:  io.Discard,
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPrintSummary(t *testing.T) {
	tests := []struct {
		name        string
		warnings    []string
		wantContain []string
		notContain  []string
	}{
		{
			name:        "no warnings",
			warnings:    nil,
			wantContain: []string{"all checks passed"},
			notContain:  []string{"warnings:"},
		},
		{
			name:        "one warning",
			warnings:    []string{"something is wrong"},
			wantContain: []string{"warnings:", "something is wrong", "1 warning(s); see above"},
			notContain:  []string{"all checks passed"},
		},
		{
			name:        "multiple warnings",
			warnings:    []string{"first issue", "second issue"},
			wantContain: []string{"warnings:", "first issue", "second issue", "2 warning(s); see above"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			printSummary(&buf, tt.warnings)
			out := buf.String()
			for _, want := range tt.wantContain {
				if !strings.Contains(out, want) {
					t.Errorf("output missing %q, got:\n%s", want, out)
				}
			}
			for _, absent := range tt.notContain {
				if strings.Contains(out, absent) {
					t.Errorf("output should not contain %q, got:\n%s", absent, out)
				}
			}
		})
	}
}

func TestLLVMVersionWarning(t *testing.T) {
	tests := []struct {
		name      string
		major     int
		wantEmpty bool
		wantSub   string
	}{
		{"zero is no warning", 0, true, ""},
		{"current version is no warning", 20, true, ""},
		{"future version is no warning", 25, true, ""},
		{"old version warns", 18, false, "LLVM 18"},
		{"old version mentions minimum", 19, false, "LLVM 20+"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := llvmVersionWarning(tt.major)
			if tt.wantEmpty && got != "" {
				t.Fatalf("expected empty warning, got %q", got)
			}
			if !tt.wantEmpty && got == "" {
				t.Fatal("expected non-empty warning")
			}
			if tt.wantSub != "" && !strings.Contains(got, tt.wantSub) {
				t.Fatalf("warning missing %q, got %q", tt.wantSub, got)
			}
		})
	}
}

func TestParseLLVMMajor(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantMajor int
		wantOK    bool
	}{
		{"Ubuntu prefix", "Ubuntu LLVM version 20.1.1", 20, true},
		{"plain version", "LLVM version 18.1.8", 18, true},
		{"future version", "LLVM version 21.0.0", 21, true},
		{"major only", "LLVM version 20", 20, true},
		{"unrelated tool", "fake-tool 1.0.0", 0, false},
		{"empty string", "", 0, false},
		{"no digits after prefix", "LLVM version ", 0, false},
		{"non-numeric version", "LLVM version abc", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			major, ok := parseLLVMMajor(tt.input)
			if major != tt.wantMajor || ok != tt.wantOK {
				t.Fatalf("parseLLVMMajor(%q) = (%d, %v), want (%d, %v)",
					tt.input, major, ok, tt.wantMajor, tt.wantOK)
			}
		})
	}
}

func TestFirstNonEmptyLine(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", ""},
		{"only newlines", "\n\n", ""},
		{"first line", "hello\nworld", "hello"},
		{"leading whitespace", "\n  first  \nsecond", "first"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := firstNonEmptyLine(tt.input); got != tt.want {
				t.Errorf("firstNonEmptyLine(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
