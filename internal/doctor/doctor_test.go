package doctor

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kyleseneker/tinybpf/internal/llvm"
)

// fakeToolOverrides creates a temp directory with properly-named fake tool
// scripts (llvm-link, opt, llc) that each run the given shell body.
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

// stubLookPath replaces the package-level lookPath for the duration of a test
// and restores it on cleanup.
func stubLookPath(t *testing.T, fn func(string) (string, error)) {
	t.Helper()
	old := lookPath
	lookPath = fn
	t.Cleanup(func() { lookPath = old })
}

// noTinyGo stubs lookPath to report tinygo as absent.
func noTinyGo(t *testing.T) {
	t.Helper()
	stubLookPath(t, func(string) (string, error) { return "", os.ErrNotExist })
}

// fakeTinyGo creates a fake tinygo script and stubs lookPath to resolve it.
func fakeTinyGo(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "tinygo")
	os.WriteFile(p, []byte("#!/bin/sh\n"+script+"\n"), 0o755)
	stubLookPath(t, func(name string) (string, error) {
		if name == "tinygo" {
			return p, nil
		}
		return exec.LookPath(name)
	})
}

// fakeTools creates fake scripts for the named binaries and stubs lookPath to resolve them.
func fakeTools(t *testing.T, tools map[string]string) {
	t.Helper()
	dir := t.TempDir()
	paths := make(map[string]string, len(tools))
	for name, script := range tools {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte("#!/bin/sh\n"+script+"\n"), 0o755)
		paths[name] = p
	}
	stubLookPath(t, func(name string) (string, error) {
		if p, ok := paths[name]; ok {
			return p, nil
		}
		return exec.LookPath(name)
	})
}

func TestRun(t *testing.T) {
	tests := []struct {
		name        string
		tools       func(t *testing.T) llvm.ToolOverrides
		setup       func(t *testing.T) // optional pre-run setup (lookPath stubs, etc.)
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
				return llvm.ToolOverrides{LLVMLink: "/does/not/exist/llvm-link"}
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
			setup:      noTinyGo,
			wantStdout: []string{"warnings:", "LLVM 18", "warning(s)"},
		},
		{
			name: "tinygo found",
			tools: func(t *testing.T) llvm.ToolOverrides {
				t.Helper()
				return fakeToolOverrides(t, "echo 'LLVM version 20.1.1'")
			},
			setup:      func(t *testing.T) { t.Helper(); fakeTinyGo(t, "echo 'tinygo version 0.40.1'") },
			wantStdout: []string{"tinygo:", "[OK]   tinygo:", "0.40.1"},
		},
		{
			name: "tinygo not found",
			tools: func(t *testing.T) llvm.ToolOverrides {
				t.Helper()
				return fakeToolOverrides(t, "echo 'LLVM version 20.1.1'")
			},
			setup:      noTinyGo,
			wantStdout: []string{"tinygo:", "(not found)", "TinyGo is not installed"},
		},
		{
			name: "tinygo version check failure",
			tools: func(t *testing.T) llvm.ToolOverrides {
				t.Helper()
				return fakeToolOverrides(t, "echo 'LLVM version 20.1.1'")
			},
			setup:      func(t *testing.T) { t.Helper(); fakeTinyGo(t, "exit 1") },
			wantStderr: []string{"[FAIL] tinygo"},
		},
		{
			name: "tinygo version on stderr",
			tools: func(t *testing.T) llvm.ToolOverrides {
				t.Helper()
				return fakeToolOverrides(t, "echo 'LLVM version 20.1.1'")
			},
			setup:      func(t *testing.T) { t.Helper(); fakeTinyGo(t, "echo 'tinygo version 0.40.1' >&2") },
			wantStdout: []string{"0.40.1"},
		},
		{
			name: "tinygo no version output",
			tools: func(t *testing.T) llvm.ToolOverrides {
				t.Helper()
				return fakeToolOverrides(t, "echo 'LLVM version 20.1.1'")
			},
			setup:      func(t *testing.T) { t.Helper(); fakeTinyGo(t, "exit 0") },
			wantStdout: []string{"(no version output)"},
		},
		{
			name: "pahole found",
			tools: func(t *testing.T) llvm.ToolOverrides {
				t.Helper()
				return fakeToolOverrides(t, "echo 'LLVM version 20.1.1'")
			},
			setup: func(t *testing.T) {
				t.Helper()
				fakeTools(t, map[string]string{
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
			setup:      func(t *testing.T) { t.Helper(); fakeTinyGo(t, "echo 'tinygo version 0.40.1'") },
			wantStdout: []string{"pahole:", "(not found)", "dwarves"},
		},
		{
			name: "all checks passed",
			tools: func(t *testing.T) llvm.ToolOverrides {
				t.Helper()
				return fakeToolOverrides(t, "echo 'LLVM version 20.1.1'")
			},
			setup: func(t *testing.T) {
				t.Helper()
				fakeTools(t, map[string]string{
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
			if tt.setup != nil {
				tt.setup(t)
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

			err := Run(context.Background(), cfg)
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

func TestFirstNonEmptyLine(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"", ""},
		{"\n\n", ""},
		{"hello\nworld", "hello"},
		{"\n  first  \nsecond", "first"},
	}
	for _, tt := range tests {
		if got := firstNonEmptyLine(tt.input); got != tt.want {
			t.Errorf("firstNonEmptyLine(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseLLVMMajor(t *testing.T) {
	tests := []struct {
		input     string
		wantMajor int
		wantOK    bool
	}{
		{"Ubuntu LLVM version 20.1.1", 20, true},
		{"LLVM version 18.1.8", 18, true},
		{"LLVM version 21.0.0", 21, true},
		{"LLVM version 20", 20, true},
		{"fake-tool 1.0.0", 0, false},
		{"", 0, false},
		{"LLVM version ", 0, false},
		{"LLVM version abc", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			major, ok := parseLLVMMajor(tt.input)
			if major != tt.wantMajor || ok != tt.wantOK {
				t.Fatalf("parseLLVMMajor(%q) = (%d, %v), want (%d, %v)",
					tt.input, major, ok, tt.wantMajor, tt.wantOK)
			}
		})
	}
}
