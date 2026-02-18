package doctor

import (
	"bytes"
	"context"
	"os"
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

func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		script     string
		tools      func(t *testing.T) llvm.ToolOverrides
		nilWriters bool // if true, set Stdout/Stderr to nil and Timeout to 0
		wantErr    bool
		wantStdout []string
		wantStderr []string
	}{
		{
			name:   "prints tool paths and versions",
			script: "echo fake-tool 1.0.0",
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
			name: "version on stderr",
			tools: func(t *testing.T) llvm.ToolOverrides {
				t.Helper()
				return fakeToolOverrides(t, "echo version-on-stderr >&2")
			},
			wantStdout: []string{"version-on-stderr"},
		},
		{
			name: "no version output",
			tools: func(t *testing.T) llvm.ToolOverrides {
				t.Helper()
				return fakeToolOverrides(t, "exit 0")
			},
			wantStdout: []string{"(no version output)"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
		})
	}
}

func TestRunWithOptionalToolsDiscovered(t *testing.T) {
	tools := fakeToolOverrides(t, "echo fake-tool 1.0.0")
	dir := filepath.Dir(tools.LLVMLink)
	for _, name := range []string{"llvm-ar", "llvm-objcopy"} {
		os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\necho fake-tool 1.0.0\n"), 0o755)
	}
	tools.LLVMAr = filepath.Join(dir, "llvm-ar")
	tools.Objcopy = filepath.Join(dir, "llvm-objcopy")

	var stdout bytes.Buffer
	err := Run(context.Background(), Config{
		Tools:   tools,
		Stdout:  &stdout,
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"llvm-ar:", "llvm-objcopy:"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("missing %q in output", want)
		}
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
