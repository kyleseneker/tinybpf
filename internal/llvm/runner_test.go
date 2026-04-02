package llvm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kyleseneker/tinybpf/internal/testutil"
)

func makeTool(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func makeRequiredTools(t *testing.T, dir string) (link, opt, llc string) {
	t.Helper()
	return makeTool(t, dir, "llvm-link"), makeTool(t, dir, "opt"), makeTool(t, dir, "llc")
}

func TestValidateBinary(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"allowed opt", "/usr/bin/opt", false},
		{"allowed llc", "/usr/local/bin/llc", false},
		{"allowed llvm-link-18", "/usr/bin/llvm-link-18", false},
		{"allowed pahole", "/usr/bin/pahole", false},
		{"allowed tinygo", "/usr/bin/tinygo", false},
		{"allowed ld.lld", "/usr/bin/ld.lld", false},
		{"rejects shell semicolon", "/bin/sh;rm -rf /", true},
		{"rejects shell pipe", "/bin/opt|cat", true},
		{"rejects shell dollar", "/tmp/opt$HOME", true},
		{"rejects shell backtick", "/tmp/opt`id`", true},
		{"rejects disallowed binary", "/usr/bin/not-allowed", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBinary(tt.path)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error for %q", tt.path)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.path, err)
			}
		})
	}
}

func TestIsVersionSuffix(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"numeric", "18", true},
		{"dotted version", "17.0.6", true},
		{"zero", "0", true},
		{"empty", "", false},
		{"trailing dot", "18.", false},
		{"leading dot", ".18", false},
		{"alpha", "abc", false},
		{"mixed", "18a", false},
		{"dotted alpha", "18.0.a", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isVersionSuffix(tt.in); got != tt.want {
				t.Errorf("isVersionSuffix(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestSanitizedEnv(t *testing.T) {
	tests := []struct {
		name        string
		wantPresent []string
		wantAbsent  []string
	}{
		{
			name:        "includes required keys and excludes others",
			wantPresent: []string{"LC_ALL", "TZ"},
			wantAbsent:  []string{"GOPATH", "GOROOT", "USER", "SHELL"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := sanitizedEnv()
			hasKey := func(key string) bool {
				prefix := key + "="
				for _, e := range env {
					if strings.HasPrefix(e, prefix) {
						return true
					}
				}
				return false
			}

			for _, key := range tt.wantPresent {
				if !hasKey(key) {
					t.Errorf("expected %s in sanitized env", key)
				}
			}
			for _, key := range tt.wantAbsent {
				if hasKey(key) {
					t.Errorf("unexpected %s in sanitized env", key)
				}
			}
		})
	}
}

func TestToolsList(t *testing.T) {
	tools := Tools{
		LLVMLink: "/usr/bin/llvm-link",
		Opt:      "/usr/bin/opt",
		LLC:      "/usr/bin/llc",
		LLVMAr:   "/usr/bin/llvm-ar",
		Objcopy:  "",
		Pahole:   "/usr/bin/pahole",
	}

	list := tools.List()
	if len(list) != 6 {
		t.Fatalf("expected 6 tools, got %d", len(list))
	}

	expected := []struct {
		name     string
		required bool
	}{
		{"llvm-link", true},
		{"opt", true},
		{"llc", true},
		{"llvm-ar", false},
		{"llvm-objcopy", false},
		{"pahole", false},
	}
	for i, tt := range expected {
		t.Run(tt.name, func(t *testing.T) {
			if list[i].Name != tt.name {
				t.Errorf("Name = %q, want %q", list[i].Name, tt.name)
			}
			if list[i].Required != tt.required {
				t.Errorf("Required = %v, want %v", list[i].Required, tt.required)
			}
			if !tt.required && list[i].Note == "" {
				t.Error("optional tool should have a note")
			}
		})
	}

	if list[4].Path != "" {
		t.Errorf("expected empty path for llvm-objcopy, got %q", list[4].Path)
	}
}

func TestDiscoverTools(t *testing.T) {
	tests := []struct {
		name      string
		overrides func(t *testing.T) ToolOverrides
		wantErr   bool
		errSubstr string
		check     func(t *testing.T, tools Tools)
	}{
		{
			name: "all overrides",
			overrides: func(t *testing.T) ToolOverrides {
				t.Helper()
				dir := t.TempDir()
				link, opt, llc := makeRequiredTools(t, dir)
				return ToolOverrides{LLVMLink: link, Opt: opt, LLC: llc}
			},
			check: func(t *testing.T, tools Tools) {
				t.Helper()
				if tools.LLVMLink == "" || tools.Opt == "" || tools.LLC == "" {
					t.Fatalf("required paths empty: %+v", tools)
				}
			},
		},
		{
			name: "with optional tools",
			overrides: func(t *testing.T) ToolOverrides {
				t.Helper()
				dir := t.TempDir()
				link, opt, llc := makeRequiredTools(t, dir)
				ar := makeTool(t, dir, "llvm-ar")
				objcopy := makeTool(t, dir, "llvm-objcopy")
				return ToolOverrides{LLVMLink: link, Opt: opt, LLC: llc, LLVMAr: ar, Objcopy: objcopy}
			},
			check: func(t *testing.T, tools Tools) {
				t.Helper()
				if tools.LLVMAr == "" || tools.Objcopy == "" {
					t.Fatalf("optional tools not resolved: %+v", tools)
				}
			},
		},
		{
			name: "version-suffixed tools",
			overrides: func(t *testing.T) ToolOverrides {
				t.Helper()
				dir := t.TempDir()
				link := makeTool(t, dir, "llvm-link-18")
				opt := makeTool(t, dir, "opt-18")
				llc := makeTool(t, dir, "llc-18")
				return ToolOverrides{LLVMLink: link, Opt: opt, LLC: llc}
			},
		},
		{
			name: "rejects disallowed binary",
			overrides: func(t *testing.T) ToolOverrides {
				t.Helper()
				bad := makeTool(t, t.TempDir(), "not-allowed")
				return ToolOverrides{LLVMLink: bad}
			},
			wantErr:   true,
			errSubstr: "allowed tool set",
		},
		{
			name: "missing llvm-link",
			overrides: func(t *testing.T) ToolOverrides {
				t.Helper()
				return ToolOverrides{LLVMLink: testutil.BadPath("llvm-link")}
			},
			wantErr: true,
		},
		{
			name: "missing opt",
			overrides: func(t *testing.T) ToolOverrides {
				t.Helper()
				dir := t.TempDir()
				link := makeTool(t, dir, "llvm-link")
				return ToolOverrides{LLVMLink: link, Opt: testutil.BadPath("opt")}
			},
			wantErr: true,
		},
		{
			name: "missing llc",
			overrides: func(t *testing.T) ToolOverrides {
				t.Helper()
				dir := t.TempDir()
				link := makeTool(t, dir, "llvm-link")
				opt := makeTool(t, dir, "opt")
				return ToolOverrides{LLVMLink: link, Opt: opt, LLC: testutil.BadPath("llc")}
			},
			wantErr: true,
		},
		{
			name: "bad llvm-ar override",
			overrides: func(t *testing.T) ToolOverrides {
				t.Helper()
				dir := t.TempDir()
				link, opt, llc := makeRequiredTools(t, dir)
				return ToolOverrides{LLVMLink: link, Opt: opt, LLC: llc, LLVMAr: testutil.BadPath("llvm-ar")}
			},
			wantErr: true,
		},
		{
			name: "bad llvm-objcopy override",
			overrides: func(t *testing.T) ToolOverrides {
				t.Helper()
				dir := t.TempDir()
				link, opt, llc := makeRequiredTools(t, dir)
				return ToolOverrides{LLVMLink: link, Opt: opt, LLC: llc, Objcopy: testutil.BadPath("llvm-objcopy")}
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			overrides := tt.overrides(t)
			tools, err := DiscoverTools(overrides)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected %q in error, got: %v", tt.errSubstr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, tools)
			}
		})
	}
}

func TestResolveOptional(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T) (override, name string)
		wantErr   bool
		errSubstr string
		check     func(t *testing.T, got string)
	}{
		{
			name: "valid override passes validation",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				return makeTool(t, t.TempDir(), "llvm-ar"), "llvm-ar"
			},
			check: func(t *testing.T, got string) {
				t.Helper()
				if got == "" {
					t.Fatal("expected non-empty path")
				}
			},
		},
		{
			name: "rejects disallowed name",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				bad := makeTool(t, t.TempDir(), "not-allowed")
				return bad, "llvm-ar"
			},
			wantErr:   true,
			errSubstr: "allowed tool set",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			override, name := tt.setup(t)
			got, err := resolveOptional(override, name)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected %q in error, got: %v", tt.errSubstr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.check != nil {
				tt.check(t, got)
			}
		})
	}
}

func TestRun(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		bin     string
		args    []string
		wantErr bool
		check   func(t *testing.T, res Result)
	}{
		{
			name: "success", timeout: 5 * time.Second,
			bin: "/bin/echo", args: []string{"hello"},
			check: func(t *testing.T, res Result) {
				t.Helper()
				if !strings.Contains(res.Stdout, "hello") {
					t.Fatalf("expected hello in stdout, got: %q", res.Stdout)
				}
				if !strings.Contains(res.Command, "echo") {
					t.Fatalf("expected echo in command, got: %q", res.Command)
				}
			},
		},
		{
			name: "failure", timeout: 5 * time.Second,
			bin: "/bin/sh", args: []string{"-c", "echo err >&2; exit 42"},
			wantErr: true,
			check: func(t *testing.T, res Result) {
				t.Helper()
				if !strings.Contains(res.Stderr, "err") {
					t.Fatalf("expected stderr, got: %q", res.Stderr)
				}
			},
		},
		{
			name: "default timeout", timeout: 0,
			bin: "/bin/echo", args: []string{"ok"},
			check: func(t *testing.T, res Result) {
				t.Helper()
				if !strings.Contains(res.Stdout, "ok") {
					t.Fatalf("unexpected stdout: %q", res.Stdout)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := Run(context.Background(), tt.timeout, tt.bin, tt.args...)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if tt.check != nil {
				tt.check(t, res)
			}
		})
	}
}

func TestRunWith(t *testing.T) {
	tests := []struct {
		name      string
		timeout   time.Duration
		run       commandRunner
		wantErr   bool
		errSubstr string
		check     func(t *testing.T, res Result)
	}{
		{
			name:    "success",
			timeout: 5 * time.Second,
			run: func(_ context.Context, _ string, _, _ []string) ([]byte, []byte, error) {
				return []byte("hello\n"), nil, nil
			},
			check: func(t *testing.T, res Result) {
				t.Helper()
				if !strings.Contains(res.Stdout, "hello") {
					t.Fatalf("expected hello in stdout, got: %q", res.Stdout)
				}
			},
		},
		{
			name:    "failure captures stderr",
			timeout: 5 * time.Second,
			run: func(_ context.Context, _ string, _, _ []string) ([]byte, []byte, error) {
				return nil, []byte("err output"), fmt.Errorf("exit status 1")
			},
			wantErr: true,
			check: func(t *testing.T, res Result) {
				t.Helper()
				if !strings.Contains(res.Stderr, "err output") {
					t.Fatalf("expected stderr, got: %q", res.Stderr)
				}
			},
		},
		{
			name:    "timeout detection",
			timeout: 10 * time.Millisecond,
			run: func(ctx context.Context, _ string, _, _ []string) ([]byte, []byte, error) {
				<-ctx.Done()
				return nil, nil, ctx.Err()
			},
			wantErr:   true,
			errSubstr: "timed out",
		},
		{
			name:    "default timeout applied",
			timeout: 0,
			run: func(_ context.Context, _ string, _, _ []string) ([]byte, []byte, error) {
				return []byte("ok"), nil, nil
			},
			check: func(t *testing.T, res Result) {
				t.Helper()
				if !strings.Contains(res.Stdout, "ok") {
					t.Fatalf("unexpected stdout: %q", res.Stdout)
				}
			},
		},
		{
			name:    "command string recorded",
			timeout: 1 * time.Second,
			run: func(_ context.Context, _ string, _, _ []string) ([]byte, []byte, error) {
				return nil, nil, nil
			},
			check: func(t *testing.T, res Result) {
				t.Helper()
				if !strings.Contains(res.Command, "echo") {
					t.Fatalf("expected echo in command, got: %q", res.Command)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := runWith(context.Background(), tt.timeout, "/usr/bin/echo", []string{"test"}, tt.run)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected %q in error, got: %v", tt.errSubstr, err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if tt.check != nil {
				tt.check(t, res)
			}
		})
	}
}

func TestFindRequired(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) string
		wantErr bool
		check   func(t *testing.T, got string)
	}{
		{
			name:  "absolute path",
			setup: func(t *testing.T) string { t.Helper(); return makeTool(t, t.TempDir(), "tool") },
			check: func(t *testing.T, got string) {
				t.Helper()
				if got == "" {
					t.Fatal("expected non-empty path")
				}
			},
		},
		{
			name: "absolute not executable",
			setup: func(t *testing.T) string {
				t.Helper()
				p := filepath.Join(t.TempDir(), "tool")
				os.WriteFile(p, []byte("data"), 0o644)
				return p
			},
			wantErr: true,
		},
		{
			name:    "absolute missing",
			setup:   func(t *testing.T) string { t.Helper(); return testutil.BadPath("tool") },
			wantErr: true,
		},
		{
			name: "PATH lookup",
			setup: func(t *testing.T) string {
				t.Helper()
				dir := t.TempDir()
				exe := filepath.Join(dir, "my-test-tool")
				os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755)
				t.Setenv("PATH", dir)
				return "my-test-tool"
			},
		},
		{
			name: "PATH missing",
			setup: func(t *testing.T) string {
				t.Helper()
				t.Setenv("PATH", t.TempDir())
				return "nonexistent-tool-xyz"
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			arg := tt.setup(t)
			got, err := findRequired(arg)
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
				tt.check(t, got)
			}
		})
	}
}

func TestFindOptional(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) (override, name string)
		wantErr bool
		check   func(t *testing.T, got string)
	}{
		{
			name: "empty not on PATH",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				t.Setenv("PATH", t.TempDir())
				return "", "no-such-tool-xyz"
			},
			check: func(t *testing.T, got string) {
				t.Helper()
				if got != "" {
					t.Fatalf("expected empty, got %q", got)
				}
			},
		},
		{
			name: "found on PATH",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				dir := t.TempDir()
				os.WriteFile(filepath.Join(dir, "my-tool"), []byte("#!/bin/sh\n"), 0o755)
				t.Setenv("PATH", dir)
				return "", "my-tool"
			},
			check: func(t *testing.T, got string) {
				t.Helper()
				if got == "" {
					t.Fatal("expected tool to be found on PATH")
				}
			},
		},
		{
			name: "explicit override",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				exe := makeTool(t, t.TempDir(), "tool")
				return exe, "default"
			},
			check: func(t *testing.T, got string) {
				t.Helper()
				if got == "" {
					t.Fatal("expected non-empty path")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			override, name := tt.setup(t)
			got, err := findOptional(override, name)
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
				tt.check(t, got)
			}
		})
	}
}

func TestFirstNonEmpty(t *testing.T) {
	tests := []struct {
		val, fallback, want string
	}{
		{"val", "fallback", "val"},
		{"", "fallback", "fallback"},
		{"  ", "fallback", "fallback"},
	}
	for _, tt := range tests {
		if got := firstNonEmpty(tt.val, tt.fallback); got != tt.want {
			t.Errorf("firstNonEmpty(%q, %q) = %q, want %q", tt.val, tt.fallback, got, tt.want)
		}
	}
}

func TestFormatCommand(t *testing.T) {
	tests := []struct {
		name        string
		bin         string
		args        []string
		wantContain []string
	}{
		{
			name:        "quoted path",
			bin:         "llc",
			args:        []string{"-march=bpf", "input file.ll"},
			wantContain: []string{"llc", "'input file.ll'"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatCommand(tt.bin, tt.args)
			for _, want := range tt.wantContain {
				if !strings.Contains(got, want) {
					t.Fatalf("expected %q in %q", want, got)
				}
			}
		})
	}
}

func TestShellQuote(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", "''"},
		{"simple", "simple"},
		{"has space", "'has space'"},
	}
	for _, tt := range tests {
		got := shellQuote(tt.in)
		if got != tt.want {
			t.Errorf("shellQuote(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
