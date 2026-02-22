package llvm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// makeTool creates a fake shell script in dir and returns its path.
func makeTool(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// makeRequiredTools creates the three required tools and returns their paths.
func makeRequiredTools(t *testing.T, dir string) (link, opt, llc string) {
	t.Helper()
	return makeTool(t, dir, "llvm-link"), makeTool(t, dir, "opt"), makeTool(t, dir, "llc")
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
				return ToolOverrides{LLVMLink: "/does/not/exist/llvm-link"}
			},
			wantErr: true,
		},
		{
			name: "missing opt",
			overrides: func(t *testing.T) ToolOverrides {
				t.Helper()
				dir := t.TempDir()
				link := makeTool(t, dir, "llvm-link")
				return ToolOverrides{LLVMLink: link, Opt: "/does/not/exist/opt"}
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
				return ToolOverrides{LLVMLink: link, Opt: opt, LLC: "/does/not/exist/llc"}
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

func TestDiscoverToolsBadOptionalOverride(t *testing.T) {
	tests := []struct {
		name      string
		overrides func(link, opt, llc string) ToolOverrides
	}{
		{
			name: "bad llvm-ar",
			overrides: func(link, opt, llc string) ToolOverrides {
				return ToolOverrides{LLVMLink: link, Opt: opt, LLC: llc, LLVMAr: "/does/not/exist/llvm-ar"}
			},
		},
		{
			name: "bad llvm-objcopy",
			overrides: func(link, opt, llc string) ToolOverrides {
				return ToolOverrides{LLVMLink: link, Opt: opt, LLC: llc, Objcopy: "/does/not/exist/llvm-objcopy"}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			link, opt, llc := makeRequiredTools(t, dir)
			_, err := DiscoverTools(tt.overrides(link, opt, llc))
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestValidateBinary(t *testing.T) {
	rejected := []struct {
		name, path string
	}{
		{"shell semicolon", "/bin/sh;rm -rf /"},
		{"shell pipe", "/bin/opt|cat"},
		{"shell dollar", "/tmp/opt$HOME"},
		{"shell backtick", "/tmp/opt`id`"},
	}
	for _, tt := range rejected {
		t.Run("rejects/"+tt.name, func(t *testing.T) {
			if err := ValidateBinary(tt.path); err == nil {
				t.Fatalf("expected error for %q", tt.path)
			}
		})
	}

	accepted := []string{
		"/usr/bin/opt", "/usr/local/bin/llc",
		"/usr/bin/llvm-link-18", "/usr/bin/pahole",
		"/usr/bin/tinygo", "/usr/bin/ld.lld",
	}
	for _, p := range accepted {
		t.Run("accepts/"+filepath.Base(p), func(t *testing.T) {
			if err := ValidateBinary(p); err != nil {
				t.Fatalf("expected %q to be allowed: %v", p, err)
			}
		})
	}
}

func TestIsVersionSuffix(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"18", true},
		{"17.0.6", true},
		{"0", true},
		{"", false},
		{"18.", false},
		{".18", false},
		{"abc", false},
		{"18a", false},
		{"18.0.a", false},
	}
	for _, tt := range tests {
		if got := isVersionSuffix(tt.in); got != tt.want {
			t.Errorf("isVersionSuffix(%q) = %v, want %v", tt.in, got, tt.want)
		}
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
			setup:   func(t *testing.T) string { t.Helper(); return "/does/not/exist/tool" },
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
		name      string
		setup     func(t *testing.T) (override, name string)
		wantErr   bool
		errSubstr string
		check     func(t *testing.T, got string)
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
			var got string
			var err error
			if tt.name == "rejects disallowed name" {
				got, err = resolveOptional(override, name)
			} else {
				got, err = findOptional(override, name)
			}
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
		name      string
		timeout   time.Duration
		bin       string
		args      []string
		wantErr   bool
		errSubstr string
		check     func(t *testing.T, res Result)
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
			name: "timeout", timeout: 10 * time.Millisecond,
			bin: "/bin/sh", args: []string{"-c", "sleep 1"},
			wantErr: true, errSubstr: "timed out",
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

	wantNames := []string{"llvm-link", "opt", "llc", "llvm-ar", "llvm-objcopy", "pahole"}
	for i, want := range wantNames {
		if list[i].Name != want {
			t.Errorf("list[%d].Name = %q, want %q", i, list[i].Name, want)
		}
	}

	for _, nt := range list[:3] {
		if !nt.Required {
			t.Errorf("%s should be required", nt.Name)
		}
	}

	for _, nt := range list[3:] {
		if nt.Required {
			t.Errorf("%s should be optional", nt.Name)
		}
		if nt.Note == "" {
			t.Errorf("%s should have a note", nt.Name)
		}
	}

	if list[4].Path != "" {
		t.Errorf("expected empty path for llvm-objcopy, got %q", list[4].Path)
	}
}
