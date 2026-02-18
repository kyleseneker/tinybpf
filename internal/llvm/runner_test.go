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
	t.Run("all overrides", func(t *testing.T) {
		dir := t.TempDir()
		link, opt, llc := makeRequiredTools(t, dir)

		tools, err := DiscoverTools(ToolOverrides{LLVMLink: link, Opt: opt, LLC: llc})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tools.LLVMLink != link || tools.Opt != opt || tools.LLC != llc {
			t.Fatalf("paths mismatch: %+v", tools)
		}
	})

	t.Run("with optional tools", func(t *testing.T) {
		dir := t.TempDir()
		link, opt, llc := makeRequiredTools(t, dir)
		ar := makeTool(t, dir, "llvm-ar")
		objcopy := makeTool(t, dir, "llvm-objcopy")

		tools, err := DiscoverTools(ToolOverrides{
			LLVMLink: link, Opt: opt, LLC: llc,
			LLVMAr: ar, Objcopy: objcopy,
		})
		if err != nil {
			t.Fatal(err)
		}
		if tools.LLVMAr != ar || tools.Objcopy != objcopy {
			t.Fatalf("optional tools not resolved: %+v", tools)
		}
	})

	t.Run("version-suffixed tools", func(t *testing.T) {
		dir := t.TempDir()
		link := makeTool(t, dir, "llvm-link-18")
		opt := makeTool(t, dir, "opt-18")
		llc := makeTool(t, dir, "llc-18")

		tools, err := DiscoverTools(ToolOverrides{LLVMLink: link, Opt: opt, LLC: llc})
		if err != nil {
			t.Fatalf("version-suffixed tools should be accepted: %v", err)
		}
		if tools.LLVMLink != link {
			t.Fatalf("unexpected path: %s", tools.LLVMLink)
		}
	})

	t.Run("rejects disallowed binary", func(t *testing.T) {
		bad := makeTool(t, t.TempDir(), "not-allowed")
		_, err := DiscoverTools(ToolOverrides{LLVMLink: bad})
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "allowed tool set") {
			t.Fatalf("expected allowlist error, got: %v", err)
		}
	})
}

func TestDiscoverToolsMissingRequired(t *testing.T) {
	t.Run("missing llvm-link", func(t *testing.T) {
		_, err := DiscoverTools(ToolOverrides{LLVMLink: "/does/not/exist/llvm-link"})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("missing opt", func(t *testing.T) {
		dir := t.TempDir()
		link := makeTool(t, dir, "llvm-link")
		_, err := DiscoverTools(ToolOverrides{LLVMLink: link, Opt: "/does/not/exist/opt"})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("missing llc", func(t *testing.T) {
		dir := t.TempDir()
		link := makeTool(t, dir, "llvm-link")
		opt := makeTool(t, dir, "opt")
		_, err := DiscoverTools(ToolOverrides{LLVMLink: link, Opt: opt, LLC: "/does/not/exist/llc"})
		if err == nil {
			t.Fatal("expected error")
		}
	})
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

func TestResolveOptionalRejectsDisallowedName(t *testing.T) {
	bad := makeTool(t, t.TempDir(), "not-allowed")
	_, err := resolveOptional(bad, "llvm-ar")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "allowed tool set") {
		t.Fatalf("expected allowlist error, got: %v", err)
	}
}

func TestFindRequired(t *testing.T) {
	t.Run("absolute path", func(t *testing.T) {
		exe := makeTool(t, t.TempDir(), "tool")
		got, err := findRequired(exe)
		if err != nil {
			t.Fatal(err)
		}
		if got != exe {
			t.Fatalf("expected %s, got %s", exe, got)
		}
	})

	t.Run("absolute not executable", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "tool")
		os.WriteFile(p, []byte("data"), 0o644)
		if _, err := findRequired(p); err == nil {
			t.Fatal("expected error for non-executable")
		}
	})

	t.Run("absolute missing", func(t *testing.T) {
		if _, err := findRequired("/does/not/exist/tool"); err == nil {
			t.Fatal("expected error for missing file")
		}
	})

	t.Run("PATH lookup", func(t *testing.T) {
		dir := t.TempDir()
		exe := filepath.Join(dir, "my-test-tool")
		os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755)
		t.Setenv("PATH", dir)

		got, err := findRequired("my-test-tool")
		if err != nil {
			t.Fatal(err)
		}
		if got != exe {
			t.Fatalf("expected %s, got %s", exe, got)
		}
	})

	t.Run("PATH missing", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		if _, err := findRequired("nonexistent-tool-xyz"); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestFindOptional(t *testing.T) {
	t.Run("empty not on PATH", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		got, err := findOptional("", "no-such-tool-xyz")
		if err != nil {
			t.Fatal(err)
		}
		if got != "" {
			t.Fatalf("expected empty, got %q", got)
		}
	})

	t.Run("found on PATH", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "my-tool"), []byte("#!/bin/sh\n"), 0o755)
		t.Setenv("PATH", dir)

		got, err := findOptional("", "my-tool")
		if err != nil {
			t.Fatal(err)
		}
		if got == "" {
			t.Fatal("expected tool to be found on PATH")
		}
	})

	t.Run("explicit override", func(t *testing.T) {
		exe := makeTool(t, t.TempDir(), "tool")
		got, err := findOptional(exe, "default")
		if err != nil {
			t.Fatal(err)
		}
		if got != exe {
			t.Fatalf("expected %s, got %s", exe, got)
		}
	})
}

func TestRun(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		res, err := Run(context.Background(), 5*time.Second, "/bin/echo", "hello")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(res.Stdout, "hello") {
			t.Fatalf("expected stdout to contain hello, got: %q", res.Stdout)
		}
		if !strings.Contains(res.Command, "echo") {
			t.Fatalf("expected command to contain echo, got: %q", res.Command)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		_, err := Run(context.Background(), 10*time.Millisecond, "/bin/sh", "-c", "sleep 1")
		if err == nil {
			t.Fatal("expected timeout error")
		}
		if !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("expected timeout message, got: %v", err)
		}
	})

	t.Run("failure", func(t *testing.T) {
		res, err := Run(context.Background(), 5*time.Second, "/bin/sh", "-c", "echo err >&2; exit 42")
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(res.Stderr, "err") {
			t.Fatalf("expected stderr, got: %q", res.Stderr)
		}
	})

	t.Run("default timeout", func(t *testing.T) {
		res, err := Run(context.Background(), 0, "/bin/echo", "ok")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(res.Stdout, "ok") {
			t.Fatalf("unexpected stdout: %q", res.Stdout)
		}
	})
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
	got := formatCommand("llc", []string{"-march=bpf", "input file.ll"})
	if !strings.Contains(got, "llc") {
		t.Fatalf("expected llc in command, got: %q", got)
	}
	if !strings.Contains(got, "'input file.ll'") {
		t.Fatalf("expected quoted path, got: %q", got)
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
