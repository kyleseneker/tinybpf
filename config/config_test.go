package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kyleseneker/tinybpf/llvm"
)

func checkFullConfig(t *testing.T, cfg *Config) {
	t.Helper()
	if cfg.Build.Output != "build/probe.bpf.o" {
		t.Errorf("output = %q, want %q", cfg.Build.Output, "build/probe.bpf.o")
	}
	if cfg.Build.CPU != "v2" {
		t.Errorf("cpu = %q, want %q", cfg.Build.CPU, "v2")
	}
	if cfg.Build.OptProfile != "aggressive" {
		t.Errorf("opt_profile = %q, want %q", cfg.Build.OptProfile, "aggressive")
	}
	if cfg.Build.BTF == nil || !*cfg.Build.BTF {
		t.Error("btf should be true")
	}
	if cfg.Build.Timeout != "60s" {
		t.Errorf("timeout = %q, want %q", cfg.Build.Timeout, "60s")
	}
	if len(cfg.Build.Programs) != 1 {
		t.Fatalf("programs len = %d, want 1", len(cfg.Build.Programs))
	}
	if cfg.Build.Programs["probe_connect"] != "kprobe/sys_connect" {
		t.Errorf("programs[probe_connect] = %q", cfg.Build.Programs["probe_connect"])
	}
	if len(cfg.Build.CustomPasses) != 2 {
		t.Fatalf("custom_passes len = %d, want 2", len(cfg.Build.CustomPasses))
	}
	if cfg.Toolchain.LLVMDir != "/usr/lib/llvm-20/bin" {
		t.Errorf("llvm_dir = %q", cfg.Toolchain.LLVMDir)
	}
	if cfg.Toolchain.TinyGo != "/opt/tinygo/bin/tinygo" {
		t.Errorf("tinygo = %q", cfg.Toolchain.TinyGo)
	}
}

func checkAllRemainingOverrides(t *testing.T, m *Config) {
	t.Helper()
	if m.Build.Timeout != "90s" {
		t.Errorf("timeout = %q, want 90s", m.Build.Timeout)
	}
	if m.Build.Programs["p2"] != "xdp" {
		t.Errorf("programs[p2] = %q, want xdp", m.Build.Programs["p2"])
	}
	if len(m.Build.CustomPasses) != 1 || m.Build.CustomPasses[0] != "dce" {
		t.Errorf("custom_passes = %v, want [dce]", m.Build.CustomPasses)
	}
	if m.Toolchain.LLVMDir != "/new/llvm" {
		t.Errorf("llvm_dir = %q", m.Toolchain.LLVMDir)
	}
	if m.Toolchain.LLVMLink != "/new/llvm-link" {
		t.Errorf("llvm_link = %q", m.Toolchain.LLVMLink)
	}
	if m.Toolchain.Opt != "/new/opt" {
		t.Errorf("opt = %q", m.Toolchain.Opt)
	}
	if m.Toolchain.LLVMAr != "/new/llvm-ar" {
		t.Errorf("llvm_ar = %q", m.Toolchain.LLVMAr)
	}
	if m.Toolchain.LLVMObjcopy != "/new/llvm-objcopy" {
		t.Errorf("llvm_objcopy = %q", m.Toolchain.LLVMObjcopy)
	}
	if m.Toolchain.Pahole != "/new/pahole" {
		t.Errorf("pahole = %q", m.Toolchain.Pahole)
	}
	if m.Toolchain.TinyGo != "/new/tinygo" {
		t.Errorf("tinygo = %q", m.Toolchain.TinyGo)
	}
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		noFile  bool
		wantErr bool
		check   func(t *testing.T, cfg *Config)
	}{
		{
			name: "full config",
			json: `{
				"build": {
					"output": "build/probe.bpf.o",
					"cpu": "v2",
					"opt_profile": "aggressive",
					"btf": true,
					"timeout": "60s",
					"programs": {"probe_connect": "kprobe/sys_connect"},
					"custom_passes": ["inline", "dce"]
				},
				"toolchain": {
					"llvm_dir": "/usr/lib/llvm-20/bin",
					"tinygo": "/opt/tinygo/bin/tinygo"
				}
			}`,
			check: checkFullConfig,
		},
		{
			name: "empty object",
			json: `{}`,
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				if cfg.Build.Output != "" {
					t.Errorf("output should be empty, got %q", cfg.Build.Output)
				}
				if cfg.Build.BTF != nil {
					t.Error("btf should be nil")
				}
			},
		},
		{
			name: "btf explicitly false",
			json: `{"build": {"btf": false}}`,
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				if cfg.Build.BTF == nil {
					t.Fatal("btf should not be nil")
				}
				if *cfg.Build.BTF {
					t.Error("btf should be false")
				}
			},
		},
		{
			name:    "invalid json",
			json:    `{not json}`,
			wantErr: true,
		},
		{
			name:    "invalid custom pass",
			json:    `{"build": {"custom_passes": ["inline;rm -rf /"]}}`,
			wantErr: true,
		},
		{
			name:    "invalid timeout",
			json:    `{"build": {"timeout": "not-a-duration"}}`,
			wantErr: true,
		},
		{
			name:    "negative timeout",
			json:    `{"build": {"timeout": "-5s"}}`,
			wantErr: true,
		},
		{
			name:    "missing file",
			noFile:  true,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var path string
			if tt.noFile {
				path = filepath.Join(t.TempDir(), "nonexistent", Filename)
			} else {
				path = filepath.Join(t.TempDir(), Filename)
				if err := os.WriteFile(path, []byte(tt.json), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cfg, err := Load(path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, cfg)
			}
		})
	}
}

func TestFind(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T) string
		wantPath bool
	}{
		{
			name: "found in start dir",
			setup: func(t *testing.T) string {
				t.Helper()
				dir := t.TempDir()
				if err := os.WriteFile(filepath.Join(dir, Filename), []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
				return dir
			},
			wantPath: true,
		},
		{
			name: "found in parent dir",
			setup: func(t *testing.T) string {
				t.Helper()
				parent := t.TempDir()
				if err := os.WriteFile(filepath.Join(parent, Filename), []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
				child := filepath.Join(parent, "sub", "deep")
				if err := os.MkdirAll(child, 0o755); err != nil {
					t.Fatal(err)
				}
				return child
			},
			wantPath: true,
		},
		{
			name: "not found",
			setup: func(t *testing.T) string {
				t.Helper()
				return t.TempDir()
			},
			wantPath: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			startDir := tt.setup(t)
			got, err := Find(startDir)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantPath && got == "" {
				t.Fatal("expected a path, got empty")
			}
			if !tt.wantPath && got != "" {
				t.Fatalf("expected empty, got %q", got)
			}
		})
	}
}

func TestMerge(t *testing.T) {
	trueVal := true
	falseVal := false

	file := &Config{
		Build: Build{
			Output:     "from-file.o",
			CPU:        "v2",
			OptProfile: "conservative",
			BTF:        &trueVal,
			Timeout:    "30s",
			Programs:   map[string]string{"prog1": "kprobe/foo"},
		},
		Toolchain: Toolchain{
			LLVMDir: "/usr/lib/llvm-18/bin",
			TinyGo:  "/usr/bin/tinygo",
		},
	}

	tests := []struct {
		name  string
		flags *Config
		check func(t *testing.T, merged *Config)
	}{
		{
			name: "flags override file",
			flags: &Config{
				Build: Build{
					Output:     "override.o",
					CPU:        "v3",
					BTF:        &falseVal,
					OptProfile: "aggressive",
				},
				Toolchain: Toolchain{
					LLC: "/custom/llc",
				},
			},
			check: func(t *testing.T, m *Config) {
				t.Helper()
				if m.Build.Output != "override.o" {
					t.Errorf("output = %q, want override.o", m.Build.Output)
				}
				if m.Build.CPU != "v3" {
					t.Errorf("cpu = %q, want v3", m.Build.CPU)
				}
				if m.Build.BTF == nil || *m.Build.BTF {
					t.Error("btf should be false from flags")
				}
				if m.Build.OptProfile != "aggressive" {
					t.Errorf("opt_profile = %q, want aggressive", m.Build.OptProfile)
				}
				if m.Build.Timeout != "30s" {
					t.Errorf("timeout = %q, want 30s (from file)", m.Build.Timeout)
				}
				if m.Toolchain.LLVMDir != "/usr/lib/llvm-18/bin" {
					t.Errorf("llvm_dir = %q, want from file", m.Toolchain.LLVMDir)
				}
				if m.Toolchain.LLC != "/custom/llc" {
					t.Errorf("llc = %q, want /custom/llc", m.Toolchain.LLC)
				}
				if m.Toolchain.TinyGo != "/usr/bin/tinygo" {
					t.Errorf("tinygo = %q, want from file", m.Toolchain.TinyGo)
				}
			},
		},
		{
			name: "all remaining fields override",
			flags: &Config{
				Build: Build{
					Timeout:      "90s",
					Programs:     map[string]string{"p2": "xdp"},
					CustomPasses: []string{"dce"},
				},
				Toolchain: Toolchain{
					LLVMDir:     "/new/llvm",
					LLVMLink:    "/new/llvm-link",
					Opt:         "/new/opt",
					LLVMAr:      "/new/llvm-ar",
					LLVMObjcopy: "/new/llvm-objcopy",
					Pahole:      "/new/pahole",
					TinyGo:      "/new/tinygo",
				},
			},
			check: checkAllRemainingOverrides,
		},
		{
			name:  "zero flags preserve file",
			flags: &Config{},
			check: func(t *testing.T, m *Config) {
				t.Helper()
				if m.Build.Output != "from-file.o" {
					t.Errorf("output = %q, want from-file.o", m.Build.Output)
				}
				if m.Build.CPU != "v2" {
					t.Errorf("cpu = %q, want v2", m.Build.CPU)
				}
				if m.Toolchain.LLVMDir != "/usr/lib/llvm-18/bin" {
					t.Errorf("llvm_dir = %q, want from file", m.Toolchain.LLVMDir)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			merged := Merge(file, tt.flags)
			tt.check(t, merged)
		})
	}
}

func TestParseTimeout(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid seconds", "30s", false},
		{"valid minutes", "5m", false},
		{"valid compound", "1h30m", false},
		{"empty string", "", false},
		{"invalid format", "not-a-duration", true},
		{"negative", "-5s", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseTimeout(tt.input)
			if tt.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestResolveToolOverrides(t *testing.T) {
	tests := []struct {
		name  string
		tc    Toolchain
		check func(t *testing.T, tools llvm.ToolOverrides)
	}{
		{
			name: "llvm_dir fills all tools",
			tc:   Toolchain{LLVMDir: "/opt/llvm/bin"},
			check: func(t *testing.T, tools llvm.ToolOverrides) {
				t.Helper()
				if tools.LLVMLink != "/opt/llvm/bin/llvm-link" {
					t.Errorf("llvm-link = %q", tools.LLVMLink)
				}
				if tools.Opt != "/opt/llvm/bin/opt" {
					t.Errorf("opt = %q", tools.Opt)
				}
				if tools.LLC != "/opt/llvm/bin/llc" {
					t.Errorf("llc = %q", tools.LLC)
				}
			},
		},
		{
			name: "per-tool override beats llvm_dir",
			tc: Toolchain{
				LLVMDir: "/opt/llvm/bin",
				Opt:     "/custom/opt",
			},
			check: func(t *testing.T, tools llvm.ToolOverrides) {
				t.Helper()
				if tools.Opt != "/custom/opt" {
					t.Errorf("opt = %q, want /custom/opt", tools.Opt)
				}
				if tools.LLC != "/opt/llvm/bin/llc" {
					t.Errorf("llc = %q, want /opt/llvm/bin/llc", tools.LLC)
				}
			},
		},
		{
			name: "empty toolchain returns empty overrides",
			tc:   Toolchain{},
			check: func(t *testing.T, tools llvm.ToolOverrides) {
				t.Helper()
				if tools.LLVMLink != "" || tools.Opt != "" || tools.LLC != "" {
					t.Error("expected empty overrides")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tools := ResolveToolOverrides(tt.tc)
			tt.check(t, tools)
		})
	}
}
