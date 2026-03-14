package config

import (
	"os"
	"path/filepath"
	"testing"
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
