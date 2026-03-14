package config

import (
	"testing"

	"github.com/kyleseneker/tinybpf"
)

func checkFullRequest(t *testing.T, req tinybpf.Request) {
	t.Helper()
	if req.Output != "out.o" {
		t.Errorf("Output = %q", req.Output)
	}
	if req.CPU != "v2" {
		t.Errorf("CPU = %q", req.CPU)
	}
	if req.OptProfile != "aggressive" {
		t.Errorf("OptProfile = %q", req.OptProfile)
	}
	if !req.EnableBTF {
		t.Error("EnableBTF should be true")
	}
	if req.Timeout.Seconds() != 45 {
		t.Errorf("Timeout = %v", req.Timeout)
	}
	if len(req.Programs) != 2 {
		t.Fatalf("Programs len = %d, want 2", len(req.Programs))
	}
	if req.Sections["handler"] != "kprobe/sys_connect" {
		t.Errorf("Sections[handler] = %q", req.Sections["handler"])
	}
	if _, ok := req.Sections["prog2"]; ok {
		t.Error("prog2 should not have a section (empty value)")
	}
	if len(req.CustomPasses) != 1 || req.CustomPasses[0] != "inline" {
		t.Errorf("CustomPasses = %v", req.CustomPasses)
	}
	if req.Toolchain.LLVMLink != "/opt/llvm/bin/llvm-link" {
		t.Errorf("Toolchain.LLVMLink = %q", req.Toolchain.LLVMLink)
	}
	if req.Toolchain.TinyGo != "/opt/tinygo/bin/tinygo" {
		t.Errorf("Toolchain.TinyGo = %q", req.Toolchain.TinyGo)
	}
}

func TestToRequest(t *testing.T) {
	trueVal := true

	tests := []struct {
		name  string
		cfg   *Config
		check func(t *testing.T, req tinybpf.Request)
	}{
		{
			name: "maps all fields",
			cfg: &Config{
				Build: Build{
					Output:       "out.o",
					CPU:          "v2",
					OptProfile:   "aggressive",
					BTF:          &trueVal,
					Timeout:      "45s",
					Programs:     map[string]string{"handler": "kprobe/sys_connect", "prog2": ""},
					CustomPasses: []string{"inline"},
				},
				Toolchain: Toolchain{
					LLVMDir: "/opt/llvm/bin",
					TinyGo:  "/opt/tinygo/bin/tinygo",
				},
			},
			check: checkFullRequest,
		},
		{
			name: "empty config uses zero values",
			cfg:  &Config{},
			check: func(t *testing.T, req tinybpf.Request) {
				t.Helper()
				if req.Output != "" {
					t.Errorf("Output = %q, want empty", req.Output)
				}
				if req.EnableBTF {
					t.Error("EnableBTF should be false")
				}
				if req.Timeout != 0 {
					t.Errorf("Timeout = %v, want 0", req.Timeout)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := ToRequest(tt.cfg)
			tt.check(t, req)
		})
	}
}

func TestResolveToolchain(t *testing.T) {
	tests := []struct {
		name  string
		tc    Toolchain
		check func(t *testing.T, tools tinybpf.Toolchain)
	}{
		{
			name: "llvm_dir fills all tools",
			tc:   Toolchain{LLVMDir: "/opt/llvm/bin"},
			check: func(t *testing.T, tools tinybpf.Toolchain) {
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
			check: func(t *testing.T, tools tinybpf.Toolchain) {
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
			check: func(t *testing.T, tools tinybpf.Toolchain) {
				t.Helper()
				if tools.LLVMLink != "" || tools.Opt != "" || tools.LLC != "" {
					t.Error("expected empty overrides")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tools := ResolveToolchain(tt.tc)
			tt.check(t, tools)
		})
	}
}
