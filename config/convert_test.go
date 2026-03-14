package config

import (
	"testing"

	"github.com/kyleseneker/tinybpf/pipeline"
)

func checkFullPipeline(t *testing.T, pc pipeline.Config) {
	t.Helper()
	if pc.Output != "out.o" {
		t.Errorf("Output = %q", pc.Output)
	}
	if pc.CPU != "v2" {
		t.Errorf("CPU = %q", pc.CPU)
	}
	if pc.OptProfile != "aggressive" {
		t.Errorf("OptProfile = %q", pc.OptProfile)
	}
	if !pc.EnableBTF {
		t.Error("EnableBTF should be true")
	}
	if pc.Timeout.Seconds() != 45 {
		t.Errorf("Timeout = %v", pc.Timeout)
	}
	if len(pc.Programs) != 2 {
		t.Fatalf("Programs len = %d, want 2", len(pc.Programs))
	}
	if pc.Sections["handler"] != "kprobe/sys_connect" {
		t.Errorf("Sections[handler] = %q", pc.Sections["handler"])
	}
	if _, ok := pc.Sections["prog2"]; ok {
		t.Error("prog2 should not have a section (empty value)")
	}
	if len(pc.CustomPasses) != 1 || pc.CustomPasses[0] != "inline" {
		t.Errorf("CustomPasses = %v", pc.CustomPasses)
	}
	if pc.Tools.LLVMLink != "/opt/llvm/bin/llvm-link" {
		t.Errorf("Tools.LLVMLink = %q", pc.Tools.LLVMLink)
	}
}

func TestToPipeline(t *testing.T) {
	trueVal := true

	tests := []struct {
		name  string
		cfg   *Config
		check func(t *testing.T, pc pipeline.Config)
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
			check: checkFullPipeline,
		},
		{
			name: "empty config uses zero values",
			cfg:  &Config{},
			check: func(t *testing.T, pc pipeline.Config) {
				t.Helper()
				if pc.Output != "" {
					t.Errorf("Output = %q, want empty", pc.Output)
				}
				if pc.EnableBTF {
					t.Error("EnableBTF should be false")
				}
				if pc.Timeout != 0 {
					t.Errorf("Timeout = %v, want 0", pc.Timeout)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pc := ToPipeline(tt.cfg)
			tt.check(t, pc)
		})
	}
}
