package testutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMakeFakeTool(t *testing.T) {
	tests := []struct {
		name   string
		tool   string
		script string
	}{
		{
			name:   "creates executable file",
			tool:   "my-tool",
			script: "echo hello",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := MakeFakeTool(t, dir, tt.tool, tt.script)
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode()&0o111 == 0 {
				t.Fatal("expected executable permissions")
			}
		})
	}
}

func TestFakeToolDir(t *testing.T) {
	tests := []struct {
		name      string
		wantTools []string
	}{
		{
			name:      "contains all required tools",
			wantTools: []string{"llvm-link", "opt", "llc"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := FakeToolDir(t)
			for _, name := range tt.wantTools {
				if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
					t.Fatalf("expected %s to exist: %v", name, err)
				}
			}
		})
	}
}

func TestFakeLLVMArgs(t *testing.T) {
	tests := []struct {
		name    string
		dir     string
		wantLen int
	}{
		{
			name:    "returns 6 args",
			dir:     "/some/dir",
			wantLen: 6,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := FakeLLVMArgs(tt.dir)
			if len(args) != tt.wantLen {
				t.Fatalf("expected %d args, got %d", tt.wantLen, len(args))
			}
		})
	}
}

func TestSampleIR(t *testing.T) {
	tests := []struct {
		name string
		fn   string
	}{
		{
			name: "returns non-empty IR",
			fn:   "my_func",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ir := SampleIR(tt.fn)
			if len(ir) == 0 {
				t.Fatal("expected non-empty IR")
			}
		})
	}
}

func TestBadPath(t *testing.T) {
	tests := []struct {
		name  string
		child string
	}{
		{
			name:  "returns non-existent path",
			child: "child",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := BadPath(tt.child)
			if _, err := os.Stat(p); err == nil {
				t.Fatalf("expected BadPath(%q) to not exist", p)
			}
		})
	}
}
