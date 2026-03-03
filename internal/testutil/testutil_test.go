package testutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMakeFakeTool(t *testing.T) {
	dir := t.TempDir()
	path := MakeFakeTool(t, dir, "my-tool", "echo hello")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatal("expected executable permissions")
	}
}

func TestFakeToolDir(t *testing.T) {
	dir := FakeToolDir(t)
	for _, name := range []string{"llvm-link", "opt", "llc"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("expected %s to exist: %v", name, err)
		}
	}
}

func TestFakeLLVMArgs(t *testing.T) {
	args := FakeLLVMArgs("/some/dir")
	if len(args) != 6 {
		t.Fatalf("expected 6 args, got %d", len(args))
	}
}

func TestSampleIR(t *testing.T) {
	ir := SampleIR("my_func")
	if len(ir) == 0 {
		t.Fatal("expected non-empty IR")
	}
}

func TestBadPath(t *testing.T) {
	p := BadPath("child")
	if _, err := os.Stat(p); err == nil {
		t.Fatalf("expected BadPath(%q) to not exist", p)
	}
}
