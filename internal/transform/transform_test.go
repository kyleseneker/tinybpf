package transform

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	t.Run("read error", func(t *testing.T) {
		if err := Run("/does/not/exist.ll", filepath.Join(t.TempDir(), "out.ll"), Options{}); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("write error", func(t *testing.T) {
		tmp := t.TempDir()
		input := filepath.Join(tmp, "in.ll")
		os.WriteFile(input, []byte("define i32 @probe(ptr %ctx) {\nentry:\n  ret i32 0\n}\n"), 0o644)
		if err := Run(input, filepath.Join(input, "out.ll"), Options{Stdout: io.Discard}); err == nil {
			t.Fatal("expected error")
		}
	})
}

// --- Integration tests (require fixtures + LLVM tools) ---

func TestFullTransform(t *testing.T) {
	fixture := filepath.Join("..", "..", "testdata", "tinygo_probe.ll")
	if _, err := os.Stat(fixture); err != nil {
		t.Skipf("fixture not found: %v", err)
	}

	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}

	opts := Options{
		Sections: map[string]string{"handle_connect": "kprobe/sys_connect"},
		Stdout:   io.Discard,
	}
	got, err := TransformLines(strings.Split(string(data), "\n"), opts)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(got, "\n")

	checks := []struct {
		contains bool
		substr   string
	}{
		{true, `target triple = "bpf"`},
		{true, `section "kprobe/sys_connect"`},
		{true, `section ".maps"`},
		{true, "alloca [16 x i8]"},
		{true, "llvm.memset.p0.i64"},
		{false, "@__dynamic_loader("},
		{false, "@tinygo_signal_handler("},
		{false, "@runtime.runMain("},
		{false, "@main.bpfProbeReadUser"},
		{false, "@runtime.alloc"},
		{false, "target-cpu"},
		{false, "target-features"},
	}
	for _, c := range checks {
		if strings.Contains(text, c.substr) != c.contains {
			if c.contains {
				t.Errorf("missing %q", c.substr)
			} else {
				t.Errorf("should not contain %q", c.substr)
			}
		}
	}

	for _, id := range []string{"112", "14", "130"} {
		if !strings.Contains(text, "inttoptr (i64 "+id+" to ptr)") {
			t.Errorf("helper inttoptr for ID %s not found", id)
		}
	}

	defineCount := 0
	for _, line := range got {
		if strings.HasPrefix(strings.TrimSpace(line), "define ") {
			defineCount++
		}
	}
	if defineCount != 1 {
		t.Errorf("expected 1 define block, got %d", defineCount)
	}
}

func TestFullTransformLLC(t *testing.T) {
	llcPath, err := exec.LookPath("llc")
	if err != nil {
		t.Skip("llc not found on PATH")
	}

	fixture := filepath.Join("..", "..", "testdata", "tinygo_probe.ll")
	if _, err := os.Stat(fixture); err != nil {
		t.Skipf("fixture not found: %v", err)
	}

	tmpDir := t.TempDir()
	outputLL := filepath.Join(tmpDir, "transformed.ll")
	outputObj := filepath.Join(tmpDir, "probe.o")

	opts := Options{
		Sections: map[string]string{"handle_connect": "kprobe/sys_connect"},
		Stdout:   io.Discard,
	}
	if err := Run(fixture, outputLL, opts); err != nil {
		t.Fatalf("transform failed: %v", err)
	}

	cmd := exec.Command(llcPath, "-march=bpf", "-mcpu=v3", "-filetype=obj", outputLL, "-o", outputObj)
	if out, err := cmd.CombinedOutput(); err != nil {
		irData, _ := os.ReadFile(outputLL)
		t.Fatalf("llc failed: %v\nllc output:\n%s\ntransformed IR:\n%s", err, out, irData)
	}

	info, err := os.Stat(outputObj)
	if err != nil {
		t.Fatalf("output not created: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("output is empty")
	}
}

func TestAllOptProfilesProduceValidBPF(t *testing.T) {
	optPath, err := exec.LookPath("opt")
	if err != nil {
		t.Skip("opt not found on PATH")
	}
	llcPath, err := exec.LookPath("llc")
	if err != nil {
		t.Skip("llc not found on PATH")
	}

	fixture := filepath.Join("..", "..", "testdata", "tinygo_probe.ll")
	if _, err := os.Stat(fixture); err != nil {
		t.Skipf("fixture not found: %v", err)
	}

	tmpDir := t.TempDir()
	transformedLL := filepath.Join(tmpDir, "transformed.ll")
	if err := Run(fixture, transformedLL, Options{
		Sections: map[string]string{"handle_connect": "kprobe/sys_connect"},
		Stdout:   io.Discard,
	}); err != nil {
		t.Fatalf("transform failed: %v", err)
	}

	profiles := map[string]string{
		"conservative": "default<O1>",
		"default":      "default<Os>",
		"aggressive":   "default<O2>",
		"verifier-safe": "function(sroa,early-cse<memssa>,instcombine," +
			"simplifycfg<bonus-inst-threshold=4>,gvn,dse,mem2reg," +
			"adce,sccp,instcombine,simplifycfg<bonus-inst-threshold=4>,adce)",
	}

	for name, pipeline := range profiles {
		t.Run(name, func(t *testing.T) {
			optimizedLL := filepath.Join(tmpDir, name+"-opt.ll")
			outputObj := filepath.Join(tmpDir, name+".o")

			cmd := exec.Command(optPath, "-passes="+pipeline, "-S", transformedLL, "-o", optimizedLL)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("opt failed: %v\n%s", err, out)
			}

			cmd = exec.Command(llcPath, "-march=bpf", "-mcpu=v3", "-filetype=obj", optimizedLL, "-o", outputObj)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("llc failed: %v\n%s", err, out)
			}

			info, err := os.Stat(outputObj)
			if err != nil {
				t.Fatalf("output not created: %v", err)
			}
			if info.Size() == 0 {
				t.Fatal("output is empty")
			}
		})
	}
}
