package transform

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func BenchmarkTransformLines(b *testing.B) {
	fixture := filepath.Join("..", "..", "testdata", "tinygo_probe.ll")
	data, err := os.ReadFile(fixture)
	if err != nil {
		b.Skipf("fixture not found: %v", err)
	}
	srcLines := strings.Split(string(data), "\n")
	opts := Options{
		Sections: map[string]string{"handle_connect": "kprobe/sys_connect"},
		Stdout:   io.Discard,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		lines := make([]string, len(srcLines))
		copy(lines, srcLines)
		if _, err := TransformLines(context.Background(), lines, opts); err != nil {
			b.Fatal(err)
		}
	}
}

func FuzzTransformLines(f *testing.F) {
	f.Add(`target datalayout = "e-m:o-p270:32:32-p271:32:32"
target triple = "arm64-apple-macosx11.0.0"

define i32 @my_program(ptr %ctx) {
entry:
  ret i32 0
}`)
	f.Add(`target triple = "x86_64-unknown-linux-gnu"

@main.events = global %main.bpfMapDef { i32 27, i32 0, i32 0, i32 16777216, i32 0 }, align 4

define i32 @my_func(ptr %ctx) #0 {
entry:
  %0 = call i64 @main.bpfGetCurrentPidTgid(ptr undef) #7
  ret i32 0
}

attributes #0 = { "target-cpu"="generic" "target-features"="+neon" }`)
	f.Add(`just random text that is not IR`)
	f.Add(`define void @runtime.runMain() {
entry:
  ret void
}

define i32 @handle(ptr %ctx) {
entry:
  %buf = call align 4 dereferenceable(16) ptr @runtime.alloc(i64 16, ptr null, ptr undef)
  %1 = call i64 @main.bpfRingbufOutput(ptr @main.events, ptr %buf, i64 16, i64 0, ptr undef) #7
  ret i32 0
}`)

	f.Fuzz(func(t *testing.T, ir string) {
		lines := strings.Split(ir, "\n")
		TransformLines(context.Background(), lines, Options{Stdout: io.Discard})
	})
}

func TestRun(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) (ctx context.Context, in, out string, opts Options)
		wantErr string
	}{
		{
			name: "read error",
			setup: func(t *testing.T) (context.Context, string, string, Options) {
				t.Helper()
				return context.Background(), "/does/not/exist.ll", filepath.Join(t.TempDir(), "out.ll"), Options{}
			},
			wantErr: "read input:",
		},
		{
			name: "write error",
			setup: func(t *testing.T) (context.Context, string, string, Options) {
				t.Helper()
				tmp := t.TempDir()
				input := filepath.Join(tmp, "in.ll")
				os.WriteFile(input, []byte("define i32 @my_func(ptr %ctx) {\nentry:\n  ret i32 0\n}\n"), 0o644)
				return context.Background(), input, filepath.Join(input, "out.ll"), Options{Stdout: io.Discard}
			},
			wantErr: "write",
		},
		{
			name: "cancelled context",
			setup: func(t *testing.T) (context.Context, string, string, Options) {
				t.Helper()
				tmp := t.TempDir()
				input := filepath.Join(tmp, "in.ll")
				os.WriteFile(input, []byte("target triple = \"x86_64\"\ndefine i32 @f(ptr %ctx) {\nentry:\n  ret i32 0\n}\n"), 0o644)
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, input, filepath.Join(tmp, "out.ll"), Options{Stdout: io.Discard}
			},
			wantErr: "context canceled",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, in, out, opts := tt.setup(t)
			err := Run(ctx, in, out, opts)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected %q in error, got: %v", tt.wantErr, err)
			}
		})
	}
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
	got, err := TransformLines(context.Background(), strings.Split(string(data), "\n"), opts)
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
	outputObj := filepath.Join(tmpDir, "output.o")

	opts := Options{
		Sections: map[string]string{"handle_connect": "kprobe/sys_connect"},
		Stdout:   io.Discard,
	}
	if err := Run(context.Background(), fixture, outputLL, opts); err != nil {
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
	if err := Run(context.Background(), fixture, transformedLL, Options{
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
