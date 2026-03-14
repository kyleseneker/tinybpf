package pipeline

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/kyleseneker/tinybpf/diag"
)

func TestRunE2E(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("BPF validation requires Linux")
	}
	for _, tool := range []string{"llvm-link", "opt", "llc"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("missing %s", tool)
		}
	}

	wd, _ := os.Getwd()

	tests := []struct {
		name      string
		fixture   string
		wantErr   bool
		wantStage diag.Stage
	}{
		{"smoke", "minimal.ll", false, ""},
		{"invalid IR", "invalid.ll", true, diag.StageLink},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := filepath.Join(wd, "..", "ir", "testdata", tt.fixture)
			if _, err := os.Stat(input); err != nil {
				t.Fatalf("missing test fixture: %v", err)
			}
			output := filepath.Join(t.TempDir(), "prog.o")
			artifacts, err := Run(context.Background(), Config{
				Inputs: []string{input}, Output: output, Timeout: 30 * time.Second,
			})
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if tt.wantStage != "" && !diag.IsStage(err, tt.wantStage) {
					t.Fatalf("expected stage %v, got: %v", tt.wantStage, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if artifacts == nil {
				t.Fatal("expected artifacts")
			}
		})
	}
}
