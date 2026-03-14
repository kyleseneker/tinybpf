package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kyleseneker/tinybpf/internal/testutil"
)

func TestRunBuild(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantErr  string
	}{
		{
			name:     "missing package",
			args:     []string{"build"},
			wantCode: 2,
			wantErr:  "package argument",
		},
		{
			name:     "--help",
			args:     []string{"build", "--help"},
			wantCode: 0,
		},
		{
			name:     "tinygo not found",
			args:     []string{"build", "--tinygo", testutil.BadPath("tinygo"), "./bpf"},
			wantCode: 1,
			wantErr:  "tinygo not found",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, stderr, code := runCLI(t, tt.args...)
			if code != tt.wantCode {
				t.Fatalf("exit code: got %d, want %d, stderr=%s", code, tt.wantCode, stderr)
			}
			if tt.wantErr != "" && !strings.Contains(stderr, tt.wantErr) {
				t.Fatalf("expected %q in stderr, got: %s", tt.wantErr, stderr)
			}
		})
	}
}

func TestRunBuildHappyPath(t *testing.T) {
	ir := testIR("my_prog")
	dir := t.TempDir()
	toolDir := fakeToolDir(t)

	irFile := filepath.Join(dir, "program.ll")
	if err := os.WriteFile(irFile, []byte(ir), 0o644); err != nil {
		t.Fatal(err)
	}

	args := append([]string{
		"link", "--input", irFile, "--output", filepath.Join(dir, "out.o"), "--verbose",
	}, fakeLLVMArgs(toolDir)...)

	stdout, stderr, code := runCLI(t, args...)
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0, stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "wrote") {
		t.Fatalf("expected 'wrote' in stdout, got: %s", stdout)
	}
}
