package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunInit(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		setup     func(t *testing.T, dir string)
		wantCode  int
		wantFiles []string
		wantOut   string
	}{
		{
			name:      "success",
			args:      []string{"init", "xdp_filter"},
			wantCode:  0,
			wantFiles: []string{"bpf/xdp_filter.go", "bpf/xdp_filter_stub.go", "Makefile"},
			wantOut:   "create",
		},
		{
			name:     "missing name",
			args:     []string{"init"},
			wantCode: 2,
		},
		{
			name:     "too many args",
			args:     []string{"init", "a", "b"},
			wantCode: 2,
		},
		{
			name:     "--help",
			args:     []string{"init", "--help"},
			wantCode: 0,
		},
		{
			name: "scaffold error (read-only dir)",
			args: []string{"init", "myproject"},
			setup: func(t *testing.T, dir string) {
				t.Helper()
				os.Chmod(dir, 0o500)
				t.Cleanup(func() { os.Chmod(dir, 0o700) })
			},
			wantCode: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			orig, _ := os.Getwd()
			os.Chdir(dir)
			defer os.Chdir(orig)

			if tt.setup != nil {
				tt.setup(t, dir)
			}

			stdout, stderr, code := runCLI(t, tt.args...)
			if code != tt.wantCode {
				t.Fatalf("exit code: got %d, want %d, stderr=%s", code, tt.wantCode, stderr)
			}
			for _, f := range tt.wantFiles {
				if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
					t.Errorf("expected %s to exist", f)
				}
			}
			if tt.wantOut != "" && !strings.Contains(stdout, tt.wantOut) {
				t.Errorf("expected %q in stdout, got: %s", tt.wantOut, stdout)
			}
		})
	}
}
