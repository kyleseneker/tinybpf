package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func initWorkDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig, _ := os.Getwd()
	t.Cleanup(func() { os.Chdir(orig) })
	os.Chdir(dir)
	return dir
}

func TestRunInit(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T) []string
		wantCode  int
		wantFiles []string
		wantOut   string
		wantErr   string
	}{
		{
			name: "success",
			setup: func(t *testing.T) []string {
				t.Helper()
				initWorkDir(t)
				return []string{"init", "xdp_filter"}
			},
			wantCode:  0,
			wantFiles: []string{"bpf/xdp_filter.go", "bpf/xdp_filter_stub.go", "Makefile"},
			wantOut:   "create",
		},
		{
			name: "missing name",
			setup: func(t *testing.T) []string {
				t.Helper()
				initWorkDir(t)
				return []string{"init"}
			},
			wantCode: 2,
			wantErr:  "project name",
		},
		{
			name: "too many args",
			setup: func(t *testing.T) []string {
				t.Helper()
				initWorkDir(t)
				return []string{"init", "a", "b"}
			},
			wantCode: 2,
			wantErr:  "project name",
		},
		{
			name: "--help",
			setup: func(t *testing.T) []string {
				t.Helper()
				initWorkDir(t)
				return []string{"init", "--help"}
			},
			wantCode: 0,
		},
		{
			name: "scaffold error (read-only dir)",
			setup: func(t *testing.T) []string {
				t.Helper()
				dir := initWorkDir(t)
				os.Chmod(dir, 0o500)
				t.Cleanup(func() { os.Chmod(dir, 0o700) })
				return []string{"init", "myproject"}
			},
			wantCode: 1,
			wantErr:  "error:",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.setup(t)
			stdout, stderr, code := runCLI(t, args...)
			if code != tt.wantCode {
				t.Fatalf("exit code: got %d, want %d, stderr=%s", code, tt.wantCode, stderr)
			}
			if tt.wantOut != "" && !strings.Contains(stdout, tt.wantOut) {
				t.Fatalf("expected %q in stdout, got: %s", tt.wantOut, stdout)
			}
			if tt.wantErr != "" && !strings.Contains(stderr, tt.wantErr) {
				t.Fatalf("expected %q in stderr, got: %s", tt.wantErr, stderr)
			}
			for _, f := range tt.wantFiles {
				if _, err := os.Stat(filepath.Join(".", f)); err != nil {
					t.Errorf("expected %s to exist", f)
				}
			}
		})
	}
}
