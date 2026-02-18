package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunDoctor(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T) []string
		wantCode int
		wantErr  string
	}{
		{
			name: "success",
			setup: func(t *testing.T) []string {
				t.Helper()
				dir := t.TempDir()
				fakeTool := func(name string) string {
					p := filepath.Join(dir, name)
					os.WriteFile(p, []byte("#!/bin/sh\necho ok\n"), 0o755)
					return p
				}
				return []string{
					"--llvm-link", fakeTool("llvm-link"),
					"--opt", fakeTool("opt"),
					"--llc", fakeTool("llc"),
				}
			},
			wantCode: 0,
		},
		{
			name: "missing tool",
			setup: func(t *testing.T) []string {
				t.Helper()
				return []string{"--llvm-link", "/does/not/exist/llvm-link"}
			},
			wantCode: 1,
			wantErr:  "llvm-link",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"doctor"}, tt.setup(t)...)
			_, stderr, code := runCLI(t, args...)
			if code != tt.wantCode {
				t.Fatalf("exit code: got %d, want %d, stderr=%s", code, tt.wantCode, stderr)
			}
			if tt.wantErr != "" && !strings.Contains(stderr, tt.wantErr) {
				t.Fatalf("expected %q in stderr, got: %s", tt.wantErr, stderr)
			}
		})
	}
}
