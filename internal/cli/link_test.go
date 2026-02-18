package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"testing"
)

func TestRunLink(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T) []string
		wantCode int
		wantOut  string
		wantErr  string
	}{
		{
			name: "explicit subcommand dispatches correctly",
			setup: func(t *testing.T) []string {
				t.Helper()
				return []string{
					"link", "--input", "/dev/null", "--output", "/tmp/test-link.o",
					"--llvm-link", "/does/not/exist/llvm-link",
				}
			},
			wantCode: 1,
			wantErr:  "failed",
		},
		{
			name:     "--help",
			setup:    func(t *testing.T) []string { t.Helper(); return []string{"link", "--help"} },
			wantCode: 0,
			wantErr:  "Usage:",
		},
		{
			name:     "missing input",
			setup:    func(t *testing.T) []string { t.Helper(); return []string{"link"} },
			wantCode: 2,
			wantErr:  "--input",
		},
		{
			name: "config file missing",
			setup: func(t *testing.T) []string {
				t.Helper()
				return []string{
					"--input", "/dev/null",
					"--output", filepath.Join(t.TempDir(), "out.o"),
					"--llvm-link", "/does/not/exist/llvm-link",
					"--config", "/does/not/exist/linker-config.json",
				}
			},
			wantCode: 1,
			wantErr:  "reading config",
		},
		{
			name: "config with invalid pass",
			setup: func(t *testing.T) []string {
				t.Helper()
				tmp := t.TempDir()
				cfgPath := filepath.Join(tmp, "linker-config.json")
				os.WriteFile(cfgPath, []byte(`{"custom_passes": ["-inline;rm"]}`), 0o644)
				return []string{
					"--input", "/dev/null",
					"--output", filepath.Join(tmp, "out.o"),
					"--llvm-link", "/does/not/exist/llvm-link",
					"--config", cfgPath,
				}
			},
			wantCode: 1,
		},
		{
			name: "config with valid passes",
			setup: func(t *testing.T) []string {
				t.Helper()
				tmp := t.TempDir()
				cfgPath := filepath.Join(tmp, "linker-config.json")
				os.WriteFile(cfgPath, []byte(`{"custom_passes": ["inline", "dse"]}`), 0o644)
				return []string{
					"--input", "/dev/null",
					"--output", filepath.Join(tmp, "out.o"),
					"--llvm-link", "/does/not/exist/llvm-link",
					"--config", cfgPath,
				}
			},
			wantCode: 1,
		},
		{
			name: "full success",
			setup: func(t *testing.T) []string {
				t.Helper()
				tmp := t.TempDir()
				toolDir := fakeToolDir(t)
				input := filepath.Join(tmp, "input.ll")
				os.WriteFile(input, []byte(testIR("handle_connect")), 0o644)
				return append([]string{
					"--input", input,
					"--output", filepath.Join(tmp, "out.o"),
					"--verbose",
				}, fakeLLVMArgs(toolDir)...)
			},
			wantCode: 0,
			wantOut:  "wrote",
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
		})
	}
}

func TestStartProfiling(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T) string
		wantErr    string
		preCleanup func(t *testing.T, basePath string)
		wantOutput string
	}{
		{
			name:       "success",
			setup:      func(t *testing.T) string { t.Helper(); return filepath.Join(t.TempDir(), "test") },
			wantOutput: "memory profile:",
		},
		{
			name:    "bad path",
			setup:   func(t *testing.T) string { t.Helper(); return "/does/not/exist/prof" },
			wantErr: "creating CPU profile",
		},
		{
			name: "CPU already running",
			setup: func(t *testing.T) string {
				t.Helper()
				tmp := t.TempDir()
				f, _ := os.Create(filepath.Join(tmp, "block.prof"))
				t.Cleanup(func() { pprof.StopCPUProfile(); f.Close() })
				pprof.StartCPUProfile(f)
				return filepath.Join(tmp, "second")
			},
			wantErr: "CPU profile",
		},
		{
			name: "heap profile write error",
			setup: func(t *testing.T) string {
				t.Helper()
				orig := writeHeapProfile
				t.Cleanup(func() { writeHeapProfile = orig })
				writeHeapProfile = func(w io.Writer) error {
					return fmt.Errorf("injected write error")
				}
				return filepath.Join(t.TempDir(), "test")
			},
			wantOutput: "warning: memory profile:",
		},
		{
			name:  "memory profile create error",
			setup: func(t *testing.T) string { t.Helper(); return filepath.Join(t.TempDir(), "test") },
			preCleanup: func(t *testing.T, basePath string) {
				t.Helper()
				dir := filepath.Dir(basePath)
				os.Chmod(dir, 0o500)
				t.Cleanup(func() { os.Chmod(dir, 0o700) })
			},
			wantOutput: "warning: memory profile:",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			basePath := tt.setup(t)
			var w bytes.Buffer

			cleanup, err := startProfiling(basePath, &w)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected %q in error, got: %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.preCleanup != nil {
				tt.preCleanup(t, basePath)
			}
			cleanup()

			if tt.wantOutput != "" && !strings.Contains(w.String(), tt.wantOutput) {
				t.Fatalf("expected %q in output, got: %s", tt.wantOutput, w.String())
			}
		})
	}
}

func TestRunLinkProfile(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T) []string
		wantCode int
		wantErr  string
	}{
		{
			name: "creates profile on pipeline failure",
			setup: func(t *testing.T) []string {
				t.Helper()
				tmp := t.TempDir()
				return []string{
					"--input", "/dev/null",
					"--output", filepath.Join(tmp, "out.o"),
					"--llvm-link", "/does/not/exist/llvm-link",
					"--profile", filepath.Join(tmp, "prof"),
				}
			},
			wantCode: 1,
		},
		{
			name: "warns on start failure",
			setup: func(t *testing.T) []string {
				t.Helper()
				tmp := t.TempDir()
				f, _ := os.Create(filepath.Join(tmp, "block.prof"))
				t.Cleanup(func() { pprof.StopCPUProfile(); f.Close() })
				pprof.StartCPUProfile(f)
				return []string{
					"--input", "/dev/null",
					"--output", filepath.Join(tmp, "out.o"),
					"--llvm-link", "/does/not/exist/llvm-link",
					"--profile", filepath.Join(tmp, "prof"),
				}
			},
			wantCode: 1,
			wantErr:  "warning: profiling failed to start",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.setup(t)
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
