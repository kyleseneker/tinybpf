package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunBuild(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T) []string
		wantCode int
		wantOut  string
		wantErr  string
	}{
		{
			name:     "missing package",
			setup:    func(t *testing.T) []string { t.Helper(); return []string{"build"} },
			wantCode: 2,
			wantErr:  "package argument",
		},
		{
			name:     "--help",
			setup:    func(t *testing.T) []string { t.Helper(); return []string{"build", "--help"} },
			wantCode: 0,
			wantErr:  "Usage:",
		},
		{
			name: "tinygo not found",
			setup: func(t *testing.T) []string {
				t.Helper()
				return []string{"build", "--tinygo", "/does/not/exist/tinygo", "./bpf"}
			},
			wantCode: 1,
			wantErr:  "tinygo not found",
		},
		{
			name: "temp dir creation failure",
			setup: func(t *testing.T) []string {
				t.Helper()
				dir := t.TempDir()
				fakeTG := filepath.Join(dir, "tinygo")
				os.WriteFile(fakeTG, []byte("#!/bin/sh\n"), 0o755)
				t.Setenv("TMPDIR", "/nonexistent/path")
				orig := runTinyGo
				t.Cleanup(func() { runTinyGo = orig })
				runTinyGo = func(_ context.Context, _ time.Duration, _ string, _ ...string) (tinyGoResult, error) {
					return tinyGoResult{}, nil
				}
				return []string{"build", "--tinygo", fakeTG, "./bpf"}
			},
			wantCode: 1,
			wantErr:  "creating temp directory",
		},
		{
			name: "tinygo compile failure",
			setup: func(t *testing.T) []string {
				t.Helper()
				orig := runTinyGo
				t.Cleanup(func() { runTinyGo = orig })
				runTinyGo = func(_ context.Context, _ time.Duration, _ string, _ ...string) (tinyGoResult, error) {
					return tinyGoResult{stderr: "cannot find package"}, fmt.Errorf("exit status 2")
				}
				dir := t.TempDir()
				fakeTG := filepath.Join(dir, "tinygo")
				os.WriteFile(fakeTG, []byte("#!/bin/sh\nexit 1\n"), 0o755)
				return []string{"build", "--tinygo", fakeTG, "--output", filepath.Join(dir, "out.o"), "./bpf"}
			},
			wantCode: 1,
			wantErr:  "tinygo-compile",
		},
		{
			name: "verbose shows tinygo stderr",
			setup: func(t *testing.T) []string {
				t.Helper()
				ir := testIR("my_prog")
				orig := runTinyGo
				t.Cleanup(func() { runTinyGo = orig })
				runTinyGo = func(_ context.Context, _ time.Duration, _ string, args ...string) (tinyGoResult, error) {
					for i, a := range args {
						if a == "-o" && i+1 < len(args) {
							os.WriteFile(args[i+1], []byte(ir), 0o644)
							break
						}
					}
					return tinyGoResult{stderr: "some tinygo warning"}, nil
				}
				dir := t.TempDir()
				fakeTG := filepath.Join(dir, "tinygo")
				os.WriteFile(fakeTG, []byte("#!/bin/sh\n"), 0o755)
				toolDir := fakeToolDir(t)
				args := append([]string{
					"build", "--tinygo", fakeTG, "--output", filepath.Join(dir, "out.o"), "--verbose",
				}, fakeLLVMArgs(toolDir)...)
				return append(args, "./bpf")
			},
			wantCode: 0,
			wantErr:  "some tinygo warning",
		},
		{
			name: "happy path",
			setup: func(t *testing.T) []string {
				t.Helper()
				ir := testIR("my_prog")
				orig := runTinyGo
				t.Cleanup(func() { runTinyGo = orig })
				runTinyGo = func(_ context.Context, _ time.Duration, _ string, args ...string) (tinyGoResult, error) {
					for i, a := range args {
						if a == "-o" && i+1 < len(args) {
							os.WriteFile(args[i+1], []byte(ir), 0o644)
							break
						}
					}
					return tinyGoResult{}, nil
				}
				dir := t.TempDir()
				fakeTG := filepath.Join(dir, "tinygo")
				os.WriteFile(fakeTG, []byte("#!/bin/sh\n"), 0o755)
				toolDir := fakeToolDir(t)
				args := append([]string{
					"build", "--tinygo", fakeTG, "--output", filepath.Join(dir, "out.o"), "--verbose",
				}, fakeLLVMArgs(toolDir)...)
				return append(args, "./bpf")
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

func TestBuildWorkDir(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T)
		input     func(t *testing.T) string
		wantError bool
		checkDir  bool
	}{
		{
			name:     "explicit dir created",
			input:    func(t *testing.T) string { t.Helper(); return filepath.Join(t.TempDir(), "new", "subdir") },
			checkDir: true,
		},
		{
			name:  "temp dir created",
			input: func(t *testing.T) string { t.Helper(); return "" },
		},
		{
			name:      "temp dir error",
			setup:     func(t *testing.T) { t.Helper(); t.Setenv("TMPDIR", "/nonexistent/path") },
			input:     func(t *testing.T) string { t.Helper(); return "" },
			wantError: true,
		},
		{
			name:      "explicit dir bad parent",
			input:     func(t *testing.T) string { t.Helper(); return "/dev/null/impossible/sub" },
			wantError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup(t)
			}
			in := tt.input(t)
			dir, cleanup, err := buildWorkDir(in)
			if tt.wantError {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()
			if dir == "" {
				t.Fatal("expected non-empty dir")
			}
			if tt.checkDir {
				if dir != in {
					t.Fatalf("got %q, want %q", dir, in)
				}
				info, statErr := os.Stat(dir)
				if statErr != nil {
					t.Fatalf("directory not created: %v", statErr)
				}
				if !info.IsDir() {
					t.Fatal("expected a directory")
				}
			}
		})
	}
}

func TestRunTinyGoReal(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name       string
		script     string
		timeout    time.Duration
		wantErr    bool
		wantStderr string
	}{
		{
			name:       "success with stderr",
			script:     "#!/bin/sh\necho 'stderr output' >&2\n",
			timeout:    5 * time.Second,
			wantStderr: "stderr output",
		},
		{
			name:       "zero timeout uses default",
			script:     "#!/bin/sh\necho 'stderr output' >&2\n",
			timeout:    0,
			wantStderr: "stderr output",
		},
		{
			name:       "command failure",
			script:     "#!/bin/sh\necho 'build error' >&2\nexit 1\n",
			timeout:    5 * time.Second,
			wantErr:    true,
			wantStderr: "build error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bin := filepath.Join(dir, strings.ReplaceAll(tt.name, " ", "_"))
			os.WriteFile(bin, []byte(tt.script), 0o755)

			res, err := runTinyGo(context.Background(), tt.timeout, bin)
			if tt.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Fatal(err)
			}
			if tt.wantStderr != "" && !strings.Contains(res.stderr, tt.wantStderr) {
				t.Fatalf("expected %q in stderr, got: %q", tt.wantStderr, res.stderr)
			}
		})
	}
}

func TestFindTinyGo(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T) string
		wantPath bool
		wantErr  string
	}{
		{
			name: "explicit path exists",
			setup: func(t *testing.T) string {
				t.Helper()
				bin := filepath.Join(t.TempDir(), "tinygo")
				os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755)
				return bin
			},
			wantPath: true,
		},
		{
			name:    "explicit path missing",
			setup:   func(t *testing.T) string { t.Helper(); return "/does/not/exist/tinygo" },
			wantErr: "tinygo not found at",
		},
		{
			name: "found on PATH",
			setup: func(t *testing.T) string {
				t.Helper()
				dir := t.TempDir()
				os.WriteFile(filepath.Join(dir, "tinygo"), []byte("#!/bin/sh\n"), 0o755)
				t.Setenv("PATH", dir)
				return ""
			},
			wantPath: true,
		},
		{
			name: "not on PATH",
			setup: func(t *testing.T) string {
				t.Helper()
				t.Setenv("PATH", t.TempDir())
				return ""
			},
			wantErr: "tinygo not found on PATH",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			override := tt.setup(t)
			got, err := findTinyGo(override)
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
			if tt.wantPath && got == "" {
				t.Fatal("expected non-empty path")
			}
		})
	}
}
