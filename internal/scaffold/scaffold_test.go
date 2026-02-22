package scaffold

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name        string
		cfg         func(dir string) Config
		setup       func(t *testing.T, dir string)
		wantErr     string
		wantFiles   []string
		wantStdout  []string
		wantContain map[string][]string
	}{
		{
			name: "scaffold from name",
			cfg: func(dir string) Config {
				return Config{Dir: dir, Program: "xdp_filter"}
			},
			wantFiles: []string{"bpf/xdp_filter.go", "bpf/xdp_filter_stub.go", "Makefile"},
			wantStdout: []string{
				"create bpf/xdp_filter.go",
				"create bpf/xdp_filter_stub.go",
				"create Makefile",
			},
			wantContain: map[string][]string{
				"bpf/xdp_filter.go": {
					"//go:build tinygo",
					"package main",
					"import \"unsafe\"",
					"bpfMapDef",
					"//export xdp_filter",
					"func xdp_filter(ctx unsafe.Pointer) int32",
					"func main() {}",
				},
				"bpf/xdp_filter_stub.go": {
					"//go:build !tinygo",
					"package main",
				},
				"Makefile": {
					"tinybpf build",
					"--section xdp_filter=",
					"SECTION :=",
					"bpf/xdp_filter.go",
					"xdp_filter.bpf.o",
				},
			},
		},
		{
			name:    "missing name",
			cfg:     func(dir string) Config { return Config{Dir: dir} },
			wantErr: "program name is required",
		},
		{
			name:    "whitespace-only name",
			cfg:     func(dir string) Config { return Config{Dir: dir, Program: "   "} },
			wantErr: "program name is required",
		},
		{
			name: "refuses overwrite",
			cfg: func(dir string) Config {
				return Config{Dir: dir, Program: "xdp_filter"}
			},
			setup: func(t *testing.T, dir string) {
				t.Helper()
				os.MkdirAll(filepath.Join(dir, "bpf"), 0o755)
				os.WriteFile(filepath.Join(dir, "bpf", "xdp_filter.go"), []byte("existing"), 0o644)
			},
			wantErr: "already exists",
		},
		{
			name:    "bad directory",
			cfg:     func(_ string) Config { return Config{Dir: "/dev/null/impossible", Program: "test"} },
			wantErr: "creating bpf directory",
		},
		{
			name: "write error on read-only dir",
			cfg: func(dir string) Config {
				return Config{Dir: dir, Program: "test"}
			},
			setup: func(t *testing.T, dir string) {
				t.Helper()
				bpf := filepath.Join(dir, "bpf")
				os.MkdirAll(bpf, 0o755)
				os.Chmod(bpf, 0o555)
				t.Cleanup(func() { os.Chmod(bpf, 0o755) })
			},
			wantErr: "writing",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := tt.cfg(dir)

			if tt.setup != nil {
				tt.setup(t, dir)
			}

			var stdout bytes.Buffer
			if cfg.Stdout == nil {
				cfg.Stdout = &stdout
			}

			err := Run(cfg)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got: %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			assertFilesExist(t, dir, tt.wantFiles)
			assertStdoutContains(t, stdout.String(), tt.wantStdout)
			assertFileContents(t, dir, tt.wantContain)
		})
	}
}

func assertFilesExist(t *testing.T, dir string, paths []string) {
	t.Helper()
	for _, f := range paths {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("expected file %s to exist", f)
		}
	}
}

func assertStdoutContains(t *testing.T, stdout string, wants []string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q, got:\n%s", want, stdout)
		}
	}
}

func assertFileContents(t *testing.T, dir string, wantContain map[string][]string) {
	t.Helper()
	for suffix, wants := range wantContain {
		data, err := os.ReadFile(filepath.Join(dir, suffix))
		if err != nil {
			t.Errorf("reading %s: %v", suffix, err)
			continue
		}
		for _, want := range wants {
			if !strings.Contains(string(data), want) {
				t.Errorf("%s missing %q", suffix, want)
			}
		}
	}
}

func TestRunNilStdout(t *testing.T) {
	dir := t.TempDir()
	err := Run(Config{Dir: dir, Program: "tc_filter"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"bpf/tc_filter.go", "bpf/tc_filter_stub.go", "Makefile"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("expected %s to exist", f)
		}
	}
}
