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
			name: "nil stdout still creates files",
			cfg: func(dir string) Config {
				return Config{Dir: dir, Program: "tc_filter", Stdout: nil}
			},
			wantFiles: []string{"bpf/tc_filter.go", "bpf/tc_filter_stub.go", "Makefile"},
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
			name: "refuses overwrite of first file",
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
			name: "refuses overwrite of later file",
			cfg: func(dir string) Config {
				return Config{Dir: dir, Program: "xdp_filter"}
			},
			setup: func(t *testing.T, dir string) {
				t.Helper()
				os.MkdirAll(filepath.Join(dir, "bpf"), 0o755)
				os.WriteFile(filepath.Join(dir, "Makefile"), []byte("existing"), 0o644)
			},
			wantErr: "already exists",
		},
		{
			name:    "name with path separator",
			cfg:     func(dir string) Config { return Config{Dir: dir, Program: "foo/bar"} },
			wantErr: "path separators",
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

func TestBuildPlan(t *testing.T) {
	files := buildPlan("/proj", "/proj/bpf", "myprobe")
	if len(files) != 3 {
		t.Fatalf("expected 3 planned files, got %d", len(files))
	}

	wantPaths := []string{
		filepath.Join("/proj/bpf", "myprobe.go"),
		filepath.Join("/proj/bpf", "myprobe_stub.go"),
		filepath.Join("/proj", "Makefile"),
	}
	for i, want := range wantPaths {
		if files[i].path != want {
			t.Errorf("files[%d].path = %q, want %q", i, files[i].path, want)
		}
	}

	if !strings.Contains(files[0].content, "//export myprobe") {
		t.Error("program file missing //export directive")
	}
	if !strings.Contains(files[1].content, "//go:build !tinygo") {
		t.Error("stub file missing build constraint")
	}
	if !strings.Contains(files[2].content, "tinybpf build") {
		t.Error("Makefile missing build command")
	}
}

func TestCheckCollisions(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "exists.go")
	os.WriteFile(existing, []byte("x"), 0o644)

	tests := []struct {
		name    string
		files   []plannedFile
		wantErr string
	}{
		{
			name:  "no collisions",
			files: []plannedFile{{path: filepath.Join(dir, "new.go")}},
		},
		{
			name:    "collision detected",
			files:   []plannedFile{{path: existing}},
			wantErr: "already exists",
		},
		{
			name: "collision on second file",
			files: []plannedFile{
				{path: filepath.Join(dir, "new.go")},
				{path: existing},
			},
			wantErr: "already exists",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkCollisions(tt.files)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateProgramName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{name: "valid name", input: "xdp_filter"},
		{name: "valid single char", input: "x"},
		{name: "empty", input: "", wantErr: "program name is required"},
		{name: "whitespace only", input: "   ", wantErr: "program name is required"},
		{name: "forward slash", input: "foo/bar", wantErr: "path separators"},
		{name: "backslash", input: `foo\bar`, wantErr: "path separators"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateProgramName(tt.input)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tt.wantErr)
			}
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
