package cli

import (
	"bytes"
	"context"
	"flag"
	"io"
	"strings"
	"testing"

	"github.com/kyleseneker/tinybpf/internal/testutil"
	"github.com/kyleseneker/tinybpf/pipeline"
)

func runCLI(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = Run(context.Background(), args, &out, &errOut)
	return out.String(), errOut.String(), code
}

func testIR(funcName string) string {
	return testutil.SampleIR(funcName)
}

func fakeToolDir(t *testing.T) string {
	t.Helper()
	return testutil.FakeToolDir(t)
}

func fakeLLVMArgs(dir string) []string {
	return testutil.FakeLLVMArgs(dir)
}

func TestMultiStringFlag(t *testing.T) {
	tests := []struct {
		name    string
		inputs  []string
		wantErr bool
		check   func(t *testing.T, m multiStringFlag)
	}{
		{
			name:   "basic usage",
			inputs: []string{"one", "two"},
			check: func(t *testing.T, m multiStringFlag) {
				t.Helper()
				if len(m) != 2 || m[0] != "one" || m[1] != "two" {
					t.Fatalf("unexpected: %v", m)
				}
				if s := m.String(); s != "one,two" {
					t.Fatalf("unexpected String(): %q", s)
				}
			},
		},
		{
			name:    "rejects empty",
			inputs:  []string{""},
			wantErr: true,
		},
		{
			name:    "rejects whitespace",
			inputs:  []string{"   "},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m multiStringFlag
			var lastErr error
			for _, v := range tt.inputs {
				if err := m.Set(v); err != nil {
					lastErr = err
				}
			}
			if tt.wantErr {
				if lastErr == nil {
					t.Fatal("expected error")
				}
				return
			}
			if lastErr != nil {
				t.Fatal(lastErr)
			}
			if tt.check != nil {
				tt.check(t, m)
			}
		})
	}
}

func TestRunExitCodes(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode int
	}{
		{"unknown flag", []string{"--unknown-flag"}, 2},
		{"doctor parse error", []string{"doctor", "--unknown-flag"}, 2},
		{"init unknown flag", []string{"init", "--unknown-flag"}, 2},
		{"init missing name", []string{"init"}, 2},
		{"verify missing input", []string{"verify"}, 2},
		{"verify unknown flag", []string{"verify", "--unknown-flag"}, 2},
		{"unknown subcommand", []string{"notacommand"}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, code := runCLI(t, tt.args...)
			if code != tt.wantCode {
				t.Fatalf("exit code: got %d, want %d", code, tt.wantCode)
			}
		})
	}
}

func TestRunHelp(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode int
	}{
		{"help subcommand", []string{"help"}, 0},
		{"--help flag", []string{"--help"}, 0},
		{"-h flag", []string{"-h"}, 0},
		{"no args", []string{}, 2},
		{"doctor --help", []string{"doctor", "--help"}, 0},
		{"init --help", []string{"init", "--help"}, 0},
		{"init -h", []string{"init", "-h"}, 0},
		{"build --help", []string{"build", "--help"}, 0},
		{"link --help", []string{"link", "--help"}, 0},
		{"verify --help", []string{"verify", "--help"}, 0},
		{"verify -h", []string{"verify", "-h"}, 0},
		{"unknown command shows usage", []string{"--input", "/dev/null"}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, code := runCLI(t, tt.args...)
			if code != tt.wantCode {
				t.Fatalf("exit code: got %d, want %d", code, tt.wantCode)
			}
			if !strings.Contains(stdout+stderr, "Usage:") {
				t.Fatalf("expected 'Usage:' in output, got stdout=%q stderr=%q", stdout, stderr)
			}
		})
	}
}

func TestNewFlagSet(t *testing.T) {
	tests := []struct {
		name        string
		usage       string
		desc        string
		addFlag     bool
		wantContain []string
		wantAbsent  []string
	}{
		{
			name:        "basic usage and description",
			usage:       "tinybpf test [flags]",
			desc:        "Test command.",
			wantContain: []string{"Usage: tinybpf test [flags]", "Test command."},
			wantAbsent:  []string{"Flags:"},
		},
		{
			name:        "includes flags section when flags registered",
			usage:       "tinybpf test [flags]",
			desc:        "Test command.",
			addFlag:     true,
			wantContain: []string{"Usage:", "Flags:", "-myflag"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			fs := newFlagSet(&buf, tt.usage, tt.desc)
			if tt.addFlag {
				fs.String("myflag", "", "A test flag.")
			}
			fs.Usage()
			out := buf.String()
			for _, s := range tt.wantContain {
				if !strings.Contains(out, s) {
					t.Errorf("expected %q in output:\n%s", s, out)
				}
			}
			for _, s := range tt.wantAbsent {
				if strings.Contains(out, s) {
					t.Errorf("unexpected %q in output:\n%s", s, out)
				}
			}
		})
	}
}

func TestParseFlags(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantOK   bool
	}{
		{"no args", nil, 0, true},
		{"valid flag", []string{"-v"}, 0, true},
		{"help flag", []string{"--help"}, 0, false},
		{"unknown flag", []string{"--unknown"}, 2, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			fs.Bool("v", false, "verbose")
			code, ok := parseFlags(fs, tt.args)
			if code != tt.wantCode || ok != tt.wantOK {
				t.Errorf("parseFlags(%v) = (%d, %v), want (%d, %v)",
					tt.args, code, ok, tt.wantCode, tt.wantOK)
			}
		})
	}
}

func TestRunVersion(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		setup       func(t *testing.T)
		wantContain string
	}{
		{
			name:        "version subcommand",
			args:        []string{"version"},
			wantContain: "tinybpf",
		},
		{
			name:        "--version flag",
			args:        []string{"--version"},
			wantContain: "tinybpf",
		},
		{
			name: "shows injected version variable",
			args: []string{"version"},
			setup: func(t *testing.T) {
				t.Helper()
				old := Version
				Version = "v0.1.0-test"
				t.Cleanup(func() { Version = old })
			},
			wantContain: "v0.1.0-test",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup(t)
			}
			stdout, _, code := runCLI(t, tt.args...)
			if code != 0 {
				t.Fatalf("exit code: got %d, want 0", code)
			}
			if !strings.Contains(stdout, tt.wantContain) {
				t.Fatalf("expected %q in output, got: %q", tt.wantContain, stdout)
			}
		})
	}
}

func TestRegisterPipelineFlags(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var cfg pipeline.Config
	var programs, sections multiStringFlag
	var configPath string
	registerPipelineFlags(fs, &cfg, &programs, &sections, &configPath)

	expected := []struct {
		name     string
		defValue string
	}{
		{"config", ""},
		{"output", "bpf.o"},
		{"o", "bpf.o"},
		{"cpu", "v3"},
		{"keep-temp", "false"},
		{"verbose", "false"},
		{"v", "false"},
		{"pass-pipeline", ""},
		{"opt-profile", "default"},
		{"timeout", "30s"},
		{"tmpdir", ""},
		{"btf", "false"},
		{"dump-ir", "false"},
		{"program-type", ""},
		{"program", ""},
		{"section", ""},
		{"llvm-link", ""},
		{"opt", ""},
		{"llc", ""},
		{"llvm-ar", ""},
		{"llvm-objcopy", ""},
		{"pahole", ""},
	}
	for _, tt := range expected {
		t.Run(tt.name, func(t *testing.T) {
			f := fs.Lookup(tt.name)
			if f == nil {
				t.Fatalf("flag %q not registered", tt.name)
			}
			if f.DefValue != tt.defValue {
				t.Errorf("default: got %q, want %q", f.DefValue, tt.defValue)
			}
		})
	}
}

func TestCliErrorf(t *testing.T) {
	tests := []struct {
		name        string
		format      string
		args        []any
		wantCode    int
		wantContain string
	}{
		{
			name:        "basic error",
			format:      "something %s",
			args:        []any{"bad"},
			wantCode:    1,
			wantContain: "error: something bad",
		},
		{
			name:        "no args",
			format:      "plain message",
			wantCode:    1,
			wantContain: "error: plain message",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			code := cliErrorf(&buf, tt.format, tt.args...)
			if code != tt.wantCode {
				t.Errorf("exit code: got %d, want %d", code, tt.wantCode)
			}
			if !strings.Contains(buf.String(), tt.wantContain) {
				t.Errorf("expected %q in output, got: %q", tt.wantContain, buf.String())
			}
		})
	}
}

func TestUsageErrorf(t *testing.T) {
	tests := []struct {
		name        string
		format      string
		args        []any
		wantCode    int
		wantContain []string
	}{
		{
			name:        "shows error and usage",
			format:      "something %s",
			args:        []any{"bad"},
			wantCode:    2,
			wantContain: []string{"error: something bad", "Usage:"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			fs := newFlagSet(&buf, "tinybpf test", "Test description.")
			code := usageErrorf(fs, &buf, tt.format, tt.args...)
			if code != tt.wantCode {
				t.Errorf("exit code: got %d, want %d", code, tt.wantCode)
			}
			out := buf.String()
			for _, s := range tt.wantContain {
				if !strings.Contains(out, s) {
					t.Errorf("expected %q in output:\n%s", s, out)
				}
			}
		})
	}
}
