package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"testing"
)

func TestRunExitCodes(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode int
	}{
		{"no args (missing input)", []string{}, 2},
		{"unknown flag", []string{"--unknown-flag"}, 2},
		{"doctor parse error", []string{"doctor", "--unknown-flag"}, 2},
		{
			"pipeline error (missing tool)",
			[]string{"--input", "/dev/null", "--output", "/tmp/test-output.o", "--llvm-link", "/does/not/exist/llvm-link"},
			1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := Run(context.Background(), tt.args, &out, &errOut)
			if code != tt.wantCode {
				t.Fatalf("expected exit code %d, got %d, stderr=%s", tt.wantCode, code, errOut.String())
			}
		})
	}
}

func TestRunVersion(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"version subcommand", []string{"version"}},
		{"--version flag", []string{"--version"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			code := Run(context.Background(), tt.args, &out, nil)
			if code != 0 {
				t.Fatalf("expected exit code 0, got %d", code)
			}
			if !strings.Contains(out.String(), "tinybpf") {
				t.Fatalf("expected version output, got: %q", out.String())
			}
		})
	}
}

func TestRunVersionShowsVariable(t *testing.T) {
	old := Version
	Version = "v0.1.0-test"
	defer func() { Version = old }()

	var out bytes.Buffer
	code := Run(context.Background(), []string{"version"}, &out, nil)
	if code != 0 {
		t.Fatal("expected exit code 0")
	}
	if !strings.Contains(out.String(), "v0.1.0-test") {
		t.Fatalf("expected injected version, got: %q", out.String())
	}
}

func TestRunDoctor(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		dir := t.TempDir()
		makeCliTool := func(name string) string {
			p := filepath.Join(dir, name)
			os.WriteFile(p, []byte("#!/bin/sh\necho ok\n"), 0o755)
			return p
		}
		link := makeCliTool("llvm-link")
		opt := makeCliTool("opt")
		llc := makeCliTool("llc")

		var out, errOut bytes.Buffer
		code := Run(context.Background(), []string{"doctor", "--llvm-link", link, "--opt", opt, "--llc", llc}, &out, &errOut)
		if code != 0 {
			t.Fatalf("expected exit code 0, got %d, stderr=%s", code, errOut.String())
		}
	})

	t.Run("missing tool", func(t *testing.T) {
		var out, errOut bytes.Buffer
		code := Run(context.Background(), []string{"doctor", "--llvm-link", "/does/not/exist/llvm-link"}, &out, &errOut)
		if code != 1 {
			t.Fatalf("expected exit code 1, got %d", code)
		}
		if !strings.Contains(errOut.String(), "llvm-link") {
			t.Errorf("expected error mentioning llvm-link, got: %s", errOut.String())
		}
	})
}

func TestMultiStringFlag(t *testing.T) {
	t.Run("basic usage", func(t *testing.T) {
		var m multiStringFlag
		m.Set("one")
		m.Set("two")
		if len(m) != 2 || m[0] != "one" || m[1] != "two" {
			t.Fatalf("unexpected: %v", m)
		}
		if s := m.String(); s != "one,two" {
			t.Fatalf("unexpected String(): %q", s)
		}
	})

	t.Run("rejects empty", func(t *testing.T) {
		var m multiStringFlag
		for _, v := range []string{"", "   "} {
			if err := m.Set(v); err == nil {
				t.Fatalf("expected error for %q", v)
			}
		}
	})
}

func TestParseSectionFlags(t *testing.T) {
	tests := []struct {
		name  string
		flags []string
		want  map[string]string
	}{
		{"nil", nil, nil},
		{"valid entries", []string{"handle_connect=kprobe/sys_connect", "probe=xdp"}, map[string]string{"handle_connect": "kprobe/sys_connect", "probe": "xdp"}},
		{"malformed skipped", []string{"no-equals", "valid=section"}, map[string]string{"valid": "section"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := parseSectionFlags(tt.flags)
			if tt.want == nil {
				if m != nil {
					t.Fatalf("expected nil, got %v", m)
				}
				return
			}
			for k, v := range tt.want {
				if m[k] != v {
					t.Fatalf("key %q: got %q, want %q", k, m[k], v)
				}
			}
		})
	}
}

func TestRunLinkConfig(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		exists   bool
		wantCode int
		wantErr  string
	}{
		{
			name:     "missing config file",
			exists:   false,
			wantCode: 1,
			wantErr:  "reading config",
		},
		{
			name:     "invalid pass in config",
			json:     `{"custom_passes": ["-inline;rm"]}`,
			exists:   true,
			wantCode: 1,
		},
		{
			name:     "valid config (pipeline still fails due to missing tool)",
			json:     `{"custom_passes": ["inline", "dse"]}`,
			exists:   true,
			wantCode: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp := t.TempDir()
			cfgPath := filepath.Join(tmp, "linker-config.json")
			if tt.exists {
				os.WriteFile(cfgPath, []byte(tt.json), 0o644)
			} else {
				cfgPath = "/does/not/exist/linker-config.json"
			}

			var out, errOut bytes.Buffer
			code := Run(context.Background(), []string{
				"--input", "/dev/null",
				"--output", filepath.Join(tmp, "out.o"),
				"--llvm-link", "/does/not/exist/llvm-link",
				"--config", cfgPath,
			}, &out, &errOut)
			if code != tt.wantCode {
				t.Fatalf("expected exit code %d, got %d", tt.wantCode, code)
			}
			if tt.wantErr != "" && !strings.Contains(errOut.String(), tt.wantErr) {
				t.Fatalf("expected %q in stderr, got: %s", tt.wantErr, errOut.String())
			}
		})
	}
}

func TestStartProfiling(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		base := filepath.Join(t.TempDir(), "test")
		var w bytes.Buffer

		cleanup, err := startProfiling(base, &w)
		if err != nil {
			t.Fatal(err)
		}
		cleanup()

		for _, suffix := range []string{".cpu.prof", ".mem.prof"} {
			if _, err := os.Stat(base + suffix); err != nil {
				t.Fatalf("%s not created: %v", suffix, err)
			}
		}
		if !strings.Contains(w.String(), "cpu profile:") || !strings.Contains(w.String(), "memory profile:") {
			t.Fatalf("expected profile messages, got: %s", w.String())
		}
	})

	t.Run("bad path", func(t *testing.T) {
		_, err := startProfiling("/does/not/exist/prof", &bytes.Buffer{})
		if err == nil {
			t.Fatal("expected error for bad path")
		}
	})

	t.Run("CPU already running", func(t *testing.T) {
		tmp := t.TempDir()
		f, _ := os.Create(filepath.Join(tmp, "block.prof"))
		defer f.Close()
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()

		_, err := startProfiling(filepath.Join(tmp, "second"), &bytes.Buffer{})
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "CPU profile") {
			t.Fatalf("expected CPU profile error, got: %v", err)
		}
	})

	t.Run("memory profile create error", func(t *testing.T) {
		tmp := t.TempDir()
		var w bytes.Buffer

		cleanup, err := startProfiling(filepath.Join(tmp, "test"), &w)
		if err != nil {
			t.Fatal(err)
		}

		os.Chmod(tmp, 0o500)
		defer os.Chmod(tmp, 0o700)
		cleanup()

		if !strings.Contains(w.String(), "warning: memory profile:") {
			t.Fatalf("expected memory profile warning, got: %s", w.String())
		}
	})
}

func TestRunLinkWithProfile(t *testing.T) {
	tmp := t.TempDir()
	profBase := filepath.Join(tmp, "prof")

	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{
		"--input", "/dev/null",
		"--output", filepath.Join(tmp, "out.o"),
		"--llvm-link", "/does/not/exist/llvm-link",
		"--profile", profBase,
	}, &out, &errOut)
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if _, err := os.Stat(profBase + ".cpu.prof"); err != nil {
		t.Fatalf("cpu profile not created: %v", err)
	}
}

func TestRunLinkProfileStartFailure(t *testing.T) {
	tmp := t.TempDir()
	f, _ := os.Create(filepath.Join(tmp, "block.prof"))
	defer f.Close()
	pprof.StartCPUProfile(f)
	defer pprof.StopCPUProfile()

	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{
		"--input", "/dev/null",
		"--output", filepath.Join(tmp, "out.o"),
		"--llvm-link", "/does/not/exist/llvm-link",
		"--profile", filepath.Join(tmp, "prof"),
	}, &out, &errOut)
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(errOut.String(), "warning: profiling failed to start") {
		t.Fatalf("expected profiling warning, got: %s", errOut.String())
	}
}

func TestRunLinkFullSuccess(t *testing.T) {
	tmp := t.TempDir()
	toolDir := filepath.Join(tmp, "tools")
	os.MkdirAll(toolDir, 0o755)

	irContent := `target datalayout = "e-m:o-p270:32:32"
target triple = "arm64-apple-macosx11.0.0"

define i32 @handle_connect(ptr %ctx) {
entry:
  ret i32 0
}
`
	input := filepath.Join(tmp, "input.ll")
	os.WriteFile(input, []byte(irContent), 0o644)

	copyTool := "#!/bin/sh\n" + `
out=""; in=""
for arg in "$@"; do case "$arg" in -o) n=1;; -passes=*|-S|-march=*|-mcpu=*|-filetype=*) ;; *) if [ "${n:-}" = 1 ]; then out="$arg"; n=0; else in="$arg"; fi;; esac; done
[ -n "$in" ] && [ -n "$out" ] && cp "$in" "$out"; exit 0`
	os.WriteFile(filepath.Join(toolDir, "llvm-link"), []byte(copyTool), 0o755)
	os.WriteFile(filepath.Join(toolDir, "opt"), []byte(copyTool), 0o755)

	llcScript := "#!/bin/sh\n" + `
out=""
for arg in "$@"; do case "$arg" in -o) n=1;; *) [ "${n:-}" = 1 ] && { out="$arg"; n=0; };; esac; done
python3 -c "
import struct,sys
h=bytearray(64);h[0:4]=b'\x7fELF';h[4]=2;h[5]=1;h[6]=1
struct.pack_into('<H',h,16,1);struct.pack_into('<H',h,18,247);struct.pack_into('<I',h,20,1)
struct.pack_into('<H',h,52,64);struct.pack_into('<H',h,58,64)
c=b'\x95\x00\x00\x00\x00\x00\x00\x00'
st=b'\x00test\x00\x00\x00\x00'
ns=b'\x00'*24;rs=struct.pack('<IBBHQQ',1,18,0,0,0,0)
ss=b'\x00.text\x00.symtab\x00.strtab\x00.shstrtab\x00\x00\x00\x00'
o=64;d=c;sto=o+len(d);d+=st;syo=o+len(d);d+=ns+rs;sso=o+len(d);d+=ss;so=o+len(d)
def s(n,t,f,off,sz,l=0,i=0,e=0):
 r=bytearray(64);struct.pack_into('<I',r,0,n);struct.pack_into('<I',r,4,t);struct.pack_into('<Q',r,8,f)
 struct.pack_into('<Q',r,24,off);struct.pack_into('<Q',r,32,sz);struct.pack_into('<I',r,40,l)
 struct.pack_into('<I',r,44,i);struct.pack_into('<Q',r,48,8);struct.pack_into('<Q',r,56,e);return bytes(r)
sh=s(0,0,0,0,0)+s(1,1,6,o,len(c))+s(7,3,0,sto,len(st))+s(15,2,0,syo,48,2,1,24)+s(23,3,0,sso,len(ss))
struct.pack_into('<Q',h,40,so);struct.pack_into('<H',h,60,5);struct.pack_into('<H',h,62,4)
sys.stdout.buffer.write(bytes(h)+d+sh)" > "$out"
exit 0`
	os.WriteFile(filepath.Join(toolDir, "llc"), []byte(llcScript), 0o755)

	output := filepath.Join(tmp, "out.o")
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{
		"--input", input,
		"--output", output,
		"--llvm-link", filepath.Join(toolDir, "llvm-link"),
		"--opt", filepath.Join(toolDir, "opt"),
		"--llc", filepath.Join(toolDir, "llc"),
		"--verbose",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "wrote") {
		t.Fatalf("expected 'wrote' output, got: %s", out.String())
	}
	if !strings.Contains(out.String(), "intermediates:") {
		t.Fatalf("expected 'intermediates:' in verbose output, got: %s", out.String())
	}
}
