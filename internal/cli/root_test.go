package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runCLI runs the CLI with the given arguments and returns the stdout, stderr, and exit code.
func runCLI(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = Run(context.Background(), args, &out, &errOut)
	return out.String(), errOut.String(), code
}

// testIR returns minimal valid LLVM IR containing a single function.
func testIR(funcName string) string {
	return fmt.Sprintf(`target datalayout = "e-m:o-p270:32:32"
target triple = "arm64-apple-macosx11.0.0"

define i32 @%s(ptr %%ctx) {
entry:
  ret i32 0
}
`, funcName)
}

// fakeToolDir creates a temporary directory containing fake llvm-link, opt,
// and llc scripts that are sufficient for the pipeline to produce a valid ELF.
func fakeToolDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "tools")
	os.MkdirAll(dir, 0o755)

	copyTool := "#!/bin/sh\n" + `
out=""; in=""
for arg in "$@"; do case "$arg" in -o) n=1;; -passes=*|-S|-march=*|-mcpu=*|-filetype=*) ;; *) if [ "${n:-}" = 1 ]; then out="$arg"; n=0; else in="$arg"; fi;; esac; done
[ -n "$in" ] && [ -n "$out" ] && cp "$in" "$out"; exit 0`
	os.WriteFile(filepath.Join(dir, "llvm-link"), []byte(copyTool), 0o755)
	os.WriteFile(filepath.Join(dir, "opt"), []byte(copyTool), 0o755)

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
	os.WriteFile(filepath.Join(dir, "llc"), []byte(llcScript), 0o755)

	return dir
}

// fakeLLVMArgs returns CLI flags pointing at the fake tools in dir.
func fakeLLVMArgs(dir string) []string {
	return []string{
		"--llvm-link", filepath.Join(dir, "llvm-link"),
		"--opt", filepath.Join(dir, "opt"),
		"--llc", filepath.Join(dir, "llc"),
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
		{
			"pipeline error (missing tool)",
			[]string{"--input", "/dev/null", "--output", "/tmp/test-output.o", "--llvm-link", "/does/not/exist/llvm-link"},
			1,
		},
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
		{"legacy link --help", []string{"--input", "/dev/null", "--help"}, 0},
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
			stdout, _, code := runCLI(t, tt.args...)
			if code != 0 {
				t.Fatalf("exit code: got %d, want 0", code)
			}
			if !strings.Contains(stdout, "tinybpf") {
				t.Fatalf("expected version output, got: %q", stdout)
			}
		})
	}
}

func TestRunVersionShowsVariable(t *testing.T) {
	old := Version
	Version = "v0.1.0-test"
	defer func() { Version = old }()

	stdout, _, code := runCLI(t, "version")
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}
	if !strings.Contains(stdout, "v0.1.0-test") {
		t.Fatalf("expected injected version, got: %q", stdout)
	}
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
		{"valid entries", []string{"handle_connect=kprobe/sys_connect", "xdp_filter=xdp"}, map[string]string{"handle_connect": "kprobe/sys_connect", "xdp_filter": "xdp"}},
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
