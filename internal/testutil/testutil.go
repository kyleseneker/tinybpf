// Package testutil provides shared, portable test helpers for internal packages.
package testutil

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// CopyToolScript is a shell script that copies its input file to its output
// file, ignoring LLVM-style flags. Suitable for faking llvm-link and opt.
const CopyToolScript = `
out=""; in=""
for arg in "$@"; do case "$arg" in -o) n=1;; -passes=*|-S|-march=*|-mcpu=*|-filetype=*) ;; *) if [ "${n:-}" = 1 ]; then out="$arg"; n=0; else in="$arg"; fi;; esac; done
[ -n "$in" ] && [ -n "$out" ] && cp "$in" "$out"; exit 0`

// LLCELFScript is a shell script that produces a minimal valid BPF ELF
// object at its -o output path. Suitable for faking llc.
const LLCELFScript = `
out=""
for arg in "$@"; do case "$arg" in -o) n=1;; *) [ "${n:-}" = 1 ] && { out="$arg"; n=0; };; esac; done
python3 -c "
import struct,sys
h=bytearray(64);h[0:4]=b'\\x7fELF';h[4]=2;h[5]=1;h[6]=1
struct.pack_into('<H',h,16,1);struct.pack_into('<H',h,18,247);struct.pack_into('<I',h,20,1)
struct.pack_into('<H',h,52,64);struct.pack_into('<H',h,58,64)
c=b'\\x95\\x00\\x00\\x00\\x00\\x00\\x00\\x00'
st=b'\\x00test\\x00\\x00\\x00\\x00'
ns=b'\\x00'*24;rs=struct.pack('<IBBHQQ',1,18,0,0,0,0)
ss=b'\\x00.text\\x00.symtab\\x00.strtab\\x00.shstrtab\\x00\\x00\\x00\\x00'
o=64;d=c;sto=o+len(d);d+=st;syo=o+len(d);d+=ns+rs;sso=o+len(d);d+=ss;so=o+len(d)
def s(n,t,f,off,sz,l=0,i=0,e=0):
 r=bytearray(64);struct.pack_into('<I',r,0,n);struct.pack_into('<I',r,4,t);struct.pack_into('<Q',r,8,f)
 struct.pack_into('<Q',r,24,off);struct.pack_into('<Q',r,32,sz);struct.pack_into('<I',r,40,l)
 struct.pack_into('<I',r,44,i);struct.pack_into('<Q',r,48,8);struct.pack_into('<Q',r,56,e);return bytes(r)
sh=s(0,0,0,0,0)+s(1,1,6,o,len(c))+s(7,3,0,sto,len(st))+s(15,2,0,syo,48,2,1,24)+s(23,3,0,sso,len(ss))
struct.pack_into('<Q',h,40,so);struct.pack_into('<H',h,60,5);struct.pack_into('<H',h,62,4)
sys.stdout.buffer.write(bytes(h)+d+sh)" > "$out"
exit 0`

// MakeFakeTool creates an executable shell script in dir with the given name
// and body. Returns the absolute path to the created script.
func MakeFakeTool(t *testing.T, dir, name, script string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil { //nolint:gosec // test executables need 0755
		t.Fatal(err)
	}
	return path
}

// FakeToolDir creates a temp directory populated with fake llvm-link, opt, and
// llc executables that pass through or generate minimal valid BPF ELF output.
func FakeToolDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "tools")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	MakeFakeTool(t, dir, "llvm-link", CopyToolScript)
	MakeFakeTool(t, dir, "opt", CopyToolScript)
	MakeFakeTool(t, dir, "llc", LLCELFScript)
	return dir
}

// FakeLLVMArgs returns CLI flag arguments pointing at fake tools in dir.
func FakeLLVMArgs(dir string) []string {
	return []string{
		"--llvm-link", filepath.Join(dir, "llvm-link"),
		"--opt", filepath.Join(dir, "opt"),
		"--llc", filepath.Join(dir, "llc"),
	}
}

// SampleIR returns minimal LLVM IR with a single BPF-compatible function.
func SampleIR(funcName string) string {
	return fmt.Sprintf(`target datalayout = "e-m:o-p270:32:32"
target triple = "arm64-apple-macosx11.0.0"

define i32 @%s(ptr %%ctx) {
entry:
  ret i32 0
}
`, funcName)
}

// BadPath returns a path that is guaranteed not to exist on any platform.
func BadPath(segments ...string) string {
	parts := append([]string{os.DevNull, "impossible"}, segments...)
	return filepath.Join(parts...)
}
