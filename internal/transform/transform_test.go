package transform

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kyleseneker/tinybpf/internal/ir"
	"github.com/kyleseneker/tinybpf/internal/testutil"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) (ctx context.Context, in, out string, opts Options)
		wantErr string
	}{
		{
			name: "read error",
			setup: func(t *testing.T) (context.Context, string, string, Options) {
				t.Helper()
				return context.Background(), testutil.BadPath("input.ll"), filepath.Join(t.TempDir(), "out.ll"), Options{}
			},
			wantErr: "read input:",
		},
		{
			name: "write error",
			setup: func(t *testing.T) (context.Context, string, string, Options) {
				t.Helper()
				tmp := t.TempDir()
				input := filepath.Join(tmp, "in.ll")
				os.WriteFile(input, []byte("define i32 @my_func(ptr %ctx) {\nentry:\n  ret i32 0\n}\n"), 0o644)
				return context.Background(), input, filepath.Join(input, "out.ll"), Options{Stdout: io.Discard}
			},
			wantErr: "write",
		},
		{
			name: "cancelled context",
			setup: func(t *testing.T) (context.Context, string, string, Options) {
				t.Helper()
				tmp := t.TempDir()
				input := filepath.Join(tmp, "in.ll")
				os.WriteFile(input, []byte("target triple = \"x86_64\"\ndefine i32 @f(ptr %ctx) {\nentry:\n  ret i32 0\n}\n"), 0o644)
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, input, filepath.Join(tmp, "out.ll"), Options{Stdout: io.Discard}
			},
			wantErr: "context canceled",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, in, out, opts := tt.setup(t)
			err := Run(ctx, in, out, opts)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected %q in error, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestTransformLines(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		opts     Options
		contains []string
		absent   []string
		wantErr  string
	}{
		{
			name: "retarget triple",
			input: `target triple = "x86_64-unknown-linux-gnu"

define i32 @my_func(ptr %ctx) {
entry:
  ret i32 0
}`,
			opts:     Options{Stdout: io.Discard},
			contains: []string{`target triple = "bpf"`},
			absent:   []string{`x86_64`},
		},
		{
			name: "strip attributes",
			input: `target triple = "x86_64-unknown-linux-gnu"

define i32 @my_func(ptr %ctx) #0 {
entry:
  ret i32 0
}

attributes #0 = { "target-cpu"="generic" "target-features"="+neon" }`,
			opts:   Options{Stdout: io.Discard},
			absent: []string{`target-cpu`, `target-features`},
		},
		{
			name: "helper rewrite",
			input: `target triple = "x86_64-unknown-linux-gnu"

define i32 @my_func(ptr %ctx) {
entry:
  %0 = call i64 @main.bpfGetCurrentPidTgid(ptr undef)
  ret i32 0
}

declare i64 @main.bpfGetCurrentPidTgid(ptr)`,
			opts:     Options{Stdout: io.Discard},
			contains: []string{"inttoptr (i64 14 to ptr)"},
			absent:   []string{"@main.bpfGetCurrentPidTgid"},
		},
		{
			name: "alloc replacement",
			input: `target triple = "x86_64-unknown-linux-gnu"

define i32 @my_func(ptr %ctx) {
entry:
  %buf = call align 4 dereferenceable(16) ptr @runtime.alloc(i64 16, ptr null, ptr undef)
  ret i32 0
}

declare ptr @runtime.alloc(i64, ptr, ptr)`,
			opts:     Options{Stdout: io.Discard},
			contains: []string{"alloca [16 x i8]", "llvm.memset.p0.i64"},
			absent:   []string{"@runtime.alloc"},
		},
		{
			name: "data section assignment",
			input: `target triple = "x86_64-unknown-linux-gnu"

@my_data = global i32 42, align 4

define i32 @my_func(ptr %ctx) {
entry:
  ret i32 0
}`,
			opts:     Options{Stdout: io.Discard},
			contains: []string{`section ".data"`},
		},
		{
			name: "bss section for zeroinitializer",
			input: `target triple = "x86_64-unknown-linux-gnu"

@my_bss = global [16 x i8] zeroinitializer, align 4

define i32 @my_func(ptr %ctx) {
entry:
  ret i32 0
}`,
			opts:     Options{Stdout: io.Discard},
			contains: []string{`section ".bss"`},
		},
		{
			name: "program section assignment",
			input: `target triple = "x86_64-unknown-linux-gnu"

define i32 @my_func(ptr %ctx) {
entry:
  ret i32 0
}`,
			opts:     Options{Sections: map[string]string{"my_func": "kprobe/sys_open"}, Stdout: io.Discard},
			contains: []string{`section "kprobe/sys_open"`},
		},
		{
			name: "license added",
			input: `target triple = "x86_64-unknown-linux-gnu"

define i32 @my_func(ptr %ctx) {
entry:
  ret i32 0
}`,
			opts:     Options{Stdout: io.Discard},
			contains: []string{`section "license"`, `c"GPL\00"`},
		},
		{
			name: "runtime functions removed",
			input: `target triple = "x86_64-unknown-linux-gnu"

define void @runtime.runMain() {
entry:
  ret void
}

define i32 @my_func(ptr %ctx) {
entry:
  ret i32 0
}`,
			opts:   Options{Stdout: io.Discard},
			absent: []string{"@runtime.runMain"},
		},
		{
			name: "map BTF rewrite",
			input: `target triple = "x86_64-unknown-linux-gnu"

%main.bpfMapDef = type { i32, i32, i32, i32, i32 }

@main.events = global %main.bpfMapDef { i32 27, i32 0, i32 0, i32 16777216, i32 0 }, align 4

define i32 @my_func(ptr %ctx) {
entry:
  ret i32 0
}`,
			opts:     Options{Stdout: io.Discard},
			contains: []string{`section ".maps"`},
		},
		{
			name: "explicit programs filter",
			input: `target triple = "x86_64-unknown-linux-gnu"

define i32 @handler_a(ptr %ctx) {
entry:
  ret i32 0
}

define i32 @handler_b(ptr %ctx) {
entry:
  ret i32 0
}`,
			opts:     Options{Programs: []string{"handler_a"}, Stdout: io.Discard},
			contains: []string{"@handler_a"},
		},
		{
			name: "explicit programs not found",
			input: `target triple = "x86_64-unknown-linux-gnu"

define i32 @my_func(ptr %ctx) {
entry:
  ret i32 0
}`,
			opts:    Options{Programs: []string{"nonexistent"}, Stdout: io.Discard},
			wantErr: "not found in IR",
		},
		{
			name: "verbose mode prints",
			input: `target triple = "x86_64-unknown-linux-gnu"

define i32 @my_func(ptr %ctx) {
entry:
  ret i32 0
}`,
			opts:     Options{Verbose: true, Stdout: io.Discard},
			contains: []string{`target triple = "bpf"`},
		},
		{
			name: "unknown helper error",
			input: `target triple = "x86_64-unknown-linux-gnu"

define i32 @my_func(ptr %ctx) {
entry:
  %0 = call i64 @main.bpfFakeHelper(ptr undef)
  ret i32 0
}

declare i64 @main.bpfFakeHelper(ptr)`,
			opts:    Options{Stdout: io.Discard},
			wantErr: "unknown BPF helper",
		},
		{
			name: "strip map prefix",
			input: `target triple = "x86_64-unknown-linux-gnu"

%main.bpfMapDef = type { i32, i32, i32, i32, i32 }

@main.events = global %main.bpfMapDef { i32 27, i32 0, i32 0, i32 16777216, i32 0 }, align 4

define i32 @my_func(ptr %ctx) {
entry:
  %0 = load ptr, ptr @main.events
  ret i32 0
}`,
			opts:     Options{Stdout: io.Discard},
			contains: []string{"@events"},
			absent:   []string{"@main.events"},
		},
		{
			name: "core access rewrite",
			input: `target triple = "x86_64-unknown-linux-gnu"

%main.bpfCoreTaskStruct = type { i32, i32 }

define i32 @my_func(ptr %ctx) {
entry:
  %0 = getelementptr %main.bpfCoreTaskStruct, ptr %ctx, i32 0, i32 1
  %1 = load i32, ptr %0
  ret i32 %1
}

!0 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfCoreTaskStruct", size: 64, elements: !1)
!1 = !{}`,
			opts:     Options{Stdout: io.Discard},
			contains: []string{"llvm.preserve.struct.access.index"},
		},
		{
			name: "core field exists rewrite",
			input: `target triple = "x86_64-unknown-linux-gnu"

%main.bpfCoreTaskStruct = type { i32, i32 }

define i32 @my_func(ptr %ctx) {
entry:
  %0 = getelementptr i8, ptr %ctx, i64 4
  %1 = call i32 @main.bpfCoreFieldExists(ptr %0, ptr undef)
  ret i32 %1
}

declare i32 @main.bpfCoreFieldExists(ptr, ptr)

!0 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfCoreTaskStruct", size: 64, elements: !1)
!1 = !{!2, !3}
!2 = !DIDerivedType(tag: DW_TAG_member, name: "Pid", size: 32, offset: 0)
!3 = !DIDerivedType(tag: DW_TAG_member, name: "Tgid", size: 32, offset: 32)`,
			opts:     Options{Stdout: io.Discard},
			contains: []string{"llvm.bpf.preserve.field.info"},
			absent:   []string{"@main.bpfCoreFieldExists"},
		},
		{
			name: "core type exists rewrite",
			input: `target triple = "x86_64-unknown-linux-gnu"

%main.bpfCoreTaskStruct = type { i32, i32 }

define i32 @my_func(ptr %ctx) {
entry:
  %0 = call i32 @main.bpfCoreTypeExists(ptr %ctx, ptr undef)
  ret i32 %0
}

declare i32 @main.bpfCoreTypeExists(ptr, ptr)

!0 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfCoreTaskStruct", size: 64, elements: !1)
!1 = !{}`,
			opts:     Options{Stdout: io.Discard},
			contains: []string{"llvm.bpf.preserve.type.info"},
			absent:   []string{"@main.bpfCoreTypeExists"},
		},
		{
			name: "rodata section for constant",
			input: `target triple = "x86_64-unknown-linux-gnu"

@my_const = constant [4 x i8] c"test", align 1

define i32 @my_func(ptr %ctx) {
entry:
  ret i32 0
}`,
			opts:     Options{Stdout: io.Discard},
			contains: []string{`section ".rodata"`},
		},
		{
			name: "core field exists no typedef (metadata-only path)",
			input: `target triple = "x86_64-unknown-linux-gnu"

define i32 @my_func(ptr %ctx) {
entry:
  %0 = getelementptr i8, ptr %ctx, i64 4
  %1 = call i32 @main.bpfCoreFieldExists(ptr %0, ptr undef)
  ret i32 %1
}

declare i32 @main.bpfCoreFieldExists(ptr, ptr)

!0 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfCoreTaskStruct", size: 64, elements: !1)
!1 = !{!2, !3}
!2 = !DIDerivedType(tag: DW_TAG_member, name: "Pid", size: 32, offset: 0)
!3 = !DIDerivedType(tag: DW_TAG_member, name: "Tgid", size: 32, offset: 32)`,
			opts:     Options{Stdout: io.Discard},
			contains: []string{"llvm.bpf.preserve.field.info"},
			absent:   []string{"@main.bpfCoreFieldExists"},
		},
		{
			name: "core field exists non-GEP pointer",
			input: `target triple = "x86_64-unknown-linux-gnu"

%main.bpfCoreTaskStruct = type { i32, i32 }

define i32 @my_func(ptr %ctx) {
entry:
  %1 = call i32 @main.bpfCoreFieldExists(ptr %ctx, ptr undef)
  ret i32 %1
}

declare i32 @main.bpfCoreFieldExists(ptr, ptr)

!0 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfCoreTaskStruct", size: 64, elements: !1)
!1 = !{!2, !3}
!2 = !DIDerivedType(tag: DW_TAG_member, name: "Pid", size: 32, offset: 0)
!3 = !DIDerivedType(tag: DW_TAG_member, name: "Tgid", size: 32, offset: 32)`,
			opts:     Options{Stdout: io.Discard},
			contains: []string{"llvm.bpf.preserve.field.info"},
			absent:   []string{"@main.bpfCoreFieldExists"},
		},
		{
			name: "core field exists non-GEP fallback (no typedef)",
			input: `target triple = "x86_64-unknown-linux-gnu"

define i32 @my_func(ptr %ctx) {
entry:
  %1 = call i32 @main.bpfCoreFieldExists(ptr %ctx, ptr undef)
  ret i32 %1
}

declare i32 @main.bpfCoreFieldExists(ptr, ptr)`,
			opts:     Options{Stdout: io.Discard},
			contains: []string{"llvm.bpf.preserve.field.info"},
			absent:   []string{"@main.bpfCoreFieldExists"},
		},
		{
			name: "core field exists fallback type (no typedef, no metadata)",
			input: `target triple = "x86_64-unknown-linux-gnu"

define i32 @my_func(ptr %ctx) {
entry:
  %0 = getelementptr i8, ptr %ctx, i64 4
  %1 = call i32 @main.bpfCoreFieldExists(ptr %0, ptr undef)
  ret i32 %1
}

declare i32 @main.bpfCoreFieldExists(ptr, ptr)`,
			opts:     Options{Stdout: io.Discard},
			contains: []string{"llvm.bpf.preserve.field.info", "__tinybpfCoreFallback"},
			absent:   []string{"@main.bpfCoreFieldExists"},
		},
		{
			name: "dump dir writes snapshots",
			input: `target triple = "x86_64-unknown-linux-gnu"

define i32 @my_func(ptr %ctx) {
entry:
  ret i32 0
}`,
			opts: Options{Stdout: io.Discard},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := strings.Split(tt.input, "\n")
			got, err := TransformLines(context.Background(), lines, tt.opts)
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
			text := strings.Join(got, "\n")
			for _, s := range tt.contains {
				if !strings.Contains(text, s) {
					t.Errorf("missing %q in output:\n%s", s, text)
				}
			}
			for _, s := range tt.absent {
				if strings.Contains(text, s) {
					t.Errorf("should not contain %q in output", s)
				}
			}
		})
	}
}

func TestDump(t *testing.T) {
	tests := []struct {
		name    string
		dir     string
		verbose bool
		check   func(t *testing.T, dir string, buf *bytes.Buffer)
	}{
		{
			name: "no-op when dir empty",
			dir:  "",
			check: func(t *testing.T, _ string, _ *bytes.Buffer) {
				t.Helper()
			},
		},
		{
			name:    "writes file",
			verbose: true,
			check: func(t *testing.T, dir string, buf *bytes.Buffer) {
				t.Helper()
				entries, err := os.ReadDir(dir)
				if err != nil {
					t.Fatal(err)
				}
				if len(entries) != 1 {
					t.Fatalf("expected 1 file, got %d", len(entries))
				}
				if !strings.Contains(entries[0].Name(), "01-test-stage.ll") {
					t.Errorf("unexpected filename: %s", entries[0].Name())
				}
				if !strings.Contains(buf.String(), "[dump-ir]") {
					t.Error("expected verbose output")
				}
			},
		},
		{
			name:    "bad dir logs error in verbose",
			dir:     "/nonexistent/path/that/does/not/exist",
			verbose: true,
			check: func(t *testing.T, _ string, buf *bytes.Buffer) {
				t.Helper()
				if !strings.Contains(buf.String(), "failed to write") {
					t.Error("expected error log in verbose mode")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := tt.dir
			if dir == "" && tt.name == "writes file" {
				dir = t.TempDir()
			}
			var buf bytes.Buffer
			d := newModuleDumper(dir, tt.verbose, &buf)

			m := mustParseMinimalModule(t)
			d.dump("test-stage", m)

			tt.check(t, dir, &buf)
		})
	}
}

func mustParseMinimalModule(t *testing.T) *ir.Module {
	t.Helper()
	src := "target triple = \"bpf\"\n\ndefine i32 @f(ptr %ctx) {\nentry:\n  ret i32 0\n}\n"
	mod, err := ir.Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	return mod
}
