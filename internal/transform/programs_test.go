package transform

import (
	"io"
	"strings"
	"testing"
)

func FuzzExtractPrograms(f *testing.F) {
	f.Add(`define i32 @handle_connect(ptr %ctx) {
entry:
  ret i32 0
}`)
	f.Add(`define void @__dynamic_loader() {
entry:
  ret void
}

define i32 @my_prog(ptr %ctx) {
entry:
  ret i32 0
}`)
	f.Add(`define void @runtime.runMain() {
entry:
  ret void
}`)
	f.Add(`no define blocks at all`)
	f.Add(`define i32 @foo() {
entry:
  ret i32 0
}

define i32 @bar() {
entry:
  ret i32 1
}`)

	f.Fuzz(func(t *testing.T, ir string) {
		if len(ir) > 1<<16 {
			return
		}
		lines := strings.Split(ir, "\n")
		extractPrograms(lines, nil, false, io.Discard)
	})
}

func TestExtractPrograms(t *testing.T) {
	base := strings.Split(strings.TrimSpace(`
source_filename = "main"

@runtime.main_argv = internal global ptr null

define void @__dynamic_loader() {
entry:
  ret void
}

define void @tinygo_signal_handler(i32 %s) {
entry:
  ret void
}

define i32 @handle_connect(ptr %ctx) #4 !dbg !0 {
entry:
    #dbg_value(ptr %ctx, !1, !DIExpression(), !2)
  %0 = icmp eq ptr %ctx, null, !dbg !3
  ret i32 0, !dbg !4
}

declare void @runtime.alloc(i64, ptr, ptr)

!llvm.dbg.cu = !{!0}
!0 = distinct !DISubprogram(name: "test")
!1 = !DILocalVariable(name: "ctx")
!2 = !DILocation(line: 1)
!3 = !DILocation(line: 2)
!4 = !DILocation(line: 3)
`), "\n")

	t.Run("auto-detect removes runtime funcs", func(t *testing.T) {
		got, err := extractPrograms(base, nil, false, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		text := strings.Join(got, "\n")
		for _, removed := range []string{"__dynamic_loader", "tinygo_signal_handler", "runtime.main_argv"} {
			if strings.Contains(text, removed) {
				t.Errorf("%s not removed", removed)
			}
		}
		if !strings.Contains(text, "handle_connect") {
			t.Error("program handle_connect was removed")
		}
		if !strings.Contains(text, "!dbg") {
			t.Error("inline debug references should be preserved")
		}
	})

	t.Run("explicit program list", func(t *testing.T) {
		input := strings.Split(strings.TrimSpace(`
define i32 @foo() {
entry:
  ret i32 0
}

define i32 @bar() {
entry:
  ret i32 1
}
`), "\n")
		got, err := extractPrograms(input, []string{"bar"}, false, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		text := strings.Join(got, "\n")
		if strings.Contains(text, "@foo") {
			t.Error("@foo should have been removed")
		}
		if !strings.Contains(text, "@bar") {
			t.Error("@bar should have been kept")
		}
	})

	t.Run("no programs found", func(t *testing.T) {
		input := strings.Split("define void @runtime.runMain() {\nentry:\n  ret void\n}\n", "\n")
		_, err := extractPrograms(input, nil, false, io.Discard)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("explicit name not found", func(t *testing.T) {
		input := strings.Split(strings.TrimSpace(`
define i32 @foo() {
entry:
  ret i32 0
}
`), "\n")
		_, err := extractPrograms(input, []string{"nonexistent"}, false, io.Discard)
		if err == nil {
			t.Fatal("expected error for missing program name")
		}
		if !strings.Contains(err.Error(), "not found in IR:") {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(err.Error(), "nonexistent") {
			t.Fatalf("error should name the missing program: %v", err)
		}
		if !strings.Contains(err.Error(), "foo") {
			t.Fatalf("error should list available functions: %v", err)
		}
	})

	t.Run("verbose", func(t *testing.T) {
		input := strings.Split("define i32 @my_program(ptr %ctx) {\nentry:\n  ret i32 0\n}\n", "\n")
		var buf strings.Builder
		got, err := extractPrograms(input, nil, true, &buf)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(strings.Join(got, "\n"), "my_program") {
			t.Error("expected program to be kept")
		}
		if !strings.Contains(buf.String(), "keeping program") {
			t.Error("expected verbose output")
		}
	})
}
