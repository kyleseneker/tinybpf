package transform

import (
	"io"
	"strings"
	"testing"
)

func TestExtractProbes(t *testing.T) {
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
		got, err := extractProbes(base, nil, false, io.Discard)
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
			t.Error("probe handle_connect was removed")
		}
		if !strings.Contains(text, "!dbg") {
			t.Error("inline debug references should be preserved")
		}
	})

	t.Run("explicit probe list", func(t *testing.T) {
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
		got, err := extractProbes(input, []string{"bar"}, false, io.Discard)
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

	t.Run("no probes found", func(t *testing.T) {
		input := strings.Split("define void @runtime.runMain() {\nentry:\n  ret void\n}\n", "\n")
		_, err := extractProbes(input, nil, false, io.Discard)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("verbose", func(t *testing.T) {
		input := strings.Split("define i32 @my_probe(ptr %ctx) {\nentry:\n  ret i32 0\n}\n", "\n")
		var buf strings.Builder
		got, err := extractProbes(input, nil, true, &buf)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(strings.Join(got, "\n"), "my_probe") {
			t.Error("expected probe to be kept")
		}
		if !strings.Contains(buf.String(), "keeping probe") {
			t.Error("expected verbose output")
		}
	})
}
