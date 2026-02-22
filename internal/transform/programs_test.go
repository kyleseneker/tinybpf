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

var extractBaseIR = `
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
`

func TestExtractPrograms(t *testing.T) {
	tests := []struct {
		name        string
		ir          string
		programs    []string
		verbose     bool
		wantContain []string
		notContain  []string
		wantErr     string
		check       func(t *testing.T, text string, buf string)
	}{
		{
			name:     "auto-detect removes runtime funcs",
			ir:       extractBaseIR,
			programs: nil,
			wantContain: []string{
				"handle_connect",
				"!dbg",
			},
			notContain: []string{
				"__dynamic_loader",
				"tinygo_signal_handler",
				"runtime.main_argv",
			},
		},
		{
			name: "explicit program list",
			ir: `
define i32 @foo() {
entry:
  ret i32 0
}

define i32 @bar() {
entry:
  ret i32 1
}
`,
			programs:    []string{"bar"},
			wantContain: []string{"@bar"},
			notContain:  []string{"@foo"},
		},
		{
			name:     "no programs found",
			ir:       "define void @runtime.runMain() {\nentry:\n  ret void\n}\n",
			programs: nil,
			wantErr:  "no program functions found",
		},
		{
			name: "explicit name not found",
			ir: `
define i32 @foo() {
entry:
  ret i32 0
}
`,
			programs: []string{"nonexistent"},
			wantErr:  "not found in IR:",
		},
		{
			name:        "verbose",
			ir:          "define i32 @my_program(ptr %ctx) {\nentry:\n  ret i32 0\n}\n",
			verbose:     true,
			wantContain: []string{"my_program"},
			check: func(t *testing.T, _ string, buf string) {
				t.Helper()
				if !strings.Contains(buf, "keeping program") {
					t.Error("expected verbose output")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := strings.Split(strings.TrimSpace(tt.ir), "\n")
			var buf strings.Builder
			w := io.Discard
			if tt.verbose {
				w = &buf
			}
			got, err := extractPrograms(input, tt.programs, tt.verbose, w)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q missing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}

			text := strings.Join(got, "\n")
			for _, want := range tt.wantContain {
				if !strings.Contains(text, want) {
					t.Errorf("output missing %q", want)
				}
			}
			for _, bad := range tt.notContain {
				if strings.Contains(text, bad) {
					t.Errorf("output should not contain %q", bad)
				}
			}
			if tt.check != nil {
				tt.check(t, text, buf.String())
			}
		})
	}
}
