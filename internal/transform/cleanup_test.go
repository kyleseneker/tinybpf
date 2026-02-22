package transform

import (
	"strings"
	"testing"
)

func FuzzCleanup(f *testing.F) {
	f.Add(`; Function Attrs: nounwind
declare void @unused_func()

declare void @llvm.memset.p0.i64(ptr, i8, i64, i1)

define i32 @my_func() #4 {
entry:
  call void @llvm.memset.p0.i64(ptr null, i8 0, i64 16, i1 false)
  ret i32 0
}

attributes #0 = { nounwind }
attributes #4 = { nounwind }`)
	f.Add(`@some_global = global i32 42
define void @foo() {
  ret void
}`)
	f.Add(`; Function Attrs: nounwind`)
	f.Add(`just some text with no IR constructs`)

	f.Fuzz(func(t *testing.T, ir string) {
		if len(ir) > 1<<16 {
			return
		}
		lines := strings.Split(ir, "\n")
		cleanup(lines)
	})
}

func TestCleanup(t *testing.T) {
	tests := []struct {
		name        string
		ir          string
		wantContain []string
		notContain  []string
	}{
		{
			name: "removes unused declares and attrs",
			ir: `
; Function Attrs: nounwind
declare void @unused_func()

declare void @llvm.memset.p0.i64(ptr, i8, i64, i1)

define i32 @my_func() #4 {
entry:
  call void @llvm.memset.p0.i64(ptr null, i8 0, i64 16, i1 false)
  ret i32 0
}

attributes #0 = { nounwind }
attributes #4 = { nounwind }
`,
			wantContain: []string{"@llvm.memset", "attributes #4"},
			notContain:  []string{"@unused_func", "attributes #0"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := strings.Split(strings.TrimSpace(tt.ir), "\n")
			got := cleanup(input)
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
		})
	}
}
