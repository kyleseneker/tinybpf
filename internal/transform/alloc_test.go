package transform

import (
	"strings"
	"testing"
)

func FuzzReplaceAlloc(f *testing.F) {
	f.Add(`define i32 @my_func(ptr %ctx) {
entry:
  %buf = call align 4 dereferenceable(16) ptr @runtime.alloc(i64 16, ptr nonnull inttoptr (i64 3 to ptr), ptr undef) #7
  ret i32 0
}`)
	f.Add(`define i32 @my_func(ptr %ctx) {
  %buf = call align 4 dereferenceable(16) ptr @runtime.alloc(i64 16, ptr nonnull inttoptr (i64 3 to ptr), ptr undef) #7
  ret i32 0
}`)
	f.Add(`define i32 @my_func(ptr %ctx) {
entry:
  ret i32 0
}`)
	f.Add(`just some text with no define blocks`)
	f.Add(`define i32 @f() {
entry:
  %a = call align 4 dereferenceable(8) ptr @runtime.alloc(i64 8, ptr null, ptr undef)
  %b = call align 4 dereferenceable(32) ptr @runtime.alloc(i64 32, ptr null, ptr undef)
  ret i32 0
}`)

	f.Fuzz(func(t *testing.T, ir string) {
		if len(ir) > 1<<16 {
			return
		}
		lines := strings.Split(ir, "\n")
		replaceAlloc(lines)
	})
}

func runReplaceAlloc(t *testing.T, ir string) string {
	t.Helper()
	input := strings.Split(strings.TrimSpace(ir), "\n")
	got, err := replaceAlloc(input)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(got, "\n")
}

func TestReplaceAlloc(t *testing.T) {
	tests := []struct {
		name        string
		ir          string
		wantContain []string
		notContain  []string
		check       func(t *testing.T, text string)
	}{
		{
			name: "single alloc",
			ir: `
define i32 @my_func(ptr %ctx) {
entry:
  %0 = icmp eq ptr %ctx, null
  br i1 %0, label %done, label %work

work:
  %buf = call align 4 dereferenceable(16) ptr @runtime.alloc(i64 16, ptr nonnull inttoptr (i64 3 to ptr), ptr undef) #7
  ret i32 1

done:
  ret i32 0
}
`,
			wantContain: []string{
				"%buf = alloca [16 x i8], align 4",
				"llvm.memset.p0.i64(ptr align 4 %buf, i8 0, i64 16, i1 false)",
				"declare void @llvm.memset.p0.i64",
			},
			notContain: []string{"@runtime.alloc"},
			check: func(t *testing.T, text string) {
				t.Helper()
				allocaIdx := strings.Index(text, "%buf = alloca")
				entryCodeIdx := strings.Index(text, "%0 = icmp")
				if allocaIdx < 0 || entryCodeIdx < 0 || allocaIdx > entryCodeIdx {
					t.Error("alloca not placed before existing entry block code")
				}
			},
		},
		{
			name: "multiple allocs",
			ir: `
define i32 @my_func(ptr %ctx) {
entry:
  br label %work

work:
  %sa = call align 4 dereferenceable(16) ptr @runtime.alloc(i64 16, ptr nonnull inttoptr (i64 3 to ptr), ptr undef) #7
  %ev = call align 4 dereferenceable(16) ptr @runtime.alloc(i64 16, ptr nonnull inttoptr (i64 3 to ptr), ptr undef) #7
  ret i32 0
}
`,
			check: func(t *testing.T, text string) {
				t.Helper()
				if strings.Count(text, "alloca [16 x i8], align 4") != 2 {
					t.Error("expected 2 alloca instructions")
				}
				if strings.Count(text, "llvm.memset.p0.i64") < 2 {
					t.Error("expected at least 2 memset references")
				}
			},
		},
		{
			name: "no entry label",
			ir: `
define i32 @my_func(ptr %ctx) {
  %buf = call align 4 dereferenceable(16) ptr @runtime.alloc(i64 16, ptr nonnull inttoptr (i64 3 to ptr), ptr undef) #7
  ret i32 0
}
`,
			wantContain: []string{"alloca [16 x i8]"},
		},
		{
			name: "existing memset decl",
			ir: `
declare void @llvm.memset.p0.i64(ptr, i8, i64, i1)

define i32 @my_func(ptr %ctx) {
entry:
  %buf = call align 4 dereferenceable(16) ptr @runtime.alloc(i64 16, ptr nonnull inttoptr (i64 3 to ptr), ptr undef) #7
  ret i32 0
}
`,
			check: func(t *testing.T, text string) {
				t.Helper()
				if strings.Count(text, "declare void @llvm.memset.p0.i64") != 1 {
					t.Error("should not add duplicate memset declaration")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text := runReplaceAlloc(t, tt.ir)
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
				tt.check(t, text)
			}
		})
	}
}
