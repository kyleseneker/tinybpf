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

func TestReplaceAlloc(t *testing.T) {
	t.Run("single alloc", func(t *testing.T) {
		input := strings.Split(strings.TrimSpace(`
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
`), "\n")
		got, err := replaceAlloc(input)
		if err != nil {
			t.Fatal(err)
		}
		text := strings.Join(got, "\n")

		if !strings.Contains(text, "%buf = alloca [16 x i8], align 4") {
			t.Error("alloca not inserted in entry block")
		}
		if !strings.Contains(text, "llvm.memset.p0.i64(ptr align 4 %buf, i8 0, i64 16, i1 false)") {
			t.Error("memset not inserted at call site")
		}
		if strings.Contains(text, "@runtime.alloc") {
			t.Error("runtime.alloc call not replaced")
		}
		allocaIdx := strings.Index(text, "%buf = alloca")
		entryCodeIdx := strings.Index(text, "%0 = icmp")
		if allocaIdx < 0 || entryCodeIdx < 0 || allocaIdx > entryCodeIdx {
			t.Error("alloca not placed before existing entry block code")
		}
		if !strings.Contains(text, "declare void @llvm.memset.p0.i64") {
			t.Error("memset declaration not added")
		}
	})

	t.Run("multiple allocs", func(t *testing.T) {
		input := strings.Split(strings.TrimSpace(`
define i32 @my_func(ptr %ctx) {
entry:
  br label %work

work:
  %sa = call align 4 dereferenceable(16) ptr @runtime.alloc(i64 16, ptr nonnull inttoptr (i64 3 to ptr), ptr undef) #7
  %ev = call align 4 dereferenceable(16) ptr @runtime.alloc(i64 16, ptr nonnull inttoptr (i64 3 to ptr), ptr undef) #7
  ret i32 0
}
`), "\n")
		got, err := replaceAlloc(input)
		if err != nil {
			t.Fatal(err)
		}
		text := strings.Join(got, "\n")
		if strings.Count(text, "alloca [16 x i8], align 4") != 2 {
			t.Error("expected 2 alloca instructions")
		}
		if strings.Count(text, "llvm.memset.p0.i64") < 2 {
			t.Error("expected at least 2 memset references")
		}
	})

	t.Run("no entry label", func(t *testing.T) {
		input := strings.Split(strings.TrimSpace(`
define i32 @my_func(ptr %ctx) {
  %buf = call align 4 dereferenceable(16) ptr @runtime.alloc(i64 16, ptr nonnull inttoptr (i64 3 to ptr), ptr undef) #7
  ret i32 0
}
`), "\n")
		got, err := replaceAlloc(input)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(strings.Join(got, "\n"), "alloca [16 x i8]") {
			t.Error("alloca not inserted without entry label")
		}
	})

	t.Run("existing memset decl", func(t *testing.T) {
		input := strings.Split(strings.TrimSpace(`
declare void @llvm.memset.p0.i64(ptr, i8, i64, i1)

define i32 @my_func(ptr %ctx) {
entry:
  %buf = call align 4 dereferenceable(16) ptr @runtime.alloc(i64 16, ptr nonnull inttoptr (i64 3 to ptr), ptr undef) #7
  ret i32 0
}
`), "\n")
		got, err := replaceAlloc(input)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(strings.Join(got, "\n"), "declare void @llvm.memset.p0.i64") != 1 {
			t.Error("should not add duplicate memset declaration")
		}
	})
}
