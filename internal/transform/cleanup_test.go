package transform

import (
	"strings"
	"testing"
)

func TestCleanup(t *testing.T) {
	input := strings.Split(strings.TrimSpace(`
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
`), "\n")

	got := cleanup(input)
	text := strings.Join(got, "\n")

	for _, check := range []struct {
		contains bool
		substr   string
		desc     string
	}{
		{false, "@unused_func", "unused declare not removed"},
		{false, "attributes #0", "unused attribute group not removed"},
		{true, "@llvm.memset", "referenced declare removed"},
		{true, "attributes #4", "referenced attribute group removed"},
	} {
		if strings.Contains(text, check.substr) != check.contains {
			t.Error(check.desc)
		}
	}
}
