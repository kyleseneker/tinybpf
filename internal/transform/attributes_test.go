package transform

import (
	"strings"
	"testing"
)

func TestStripAttributes(t *testing.T) {
	lines := []string{
		`attributes #0 = { allockind("alloc,zeroed") allocsize(0) "alloc-family"="runtime.alloc" "target-cpu"="generic" "target-features"="+ete,+fp-armv8,+neon,+trbe,+v8a" }`,
		`attributes #4 = { nounwind "target-cpu"="generic" "target-features"="+ete,+fp-armv8,+neon,+trbe,+v8a" }`,
		`attributes #7 = { nounwind }`,
	}
	got := stripAttributes(lines)

	t.Run("removes host attrs from #0", func(t *testing.T) {
		for _, bad := range []string{"target-cpu", "target-features", "allockind", "allocsize", "alloc-family"} {
			if strings.Contains(got[0], bad) {
				t.Errorf("still contains %s", bad)
			}
		}
	})
	t.Run("preserves nounwind in #4", func(t *testing.T) {
		if !strings.Contains(got[1], "nounwind") {
			t.Error("lost nounwind")
		}
	})
	t.Run("leaves #7 unchanged", func(t *testing.T) {
		if got[2] != `attributes #7 = { nounwind }` {
			t.Errorf("changed: %q", got[2])
		}
	})
}
