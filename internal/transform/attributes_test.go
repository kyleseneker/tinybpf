package transform

import (
	"strings"
	"testing"
)

func FuzzStripAttributes(f *testing.F) {
	f.Add(`attributes #0 = { allockind("alloc,zeroed") allocsize(0) "alloc-family"="runtime.alloc" "target-cpu"="generic" "target-features"="+neon" }`)
	f.Add(`attributes #4 = { nounwind "target-cpu"="generic" }`)
	f.Add(`attributes #7 = { nounwind }`)
	f.Add(`not an attributes line at all`)
	f.Add(`attributes #0 = { }`)

	f.Fuzz(func(t *testing.T, line string) {
		if len(line) > 1<<16 {
			return
		}
		lines := strings.Split(line, "\n")
		stripAttributes(lines)
	})
}

func TestStripAttributes(t *testing.T) {
	lines := []string{
		`attributes #0 = { allockind("alloc,zeroed") allocsize(0) "alloc-family"="runtime.alloc" "target-cpu"="generic" "target-features"="+ete,+fp-armv8,+neon,+trbe,+v8a" }`,
		`attributes #4 = { nounwind "target-cpu"="generic" "target-features"="+ete,+fp-armv8,+neon,+trbe,+v8a" }`,
		`attributes #7 = { nounwind }`,
	}
	got := stripAttributes(lines)

	tests := []struct {
		name        string
		lineIdx     int
		wantContain []string
		notContain  []string
		wantExact   string
	}{
		{
			name:       "removes host attrs from #0",
			lineIdx:    0,
			notContain: []string{"target-cpu", "target-features", "allockind", "allocsize", "alloc-family"},
		},
		{
			name:        "preserves nounwind in #4",
			lineIdx:     1,
			wantContain: []string{"nounwind"},
		},
		{
			name:      "leaves #7 unchanged",
			lineIdx:   2,
			wantExact: `attributes #7 = { nounwind }`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line := got[tt.lineIdx]
			for _, want := range tt.wantContain {
				if !strings.Contains(line, want) {
					t.Errorf("line missing %q: %s", want, line)
				}
			}
			for _, bad := range tt.notContain {
				if strings.Contains(line, bad) {
					t.Errorf("line still contains %q: %s", bad, line)
				}
			}
			if tt.wantExact != "" && line != tt.wantExact {
				t.Errorf("got %q, want %q", line, tt.wantExact)
			}
		})
	}
}
