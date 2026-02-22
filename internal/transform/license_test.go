package transform

import (
	"strings"
	"testing"
)

func TestAddLicense(t *testing.T) {
	tests := []struct {
		name        string
		input       []string
		wantContain []string
		wantCount   map[string]int
	}{
		{
			name: "already present",
			input: []string{
				`@_license = global [4 x i8] c"GPL\00", section "license", align 1`,
				"define i32 @my_func() { ret i32 0 }",
			},
			wantCount: map[string]int{`section "license"`: 1},
		},
		{
			name:        "no define block",
			input:       []string{`target triple = "bpf"`, `@x = global i32 0`},
			wantContain: []string{`section "license"`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := addLicense(tt.input)
			text := strings.Join(got, "\n")
			for _, want := range tt.wantContain {
				if !strings.Contains(text, want) {
					t.Errorf("output missing %q", want)
				}
			}
			for substr, wantN := range tt.wantCount {
				n := strings.Count(text, substr)
				if n != wantN {
					t.Errorf("expected %d occurrences of %q, got %d", wantN, substr, n)
				}
			}
		})
	}
}
