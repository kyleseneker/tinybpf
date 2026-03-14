package transform

import (
	"strings"
	"testing"
)

func TestParseI32Initializer(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
		wantNil bool
	}{
		{"valid 5 fields", "i32 27, i32 0, i32 0, i32 16777216, i32 0", 5, false},
		{"valid 1 field", "i32 42", 1, false},
		{"malformed value", "i32 abc, i32 1", 0, true},
		{"empty string", "", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseI32Initializer(tt.input)
			if tt.wantNil {
				if got != nil {
					t.Fatalf("expected nil, got %v", got)
				}
				return
			}
			if len(got) != tt.wantLen {
				t.Fatalf("expected %d values, got %d: %v", tt.wantLen, len(got), got)
			}
		})
	}
}

func TestReplaceDotInNameFields(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "dot in name",
			line: `!5 = !DISubprogram(name: "main.handle", linkageName: "main.handle")`,
			want: `!5 = !DISubprogram(name: "main_handle", linkageName: "main_handle")`,
		},
		{
			name: "no dot",
			line: `!5 = !DISubprogram(name: "handle")`,
			want: `!5 = !DISubprogram(name: "handle")`,
		},
		{
			name: "no name field",
			line: `!5 = !DIBasicType(size: 32)`,
			want: `!5 = !DIBasicType(size: 32)`,
		},
		{
			name: "multiple dots",
			line: `!5 = !DISubprogram(name: "internal/task.start.func1")`,
			want: `!5 = !DISubprogram(name: "internal/task_start_func1")`,
		},
		{
			name: "unclosed quote",
			line: `name: "broken`,
			want: `name: "broken`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf strings.Builder
			got := replaceDotInNameFields(tt.line, &buf)
			if got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}

func TestStripPointerName(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "strips name field",
			line: `!5 = !DIDerivedType(tag: DW_TAG_pointer_type, name: "unsafe.Pointer", baseType: !6)`,
			want: `!5 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !6)`,
		},
		{
			name: "no name field",
			line: `!5 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !6)`,
			want: `!5 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !6)`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stripPointerName(tt.line); got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}
