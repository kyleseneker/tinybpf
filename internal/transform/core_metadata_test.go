package transform

import (
	"strings"
	"testing"
)

//nolint:dupword
func TestFindCoreTypes(t *testing.T) {
	tests := []struct {
		name     string
		lines    []string
		wantKeys []string
	}{
		{
			name:     "detects bpfCore type",
			lines:    []string{"%main.bpfCoreTaskStruct = type { i32, i32 }"},
			wantKeys: []string{"%main.bpfCoreTaskStruct"},
		},
		{
			name:     "ignores non-core type",
			lines:    []string{"%main.bpfMapDef = type { i32, i32, i32, i32, i32 }"},
			wantKeys: nil,
		},
		{
			name: "multiple core types",
			lines: []string{
				"%main.bpfCoreTaskStruct = type { i32, i32 }",
				"%main.bpfCoreFileStruct = type { i64 }",
			},
			wantKeys: []string{"%main.bpfCoreTaskStruct", "%main.bpfCoreFileStruct"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := findCoreTypes(tt.lines)
			if err != nil {
				t.Fatal(err)
			}
			if len(tt.wantKeys) == 0 && len(got) == 0 {
				return
			}
			for _, k := range tt.wantKeys {
				if !got[k] {
					t.Errorf("missing type %q", k)
				}
			}
			if len(got) != len(tt.wantKeys) {
				t.Errorf("expected %d types, got %d", len(tt.wantKeys), len(got))
			}
		})
	}
}

func TestSanitizeCoreFieldNames(t *testing.T) {
	tests := []struct {
		name        string
		lines       []string
		wantContain []string
		notContain  []string
	}{
		{
			name: "renames struct type and field names",
			lines: []string{
				`!0 = !DICompositeType(tag: DW_TAG_structure_type, name: "main_bpfCoreTaskStruct", size: 64, elements: !{!1, !2})`,
				`!1 = !DIDerivedType(tag: DW_TAG_member, name: "Pid", baseType: !3, size: 32, offset: 0)`,
				`!2 = !DIDerivedType(tag: DW_TAG_member, name: "Tgid", baseType: !3, size: 32, offset: 32)`,
				`!3 = !DIBasicType(name: "int32", size: 32)`,
			},
			wantContain: []string{
				`name: "task_struct"`,
				`name: "pid"`,
				`name: "tgid"`,
			},
			notContain: []string{
				`name: "Pid"`,
				`name: "Tgid"`,
				`name: "main_bpfCoreTaskStruct"`,
			},
		},
		{
			name: "multi-word field names become snake_case",
			lines: []string{
				`!0 = !DICompositeType(tag: DW_TAG_structure_type, name: "main_bpfCoreCredStruct", size: 64, elements: !{!1})`,
				`!1 = !DIDerivedType(tag: DW_TAG_member, name: "LoginUid", baseType: !2, size: 32, offset: 0)`,
				`!2 = !DIBasicType(name: "int32", size: 32)`,
			},
			wantContain: []string{
				`name: "cred_struct"`,
				`name: "login_uid"`,
			},
		},
		{
			name: "non-core metadata unchanged",
			lines: []string{
				`!0 = !DICompositeType(tag: DW_TAG_structure_type, name: "main_bpfMapDef", size: 160, elements: !{!1})`,
				`!1 = !DIDerivedType(tag: DW_TAG_member, name: "Type", baseType: !2, size: 32, offset: 0)`,
				`!2 = !DIBasicType(name: "int32", size: 32)`,
			},
			wantContain: []string{
				`name: "Type"`,
				`name: "main_bpfMapDef"`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sanitizeCoreFieldNames(tt.lines)
			if err != nil {
				t.Fatal(err)
			}
			text := strings.Join(got, "\n")
			for _, want := range tt.wantContain {
				if !strings.Contains(text, want) {
					t.Errorf("output missing %q\n---\n%s", want, text)
				}
			}
			for _, bad := range tt.notContain {
				if strings.Contains(text, bad) {
					t.Errorf("output should not contain %q\n---\n%s", bad, text)
				}
			}
		})
	}
}

func TestBuildMetadataLineIndex(t *testing.T) {
	lines := []string{
		"!0 = !DICompositeType(tag: DW_TAG_structure_type)",
		"!1 = !DIDerivedType(tag: DW_TAG_member)",
		"define void @main() {",
		"  ret void",
		"}",
		"!2 = !DIBasicType(name: \"int32\")",
	}
	idx := buildMetadataLineIndex(lines)
	if len(idx) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(idx))
	}
	for _, id := range []int{0, 1, 2} {
		if _, ok := idx[id]; !ok {
			t.Errorf("missing metadata ID %d", id)
		}
	}
}

func TestExtractMetadataName(t *testing.T) {
	tests := []struct {
		line string
		want string
		ok   bool
	}{
		{`name: "main.bpfCoreTaskStruct"`, "main.bpfCoreTaskStruct", true},
		{`tag: DW_TAG_member, name: "Pid"`, "Pid", true},
		{`no name field here`, "", false},
		{`name: "unterminated`, "", false},
	}
	for _, tt := range tests {
		got, ok := extractMetadataName(tt.line)
		if ok != tt.ok || got != tt.want {
			t.Errorf("extractMetadataName(%q) = (%q, %v), want (%q, %v)",
				tt.line, got, ok, tt.want, tt.ok)
		}
	}
}

func TestParseMetadataRefs(t *testing.T) {
	tests := []struct {
		in   string
		want []int
	}{
		{"!{!1, !2, !3}", []int{1, 2, 3}},
		{"!{!10}", []int{10}},
		{"!{}", nil},
		{"", nil},
	}
	for _, tt := range tests {
		got := parseMetadataRefs(tt.in)
		if len(got) != len(tt.want) {
			t.Errorf("parseMetadataRefs(%q) = %v, want %v", tt.in, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("parseMetadataRefs(%q)[%d] = %d, want %d", tt.in, i, got[i], tt.want[i])
			}
		}
	}
}

func TestExtractMemberOffsetBits(t *testing.T) {
	tests := []struct {
		line  string
		want  int
		found bool
	}{
		{`DIDerivedType(tag: DW_TAG_member, name: "Pid", offset: 0)`, 0, true},
		{`DIDerivedType(tag: DW_TAG_member, name: "Tgid", offset: 32)`, 32, true},
		{`DIDerivedType(tag: DW_TAG_member, name: "X")`, 0, false},
		{`offset: abc`, 0, false},
	}
	for _, tt := range tests {
		got, found := extractMemberOffsetBits(tt.line)
		if found != tt.found || got != tt.want {
			t.Errorf("extractMemberOffsetBits(%q) = (%d, %v), want (%d, %v)",
				tt.line, got, found, tt.want, tt.found)
		}
	}
}

func TestIRTypeSize(t *testing.T) {
	tests := []struct {
		in   string
		want int
		err  bool
	}{
		{"i8", 1, false},
		{"i16", 2, false},
		{"i32", 4, false},
		{"i64", 8, false},
		{"ptr", 8, false},
		{"[16 x i8]", 16, false},
		{"[4 x i32]", 16, false},
		{"float", 0, true},
	}
	for _, tt := range tests {
		got, err := irTypeSize(tt.in)
		if (err != nil) != tt.err {
			t.Errorf("irTypeSize(%q) error = %v, wantErr %v", tt.in, err, tt.err)
			continue
		}
		if got != tt.want {
			t.Errorf("irTypeSize(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestSplitStructFields(t *testing.T) {
	tests := []struct {
		body string
		want []string
	}{
		{"i32, i32", []string{"i32", "i32"}},
		{"i32, [16 x i8]", []string{"i32", "[16 x i8]"}},
		{"i64", []string{"i64"}},
	}
	for _, tt := range tests {
		got := splitStructFields(tt.body)
		if len(got) != len(tt.want) {
			t.Errorf("splitStructFields(%q) = %v, want %v", tt.body, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("splitStructFields(%q)[%d] = %q, want %q", tt.body, i, got[i], tt.want[i])
			}
		}
	}
}

func TestCumulativeOffsets(t *testing.T) {
	got := cumulativeOffsets([]int{4, 4, 16})
	want := []int{0, 4, 8}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("cumulativeOffsets[%d] = %d, want %d", i, got[i], want[i])
		}
	}
}

func TestFieldIndexFromOffset(t *testing.T) {
	offsets := []int{0, 4, 8}
	tests := []struct {
		offset int
		want   int
	}{
		{0, 0},
		{4, 1},
		{8, 2},
		{12, -1},
	}
	for _, tt := range tests {
		got := fieldIndexFromOffset(offsets, tt.offset)
		if got != tt.want {
			t.Errorf("fieldIndexFromOffset(%v, %d) = %d, want %d", offsets, tt.offset, got, tt.want)
		}
	}
}

func TestParseLeadingInt(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"42 = ...", 42},
		{"0 = ...", 0},
		{"abc", -1},
		{"", -1},
		{"123", -1},
	}
	for _, tt := range tests {
		got := parseLeadingInt(tt.in)
		if got != tt.want {
			t.Errorf("parseLeadingInt(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}
