package transform

import (
	"strings"
	"testing"
)

func TestIsIdentChar(t *testing.T) {
	tests := []struct {
		c    byte
		want bool
	}{
		{'a', true},
		{'z', true},
		{'A', true},
		{'Z', true},
		{'0', true},
		{'9', true},
		{'_', true},
		{'.', true},
		{' ', false},
		{'\t', false},
		{'@', false},
		{'#', false},
		{'!', false},
		{'(', false},
		{')', false},
		{'-', false},
	}
	for _, tt := range tests {
		if got := isIdentChar(tt.c); got != tt.want {
			t.Errorf("isIdentChar(%q) = %v, want %v", tt.c, got, tt.want)
		}
	}
}

func TestParseDefineName(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"define i32 @my_func(ptr %ctx) {", "my_func", true},
		{"define void @main.prog(ptr %ctx) {", "main.prog", true},
		{"define i32 @.hidden(ptr %ctx) {", "", false},
		{"declare void @llvm.memset(ptr)", "", false},
		{"not a define", "", false},
	}
	for _, tt := range tests {
		got, ok := parseDefineName(tt.in)
		if ok != tt.ok || got != tt.want {
			t.Errorf("parseDefineName(%q) = (%q, %v), want (%q, %v)",
				tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

func TestParseDeclareName(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"declare void @llvm.memset.p0.i64(ptr, i8, i64, i1)", "llvm.memset.p0.i64", true},
		{"declare i32 @main.bpfCoreFieldExists(ptr, ptr)", "main.bpfCoreFieldExists", true},
		{"define i32 @my_func(ptr %ctx) {", "", false},
	}
	for _, tt := range tests {
		got, ok := parseDeclareName(tt.in)
		if ok != tt.ok || got != tt.want {
			t.Errorf("parseDeclareName(%q) = (%q, %v), want (%q, %v)",
				tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

func TestParseGlobalName(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"@main.events = global %main.bpfMapDef { i32 27 }", "main.events", true},
		{"@_license = global [4 x i8] c\"GPL\\00\"", "_license", true},
		{"not a global", "", false},
		{"@", "", false},
		{"@name", "", false},
	}
	for _, tt := range tests {
		got, ok := parseGlobalName(tt.in)
		if ok != tt.ok || got != tt.want {
			t.Errorf("parseGlobalName(%q) = (%q, %v), want (%q, %v)",
				tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

func TestExtractMetadataID(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"!0 = !DICompositeType(...)", 0},
		{"!42 = !DIBasicType(name: \"int\")", 42},
		{"not metadata", -1},
		{"!abc = bad", -1},
		{"", -1},
	}
	for _, tt := range tests {
		if got := extractMetadataID(tt.in); got != tt.want {
			t.Errorf("extractMetadataID(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestIrSnippet(t *testing.T) {
	lines := []string{"aaa", "bbb", "ccc", "ddd", "eee", "fff"}

	tests := []struct {
		name   string
		center int
		radius int
		want   string
	}{
		{
			name:   "middle with radius 1",
			center: 2,
			radius: 1,
			want:   "  2: bbb\n> 3: ccc\n  4: ddd\n",
		},
		{
			name:   "start clamped",
			center: 0,
			radius: 2,
			want:   "> 1: aaa\n  2: bbb\n  3: ccc\n",
		},
		{
			name:   "end clamped",
			center: 5,
			radius: 2,
			want:   "  4: ddd\n  5: eee\n> 6: fff\n",
		},
		{
			name:   "radius 0",
			center: 3,
			radius: 0,
			want:   "> 4: ddd\n",
		},
		{
			name:   "radius larger than input",
			center: 2,
			radius: 10,
			want:   "  1: aaa\n  2: bbb\n> 3: ccc\n  4: ddd\n  5: eee\n  6: fff\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := irSnippet(lines, tt.center, tt.radius)
			if got != tt.want {
				t.Errorf("got:\n%s\nwant:\n%s", got, tt.want)
			}
		})
	}
}

func TestCamelToSnake(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"TaskStruct", "task_struct"},
		{"Pid", "pid"},
		{"LoginUid", "login_uid"},
		{"CredStruct", "cred_struct"},
		{"pid", "pid"},
		{"A", "a"},
		{"ABCDef", "a_b_c_def"},
	}
	for _, tt := range tests {
		if got := camelToSnake(tt.in); got != tt.want {
			t.Errorf("camelToSnake(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestHasDeclare(t *testing.T) {
	lines := []string{
		"define void @main() {",
		"  ret void",
		"}",
		"declare void @llvm.memset.p0.i64(ptr, i8, i64, i1)",
	}
	tests := []struct {
		substr string
		want   bool
	}{
		{"llvm.memset", true},
		{"llvm.memset.p0.i64", true},
		{"llvm.nonexistent", false},
		{"define", false},
	}
	for _, tt := range tests {
		if got := hasDeclare(lines, tt.substr); got != tt.want {
			t.Errorf("hasDeclare(lines, %q) = %v, want %v", tt.substr, got, tt.want)
		}
	}
}

func TestInsertBeforeFunc(t *testing.T) {
	tests := []struct {
		name     string
		lines    []string
		insert   []string
		wantLast string
		before   string
	}{
		{
			name: "before define",
			lines: []string{
				`target triple = "bpf"`,
				"",
				"define i32 @main(ptr %ctx) {",
				"  ret i32 0",
				"}",
			},
			insert: []string{"declare void @foo()"},
			before: "define i32 @main",
		},
		{
			name: "before declare",
			lines: []string{
				`target triple = "bpf"`,
				"declare void @bar()",
			},
			insert: []string{"; inserted"},
			before: "declare void @bar",
		},
		{
			name:     "fallback append",
			lines:    []string{"just", "some", "lines"},
			insert:   []string{"appended"},
			wantLast: "appended",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := insertBeforeFunc(tt.lines, tt.insert...)
			text := strings.Join(got, "\n")
			if tt.before != "" {
				insIdx := strings.Index(text, tt.insert[0])
				befIdx := strings.Index(text, tt.before)
				if insIdx < 0 || befIdx < 0 || insIdx >= befIdx {
					t.Errorf("expected %q before %q in:\n%s", tt.insert[0], tt.before, text)
				}
			}
			if tt.wantLast != "" && got[len(got)-1] != tt.wantLast {
				t.Errorf("expected last line %q, got %q", tt.wantLast, got[len(got)-1])
			}
		})
	}
}
