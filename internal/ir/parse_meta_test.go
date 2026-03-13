package ir

import (
	"testing"
)

func TestParseMetadataNode(t *testing.T) {
	tests := []struct {
		name      string
		line      string
		trimmed   string
		id        int
		wantKind  string
		wantTuple []string
		wantField map[string]string
	}{
		{
			name:     "DICompositeType",
			line:     `!0 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfMapDef", size: 160)`,
			trimmed:  `!0 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfMapDef", size: 160)`,
			id:       0,
			wantKind: "DICompositeType",
			wantField: map[string]string{
				"tag":  "DW_TAG_structure_type",
				"name": "main.bpfMapDef",
				"size": "160",
			},
		},
		{
			name:     "DIDerivedType",
			line:     `!1 = !DIDerivedType(tag: DW_TAG_member, name: "Pid", baseType: !4, size: 32, offset: 0)`,
			trimmed:  `!1 = !DIDerivedType(tag: DW_TAG_member, name: "Pid", baseType: !4, size: 32, offset: 0)`,
			id:       1,
			wantKind: "DIDerivedType",
			wantField: map[string]string{
				"tag":      "DW_TAG_member",
				"name":     "Pid",
				"baseType": "!4",
				"size":     "32",
				"offset":   "0",
			},
		},
		{
			name:      "tuple",
			line:      `!10 = !{!0, !1}`,
			trimmed:   `!10 = !{!0, !1}`,
			id:        10,
			wantKind:  "",
			wantTuple: []string{"!0", "!1"},
		},
		{
			name:     "distinct prefix",
			line:     `!5 = distinct !DISubprogram(name: "main")`,
			trimmed:  `!5 = distinct !DISubprogram(name: "main")`,
			id:       5,
			wantKind: "DISubprogram",
			wantField: map[string]string{
				"name": "main",
			},
		},
		{
			name:      "distinct tuple",
			line:      `!9 = distinct !{!3, !4}`,
			trimmed:   `!9 = distinct !{!3, !4}`,
			id:        9,
			wantTuple: []string{"!3", "!4"},
		},
		{
			name:     "no equals sign",
			line:     `!0 something without equals`,
			trimmed:  `!0 something without equals`,
			id:       0,
			wantKind: "",
		},
		{
			name:     "DW prefix kind",
			line:     `!7 = !DW_TAG_member(name: "x")`,
			trimmed:  `!7 = !DW_TAG_member(name: "x")`,
			id:       7,
			wantKind: "DW_TAG_member",
			wantField: map[string]string{
				"name": "x",
			},
		},
		{
			name:     "empty line",
			line:     ``,
			trimmed:  ``,
			id:       0,
			wantKind: "",
		},
		{
			name:      "empty tuple braces",
			line:      `!3 = !{}`,
			trimmed:   `!3 = !{}`,
			id:        3,
			wantTuple: nil,
		},
		{
			name:     "DI kind without parens",
			line:     `!6 = !DIFile`,
			trimmed:  `!6 = !DIFile`,
			id:       6,
			wantKind: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseMetadataNode(tt.line, tt.trimmed, tt.id)

			if got.ID != tt.id {
				t.Errorf("ID = %d, want %d", got.ID, tt.id)
			}
			if got.Raw != tt.line {
				t.Errorf("Raw = %q, want %q", got.Raw, tt.line)
			}
			if got.Kind != tt.wantKind {
				t.Errorf("Kind = %q, want %q", got.Kind, tt.wantKind)
			}
			if len(got.Tuple) != len(tt.wantTuple) {
				t.Fatalf("Tuple len = %d, want %d; got %v", len(got.Tuple), len(tt.wantTuple), got.Tuple)
			}
			for i, ref := range tt.wantTuple {
				if got.Tuple[i] != ref {
					t.Errorf("Tuple[%d] = %q, want %q", i, got.Tuple[i], ref)
				}
			}
			for k, v := range tt.wantField {
				if got.Fields[k] != v {
					t.Errorf("Fields[%q] = %q, want %q", k, got.Fields[k], v)
				}
			}
		})
	}
}

func TestParseNamedMetadata(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		trimmed  string
		wantName string
		wantRefs []string
	}{
		{
			name:     "single ref",
			line:     `!llvm.dbg.cu = !{!0}`,
			trimmed:  `!llvm.dbg.cu = !{!0}`,
			wantName: "llvm.dbg.cu",
			wantRefs: []string{"!0"},
		},
		{
			name:     "multiple refs",
			line:     `!llvm.module.flags = !{!1, !2, !3}`,
			trimmed:  `!llvm.module.flags = !{!1, !2, !3}`,
			wantName: "llvm.module.flags",
			wantRefs: []string{"!1", "!2", "!3"},
		},
		{
			name:     "no equals sign",
			line:     `!llvm.dbg.cu something`,
			trimmed:  `!llvm.dbg.cu something`,
			wantName: "",
			wantRefs: nil,
		},
		{
			name:     "equals but no tuple",
			line:     `!foo = bar`,
			trimmed:  `!foo = bar`,
			wantName: "foo",
			wantRefs: nil,
		},
		{
			name:     "empty tuple",
			line:     `!foo = !{}`,
			trimmed:  `!foo = !{}`,
			wantName: "foo",
			wantRefs: nil,
		},
		{
			name:     "empty string",
			line:     ``,
			trimmed:  ``,
			wantName: "",
			wantRefs: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseNamedMetadata(tt.line, tt.trimmed)

			if got.Raw != tt.line {
				t.Errorf("Raw = %q, want %q", got.Raw, tt.line)
			}
			if got.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", got.Name, tt.wantName)
			}
			if len(got.Refs) != len(tt.wantRefs) {
				t.Fatalf("Refs len = %d, want %d; got %v", len(got.Refs), len(tt.wantRefs), got.Refs)
			}
			for i, ref := range tt.wantRefs {
				if got.Refs[i] != ref {
					t.Errorf("Refs[%d] = %q, want %q", i, got.Refs[i], ref)
				}
			}
		})
	}
}

func TestParseTupleRefs(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want []string
	}{
		{
			name: "normal refs",
			s:    `!{!0, !1, !2}`,
			want: []string{"!0", "!1", "!2"},
		},
		{
			name: "single ref",
			s:    `!{!5}`,
			want: []string{"!5"},
		},
		{
			name: "empty braces",
			s:    `!{}`,
			want: nil,
		},
		{
			name: "no braces",
			s:    `!DIFile`,
			want: nil,
		},
		{
			name: "empty string",
			s:    ``,
			want: nil,
		},
		{
			name: "only open brace",
			s:    `!{!0, !1`,
			want: nil,
		},
		{
			name: "spaces in refs",
			s:    `!{  !0 ,  !1  }`,
			want: []string{"!0", "!1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseTupleRefs(tt.s)
			if len(got) != len(tt.want) {
				t.Fatalf("len = %d, want %d; got %v", len(got), len(tt.want), got)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestParseDIFields(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want map[string]string
	}{
		{
			name: "normal fields",
			s:    `!DICompositeType(tag: DW_TAG_structure_type, name: "foo", size: 64)`,
			want: map[string]string{
				"tag":  "DW_TAG_structure_type",
				"name": "foo",
				"size": "64",
			},
		},
		{
			name: "single field",
			s:    `!DIBasicType(name: "int32")`,
			want: map[string]string{
				"name": "int32",
			},
		},
		{
			name: "no parens",
			s:    `!DIFile`,
			want: nil,
		},
		{
			name: "mismatched parens - no close",
			s:    `!DIFile(name: "x"`,
			want: nil,
		},
		{
			name: "mismatched parens - close before open",
			s:    `)!DIFile(`,
			want: nil,
		},
		{
			name: "empty parens",
			s:    `!DIFile()`,
			want: map[string]string{},
		},
		{
			name: "empty string",
			s:    ``,
			want: nil,
		},
		{
			name: "metadata ref value",
			s:    `!DIDerivedType(baseType: !4, size: 32)`,
			want: map[string]string{
				"baseType": "!4",
				"size":     "32",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseDIFields(tt.s)
			if tt.want == nil {
				if got != nil {
					t.Fatalf("got %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("got nil, want non-nil")
			}
			if len(got) != len(tt.want) {
				t.Fatalf("len = %d, want %d; got %v", len(got), len(tt.want), got)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("[%q] = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestSplitDIKeyValues(t *testing.T) {
	tests := []struct {
		name string
		body string
		want map[string]string
	}{
		{
			name: "key value pairs",
			body: `tag: DW_TAG_member, name: "Pid", size: 32`,
			want: map[string]string{
				"tag":  "DW_TAG_member",
				"name": "Pid",
				"size": "32",
			},
		},
		{
			name: "quoted value stripped",
			body: `name: "hello world"`,
			want: map[string]string{
				"name": "hello world",
			},
		},
		{
			name: "unquoted value",
			body: `size: 64`,
			want: map[string]string{
				"size": "64",
			},
		},
		{
			name: "no colon skipped",
			body: `orphanvalue`,
			want: map[string]string{},
		},
		{
			name: "colon at start skipped",
			body: `: value`,
			want: map[string]string{},
		},
		{
			name: "empty body",
			body: ``,
			want: map[string]string{},
		},
		{
			name: "single char quoted value not stripped",
			body: `x: "a"`,
			want: map[string]string{
				"x": "a",
			},
		},
		{
			name: "metadata ref value",
			body: `baseType: !4`,
			want: map[string]string{
				"baseType": "!4",
			},
		},
		{
			name: "multiple pairs with whitespace",
			body: `  tag:  DW_TAG_member ,  name:  "foo"  `,
			want: map[string]string{
				"tag":  "DW_TAG_member",
				"name": "foo",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitDIKeyValues(tt.body)
			if len(got) != len(tt.want) {
				t.Fatalf("len = %d, want %d; got %v", len(got), len(tt.want), got)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("[%q] = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestSplitDIPairs(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "comma separated",
			body: `tag: DW_TAG_member, name: "Pid", size: 32`,
			want: []string{`tag: DW_TAG_member`, `name: "Pid"`, `size: 32`},
		},
		{
			name: "nested braces",
			body: `elements: !{!1, !2}, size: 64`,
			want: []string{`elements: !{!1, !2}`, `size: 64`},
		},
		{
			name: "nested parens",
			body: `elements: foo(!1, !2), size: 64`,
			want: []string{`elements: foo(!1, !2)`, `size: 64`},
		},
		{
			name: "quoted string with commas",
			body: `name: "a, b, c", size: 32`,
			want: []string{`name: "a, b, c"`, `size: 32`},
		},
		{
			name: "single item",
			body: `name: "hello"`,
			want: []string{`name: "hello"`},
		},
		{
			name: "empty body",
			body: ``,
			want: nil,
		},
		{
			name: "whitespace only",
			body: `   `,
			want: nil,
		},
		{
			name: "escaped quote in string",
			body: `name: "he said \"hi\", ok", tag: x`,
			want: []string{`name: "he said \"hi\", ok"`, `tag: x`},
		},
		{
			name: "deeply nested braces",
			body: `a: {x, {y, z}}, b: 1`,
			want: []string{`a: {x, {y, z}}`, `b: 1`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitDIPairs(tt.body)
			if len(got) != len(tt.want) {
				t.Fatalf("len = %d, want %d; got %v", len(got), len(tt.want), got)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestExtractBraced(t *testing.T) {
	tests := []struct {
		name  string
		s     string
		open  byte
		close byte
		want  string
	}{
		{
			name:  "normal curly braces",
			s:     `!{!0, !1}`,
			open:  '{',
			close: '}',
			want:  "!0, !1",
		},
		{
			name:  "parens",
			s:     `foo(bar, baz)`,
			open:  '(',
			close: ')',
			want:  "bar, baz",
		},
		{
			name:  "no open brace",
			s:     `!0, !1}`,
			open:  '{',
			close: '}',
			want:  "",
		},
		{
			name:  "no close brace",
			s:     `!{!0, !1`,
			open:  '{',
			close: '}',
			want:  "",
		},
		{
			name:  "close before open",
			s:     `}!{`,
			open:  '{',
			close: '}',
			want:  "",
		},
		{
			name:  "close equals open index",
			s:     `{}`,
			open:  '{',
			close: '}',
			want:  "",
		},
		{
			name:  "empty string",
			s:     ``,
			open:  '{',
			close: '}',
			want:  "",
		},
		{
			name:  "nested braces uses last close",
			s:     `{a, {b, c}}`,
			open:  '{',
			close: '}',
			want:  "a, {b, c}",
		},
		{
			name:  "content between brackets",
			s:     `[hello]`,
			open:  '[',
			close: ']',
			want:  "hello",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractBraced(tt.s, tt.open, tt.close)
			if got != tt.want {
				t.Errorf("extractBraced(%q, %q, %q) = %q, want %q", tt.s, string(tt.open), string(tt.close), got, tt.want)
			}
		})
	}
}
