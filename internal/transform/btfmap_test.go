package transform

import (
	"strings"
	"testing"
)

func FuzzRewriteMapForBTF(f *testing.F) {
	//nolint:dupword
	f.Add(`%main.bpfMapDef = type { i32, i32, i32, i32, i32 }
@main.events = global %main.bpfMapDef { i32 27, i32 0, i32 0, i32 16777216, i32 0 }, align 4
!0 = !DIDerivedType(tag: DW_TAG_member, name: "Type", baseType: !1, size: 32, offset: 0)
!1 = !DIBasicType(name: "uint32", size: 32, encoding: DW_ATE_unsigned)`)
	f.Add(`no map globals here`)
	f.Add(`@main.events = global %main.bpfMapDef { i32 bad, i32 0 }`)

	f.Fuzz(func(t *testing.T, ir string) {
		if len(ir) > 1<<16 {
			return
		}
		lines := strings.Split(ir, "\n")
		rewriteMapForBTF(lines)
	})
}

func FuzzSanitizeBTFNames(f *testing.F) {
	f.Add(`!0 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfMapDef", size: 160)
!1 = !DIDerivedType(tag: DW_TAG_pointer_type, name: "unsafe.Pointer", baseType: !2, size: 64)
!2 = !DIGlobalVariable(name: "main.events", linkageName: "main.events")`)
	f.Add(`!0 = !DISubprogram(name: "main.myFunc")`)
	f.Add(`not metadata at all`)

	f.Fuzz(func(t *testing.T, ir string) {
		if len(ir) > 1<<16 {
			return
		}
		lines := strings.Split(ir, "\n")
		sanitizeBTFNames(lines)
	})
}

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

//nolint:dupword
var btfMapIR5Field = `
%main.bpfMapDef = type { i32, i32, i32, i32, i32 }
@main.events = global %main.bpfMapDef { i32 27, i32 0, i32 0, i32 16777216, i32 0 }, align 4
!0 = !DIDerivedType(tag: DW_TAG_member, name: "Type", baseType: !1, size: 32, offset: 0)
!1 = !DIBasicType(name: "uint32", size: 32, encoding: DW_ATE_unsigned)
!2 = !DIDerivedType(tag: DW_TAG_member, name: "KeySize", baseType: !1, size: 32, offset: 32)
!3 = !DIDerivedType(tag: DW_TAG_member, name: "ValueSize", baseType: !1, size: 32, offset: 64)
!4 = !DIDerivedType(tag: DW_TAG_member, name: "MaxEntries", baseType: !1, size: 32, offset: 96)
!5 = !DIDerivedType(tag: DW_TAG_member, name: "MapFlags", baseType: !1, size: 32, offset: 128)
!6 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfMapDef", size: 160, elements: !{!0, !2, !3, !4, !5})
`

//nolint:dupword
var btfMapIRMultiple = `
%main.bpfMapDef = type { i32, i32, i32, i32, i32 }
@main.events = global %main.bpfMapDef { i32 27, i32 0, i32 0, i32 16777216, i32 0 }, align 4
@main.counters = global %main.bpfMapDef { i32 2, i32 4, i32 8, i32 256, i32 0 }, align 4
!0 = !DIDerivedType(tag: DW_TAG_member, name: "Type", baseType: !1, size: 32, offset: 0)
!1 = !DIBasicType(name: "uint32", size: 32, encoding: DW_ATE_unsigned)
!2 = !DIDerivedType(tag: DW_TAG_member, name: "KeySize", baseType: !1, size: 32, offset: 32)
!3 = !DIDerivedType(tag: DW_TAG_member, name: "ValueSize", baseType: !1, size: 32, offset: 64)
!4 = !DIDerivedType(tag: DW_TAG_member, name: "MaxEntries", baseType: !1, size: 32, offset: 96)
!5 = !DIDerivedType(tag: DW_TAG_member, name: "MapFlags", baseType: !1, size: 32, offset: 128)
!6 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfMapDef", size: 160, elements: !{!0, !2, !3, !4, !5})
`

//nolint:dupword
var btfMapIRZeroinit = `
%main.bpfMapDef = type { i32, i32, i32, i32, i32 }
@main.empty_map = global %main.bpfMapDef zeroinitializer, align 4
!0 = !DIDerivedType(tag: DW_TAG_member, name: "Type", baseType: !1, size: 32, offset: 0)
!1 = !DIBasicType(name: "uint32", size: 32, encoding: DW_ATE_unsigned)
!2 = !DIDerivedType(tag: DW_TAG_member, name: "KeySize", baseType: !1, size: 32, offset: 32)
!3 = !DIDerivedType(tag: DW_TAG_member, name: "ValueSize", baseType: !1, size: 32, offset: 64)
!4 = !DIDerivedType(tag: DW_TAG_member, name: "MaxEntries", baseType: !1, size: 32, offset: 96)
!5 = !DIDerivedType(tag: DW_TAG_member, name: "MapFlags", baseType: !1, size: 32, offset: 128)
!6 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfMapDef", size: 160, elements: !{!0, !2, !3, !4, !5})
`

//nolint:dupword
var btfMapIRInternal = `
%main.bpfMapDef = type { i32, i32, i32, i32, i32 }
@main.events = internal global %main.bpfMapDef { i32 27, i32 0, i32 0, i32 16777216, i32 0 }, align 4
!0 = !DIDerivedType(tag: DW_TAG_member, name: "Type", baseType: !1, size: 32, offset: 0)
!1 = !DIBasicType(name: "uint32", size: 32, encoding: DW_ATE_unsigned)
!2 = !DIDerivedType(tag: DW_TAG_member, name: "KeySize", baseType: !1, size: 32, offset: 32)
!3 = !DIDerivedType(tag: DW_TAG_member, name: "ValueSize", baseType: !1, size: 32, offset: 64)
!4 = !DIDerivedType(tag: DW_TAG_member, name: "MaxEntries", baseType: !1, size: 32, offset: 96)
!5 = !DIDerivedType(tag: DW_TAG_member, name: "MapFlags", baseType: !1, size: 32, offset: 128)
!6 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfMapDef", size: 160, elements: !{!0, !2, !3, !4, !5})
`

//nolint:dupword
var btfMapIR6Field = `
%main.bpfMapDef = type { i32, i32, i32, i32, i32, i32 }
@main.pinned = global %main.bpfMapDef { i32 1, i32 4, i32 4, i32 1024, i32 0, i32 1 }, align 4
!0 = !DIDerivedType(tag: DW_TAG_member, name: "Type", baseType: !1, size: 32, offset: 0)
!1 = !DIBasicType(name: "uint32", size: 32, encoding: DW_ATE_unsigned)
!2 = !DIDerivedType(tag: DW_TAG_member, name: "KeySize", baseType: !1, size: 32, offset: 32)
!3 = !DIDerivedType(tag: DW_TAG_member, name: "ValueSize", baseType: !1, size: 32, offset: 64)
!4 = !DIDerivedType(tag: DW_TAG_member, name: "MaxEntries", baseType: !1, size: 32, offset: 96)
!5 = !DIDerivedType(tag: DW_TAG_member, name: "MapFlags", baseType: !1, size: 32, offset: 128)
!6 = !DIDerivedType(tag: DW_TAG_member, name: "Pinning", baseType: !1, size: 32, offset: 160)
!7 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfMapDef", size: 192, elements: !{!0, !2, !3, !4, !5, !6})
`

//nolint:dupword
var btfMapIR7Field = `
%main.bpfMapDef = type { i32, i32, i32, i32, i32, i32, i32 }
@main.outer = global %main.bpfMapDef { i32 12, i32 4, i32 4, i32 64, i32 0, i32 0, i32 0 }, align 4
!0 = !DIDerivedType(tag: DW_TAG_member, name: "Type", baseType: !1, size: 32, offset: 0)
!1 = !DIBasicType(name: "uint32", size: 32, encoding: DW_ATE_unsigned)
!2 = !DIDerivedType(tag: DW_TAG_member, name: "KeySize", baseType: !1, size: 32, offset: 32)
!3 = !DIDerivedType(tag: DW_TAG_member, name: "ValueSize", baseType: !1, size: 32, offset: 64)
!4 = !DIDerivedType(tag: DW_TAG_member, name: "MaxEntries", baseType: !1, size: 32, offset: 96)
!5 = !DIDerivedType(tag: DW_TAG_member, name: "MapFlags", baseType: !1, size: 32, offset: 128)
!6 = !DIDerivedType(tag: DW_TAG_member, name: "Pinning", baseType: !1, size: 32, offset: 160)
!7 = !DIDerivedType(tag: DW_TAG_member, name: "InnerMapFd", baseType: !1, size: 32, offset: 192)
!8 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfMapDef", size: 224, elements: !{!0, !2, !3, !4, !5, !6, !7})
`

//nolint:dupword
var btfMapIR7FieldZeroinit = `
%main.bpfMapDef = type { i32, i32, i32, i32, i32, i32, i32 }
@main.outer = global %main.bpfMapDef zeroinitializer, align 4
!0 = !DIDerivedType(tag: DW_TAG_member, name: "Type", baseType: !1, size: 32, offset: 0)
!1 = !DIBasicType(name: "uint32", size: 32, encoding: DW_ATE_unsigned)
!2 = !DIDerivedType(tag: DW_TAG_member, name: "KeySize", baseType: !1, size: 32, offset: 32)
!3 = !DIDerivedType(tag: DW_TAG_member, name: "ValueSize", baseType: !1, size: 32, offset: 64)
!4 = !DIDerivedType(tag: DW_TAG_member, name: "MaxEntries", baseType: !1, size: 32, offset: 96)
!5 = !DIDerivedType(tag: DW_TAG_member, name: "MapFlags", baseType: !1, size: 32, offset: 128)
!6 = !DIDerivedType(tag: DW_TAG_member, name: "Pinning", baseType: !1, size: 32, offset: 160)
!7 = !DIDerivedType(tag: DW_TAG_member, name: "InnerMapFd", baseType: !1, size: 32, offset: 192)
!8 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfMapDef", size: 224, elements: !{!0, !2, !3, !4, !5, !6, !7})
`

//nolint:dupword
var btfMapIRWrongFieldCount = `
%main.bpfMapDef = type { i32, i32, i32 }
@main.events = global %main.bpfMapDef { i32 27, i32 0, i32 0 }, align 4
`

func TestRewriteMapForBTF(t *testing.T) {
	tests := []struct {
		name        string
		ir          string
		wantContain []string
		notContain  []string
		wantErr     bool
		check       func(t *testing.T, text string)
	}{
		{
			name: "global rewritten to ptr struct",
			ir:   btfMapIR5Field,
			wantContain: []string{
				"global { ptr, ptr, ptr, ptr, ptr } zeroinitializer", //nolint:dupword
			},
		},
		{
			name: "type def rewritten",
			ir:   btfMapIR5Field,
			wantContain: []string{
				"{ ptr, ptr, ptr, ptr, ptr }", //nolint:dupword
			},
		},
		{
			name: "member names rewritten to C conventions",
			ir:   btfMapIR5Field,
			wantContain: []string{
				`name: "type"`, `name: "key_size"`, `name: "value_size"`,
				`name: "max_entries"`, `name: "map_flags"`,
			},
		},
		{
			name:        "member sizes rewritten to 64",
			ir:          btfMapIR5Field,
			wantContain: []string{"size: 64"},
		},
		{
			name:        "struct size rewritten to 320",
			ir:          btfMapIR5Field,
			wantContain: []string{"size: 320"},
		},
		{
			name: "BTF metadata appended",
			ir:   btfMapIR5Field,
			wantContain: []string{
				`DIBasicType(name: "int", size: 32`,
				"DISubrange(count: 27)",
				"DISubrange(count: 16777216)",
				"DW_TAG_array_type",
				"DW_TAG_pointer_type",
			},
		},
		{
			name:        "no match returns unchanged",
			ir:          "just some IR\nwith no map globals",
			wantContain: []string{"just some IR"},
		},
		{
			name:        "multiple maps",
			ir:          btfMapIRMultiple,
			wantContain: []string{"DISubrange(count: 27)", "DISubrange(count: 2)", "DISubrange(count: 256)"},
			check: func(t *testing.T, text string) {
				t.Helper()
				count := strings.Count(text, "global { ptr, ptr, ptr, ptr, ptr } zeroinitializer") //nolint:dupword
				if count != 2 {
					t.Errorf("expected 2 map globals rewritten, got %d", count)
				}
			},
		},
		{
			name: "zeroinitializer map",
			ir:   btfMapIRZeroinit,
			wantContain: []string{
				"global { ptr, ptr, ptr, ptr, ptr } zeroinitializer", //nolint:dupword
			},
			check: func(t *testing.T, text string) {
				t.Helper()
				if strings.Count(text, "DISubrange(count: 0)") < 5 {
					t.Error("expected 5 zero subranges")
				}
			},
		},
		{
			name: "internal linkage",
			ir:   btfMapIRInternal,
			wantContain: []string{
				"global { ptr, ptr, ptr, ptr, ptr } zeroinitializer", //nolint:dupword
			},
		},
		{
			name: "six fields with pinning",
			ir:   btfMapIR6Field,
			wantContain: []string{
				"global { ptr, ptr, ptr, ptr, ptr, ptr } zeroinitializer", //nolint:dupword
				`name: "pinning"`,
				"size: 384",
				"DISubrange(count: 1)",
			},
		},
		{
			name: "seven fields with inner_map_fd",
			ir:   btfMapIR7Field,
			wantContain: []string{
				"global { ptr, ptr, ptr, ptr, ptr, ptr, ptr } zeroinitializer", //nolint:dupword
				`name: "inner_map_fd"`,
				"size: 448",
				"DISubrange(count: 12)",
			},
		},
		{
			name: "seven fields zeroinitializer",
			ir:   btfMapIR7FieldZeroinit,
			wantContain: []string{
				"global { ptr, ptr, ptr, ptr, ptr, ptr, ptr } zeroinitializer", //nolint:dupword
			},
			check: func(t *testing.T, text string) {
				t.Helper()
				if strings.Count(text, "DISubrange(count: 0)") < 7 {
					t.Error("expected 7 zero subranges")
				}
			},
		},
		{
			name:    "wrong field count errors",
			ir:      btfMapIRWrongFieldCount,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := strings.Split(strings.TrimSpace(tt.ir), "\n")
			got, err := rewriteMapForBTF(input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			text := strings.Join(got, "\n")
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

func runSanitizeBTF(t *testing.T, ir string) string {
	t.Helper()
	input := strings.Split(strings.TrimSpace(ir), "\n")
	got, err := sanitizeBTFNames(input)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(got, "\n")
}

var sanitizeBTFInput = `
!0 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfMapDef", size: 160)
!1 = !DIDerivedType(tag: DW_TAG_pointer_type, name: "unsafe.Pointer", baseType: !2, size: 64)
!2 = !DIBasicType(name: "uint32", size: 32, encoding: DW_ATE_unsigned)
!3 = !DIGlobalVariable(name: "main.events", linkageName: "main.events", type: !0)
!4 = !DISubprogram(name: "main.myFunc", linkageName: "main.myFunc")
some non-metadata line with dots main.foo
!5 = !DIExpression()
`

func TestSanitizeBTFNames(t *testing.T) {
	text := runSanitizeBTF(t, sanitizeBTFInput)

	tests := []struct {
		name        string
		wantContain []string
		notContain  []string
		check       func(t *testing.T, text string)
	}{
		{
			name:        "dots replaced with underscores in struct name",
			wantContain: []string{`name: "main_bpfMapDef"`},
		},
		{
			name: "pointer type name stripped",
			check: func(t *testing.T, text string) {
				t.Helper()
				for _, line := range strings.Split(text, "\n") {
					if strings.Contains(line, "DW_TAG_pointer_type") && strings.Contains(line, "unsafe") {
						t.Error("pointer type name should be stripped entirely")
					}
				}
			},
		},
		{
			name:        "basic type without dots unchanged",
			wantContain: []string{`name: "uint32"`},
		},
		{
			name:        "global variable dots replaced",
			wantContain: []string{`name: "main_events"`, `linkageName: "main_events"`},
		},
		{
			name:        "subprogram dots replaced",
			wantContain: []string{`name: "main_myFunc"`},
		},
		{
			name:        "non-metadata lines unchanged",
			wantContain: []string{"main.foo"},
		},
		{
			name:        "unrelated metadata unchanged",
			wantContain: []string{"!DIExpression()"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
