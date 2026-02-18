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
		lines := strings.Split(ir, "\n")
		sanitizeBTFNames(lines)
	})
}

func TestParseI32InitializerError(t *testing.T) {
	if got := parseI32Initializer("i32 abc, i32 1"); got != nil {
		t.Fatalf("expected nil for malformed initializer, got %v", got)
	}
}

func TestRewriteMapForBTF(t *testing.T) {
	//nolint:dupword
	input := strings.Split(strings.TrimSpace(`
%main.bpfMapDef = type { i32, i32, i32, i32, i32 }
@main.events = global %main.bpfMapDef { i32 27, i32 0, i32 0, i32 16777216, i32 0 }, align 4
!0 = !DIDerivedType(tag: DW_TAG_member, name: "Type", baseType: !1, size: 32, offset: 0)
!1 = !DIBasicType(name: "uint32", size: 32, encoding: DW_ATE_unsigned)
!2 = !DIDerivedType(tag: DW_TAG_member, name: "KeySize", baseType: !1, size: 32, offset: 32)
!3 = !DIDerivedType(tag: DW_TAG_member, name: "ValueSize", baseType: !1, size: 32, offset: 64)
!4 = !DIDerivedType(tag: DW_TAG_member, name: "MaxEntries", baseType: !1, size: 32, offset: 96)
!5 = !DIDerivedType(tag: DW_TAG_member, name: "MapFlags", baseType: !1, size: 32, offset: 128)
!6 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfMapDef", size: 160, elements: !{!0, !2, !3, !4, !5})
`), "\n")

	got := rewriteMapForBTF(input)
	text := strings.Join(got, "\n")

	t.Run("global rewritten to ptr struct", func(t *testing.T) {
		if !strings.Contains(text, "global { ptr, ptr, ptr, ptr, ptr } zeroinitializer") { //nolint:dupword
			t.Error("map global not rewritten to pointer struct")
		}
	})

	t.Run("type def rewritten", func(t *testing.T) {
		if !strings.Contains(text, "{ ptr, ptr, ptr, ptr, ptr }") { //nolint:dupword
			t.Error("type definition not rewritten to pointers")
		}
	})

	t.Run("member names rewritten to C conventions", func(t *testing.T) {
		for _, cName := range []string{"type", "key_size", "value_size", "max_entries", "map_flags"} {
			want := `name: "` + cName + `"`
			if !strings.Contains(text, want) {
				t.Errorf("missing C field name %q", cName)
			}
		}
	})

	t.Run("member sizes rewritten to 64", func(t *testing.T) {
		for _, line := range got {
			if strings.Contains(line, "DW_TAG_member") && strings.Contains(line, `name: "type"`) {
				if !strings.Contains(line, "size: 64") {
					t.Error("member size not rewritten to 64")
				}
			}
		}
	})

	t.Run("struct size rewritten to 320", func(t *testing.T) {
		if !strings.Contains(text, "size: 320") {
			t.Error("struct size not updated to 320")
		}
	})

	t.Run("BTF metadata appended", func(t *testing.T) {
		if !strings.Contains(text, "DIBasicType(name: \"int\", size: 32") {
			t.Error("int base type metadata not appended")
		}
		if !strings.Contains(text, "DISubrange(count: 27)") {
			t.Error("subrange for Type field (27) not found")
		}
		if !strings.Contains(text, "DISubrange(count: 16777216)") {
			t.Error("subrange for MaxEntries field not found")
		}
		if !strings.Contains(text, "DW_TAG_array_type") {
			t.Error("array type metadata not appended")
		}
		if !strings.Contains(text, "DW_TAG_pointer_type") {
			t.Error("pointer type metadata not appended")
		}
	})

	t.Run("no match returns unchanged", func(t *testing.T) {
		input := []string{"just some IR", "with no map globals"}
		got := rewriteMapForBTF(input)
		if strings.Join(got, "\n") != strings.Join(input, "\n") {
			t.Error("lines should be unchanged when no maps found")
		}
	})
}

func TestSanitizeBTFNames(t *testing.T) {
	input := strings.Split(strings.TrimSpace(`
!0 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfMapDef", size: 160)
!1 = !DIDerivedType(tag: DW_TAG_pointer_type, name: "unsafe.Pointer", baseType: !2, size: 64)
!2 = !DIBasicType(name: "uint32", size: 32, encoding: DW_ATE_unsigned)
!3 = !DIGlobalVariable(name: "main.events", linkageName: "main.events", type: !0)
!4 = !DISubprogram(name: "main.myFunc", linkageName: "main.myFunc")
some non-metadata line with dots main.foo
!5 = !DIExpression()
`), "\n")

	got := sanitizeBTFNames(input)
	text := strings.Join(got, "\n")

	t.Run("dots replaced with underscores in struct name", func(t *testing.T) {
		if !strings.Contains(text, `name: "main_bpfMapDef"`) {
			t.Error("dots not replaced in composite type name")
		}
	})

	t.Run("pointer type name stripped", func(t *testing.T) {
		for _, line := range got {
			if strings.Contains(line, "DW_TAG_pointer_type") {
				if strings.Contains(line, "unsafe") {
					t.Error("pointer type name should be stripped entirely")
				}
			}
		}
	})

	t.Run("basic type without dots unchanged", func(t *testing.T) {
		if !strings.Contains(text, `name: "uint32"`) {
			t.Error("basic type name without dots should be preserved")
		}
	})

	t.Run("global variable dots replaced", func(t *testing.T) {
		if !strings.Contains(text, `name: "main_events"`) {
			t.Error("dots not replaced in global variable name")
		}
		if !strings.Contains(text, `linkageName: "main_events"`) {
			t.Error("dots not replaced in global variable linkage name")
		}
	})

	t.Run("subprogram dots replaced", func(t *testing.T) {
		if !strings.Contains(text, `name: "main_myFunc"`) {
			t.Error("dots not replaced in subprogram name")
		}
	})

	t.Run("non-metadata lines unchanged", func(t *testing.T) {
		if !strings.Contains(text, "main.foo") {
			t.Error("non-metadata lines should not be modified")
		}
	})

	t.Run("unrelated metadata unchanged", func(t *testing.T) {
		if !strings.Contains(text, "!DIExpression()") {
			t.Error("unrelated metadata nodes should not be modified")
		}
	})
}
