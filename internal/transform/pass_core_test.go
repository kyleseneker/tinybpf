package transform

import (
	"testing"

	"github.com/kyleseneker/tinybpf/internal/ir"
)

func TestExtractDBG(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{", !dbg !10", "!dbg !10"},
		{", !dbg !42, !other !5", "!dbg !42"},
		{"no dbg here", ""},
		{"", ""},
		{"!dbg !0", "!dbg !0"},
	}
	for _, tt := range tests {
		if got := extractDBG(tt.in); got != tt.want {
			t.Errorf("extractDBG(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestPreserveStructAccessCall(t *testing.T) {
	tests := []struct {
		name                          string
		base, elemType, gepIdx, diIdx string
		wantContains                  string
	}{
		{
			name:         "basic call",
			base:         "%0",
			elemType:     "%main.bpfCoreTaskStruct",
			gepIdx:       "0",
			diIdx:        "1",
			wantContains: "call ptr @llvm.preserve.struct.access.index.p0.p0(ptr elementtype(%main.bpfCoreTaskStruct) %0, i32 0, i32 1)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := preserveStructAccessCall(tt.base, tt.elemType, tt.gepIdx, tt.diIdx)
			if got != tt.wantContains {
				t.Errorf("got  %q\nwant %q", got, tt.wantContains)
			}
		})
	}
}

func TestSoleType(t *testing.T) {
	tests := []struct {
		name         string
		fieldOffsets map[string][]int
		want         string
	}{
		{
			name:         "single type",
			fieldOffsets: map[string][]int{"%main.bpfCoreTaskStruct": {0, 4}},
			want:         "%main.bpfCoreTaskStruct",
		},
		{
			name: "multiple types",
			fieldOffsets: map[string][]int{
				"%main.bpfCoreTaskStruct": {0, 4},
				"%main.bpfCoreFileStruct": {0, 8},
			},
			want: "",
		},
		{
			name:         "empty",
			fieldOffsets: map[string][]int{},
			want:         "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &coreExistsContext{fieldOffsets: tt.fieldOffsets}
			if got := ctx.soleType(); got != tt.want {
				t.Errorf("soleType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveField(t *testing.T) {
	tests := []struct {
		name         string
		fieldOffsets map[string][]int
		byteOffset   int
		wantType     string
		wantIdx      int
	}{
		{
			name:         "found",
			fieldOffsets: map[string][]int{"%main.bpfCoreA": {0, 4, 8}},
			byteOffset:   4,
			wantType:     "%main.bpfCoreA",
			wantIdx:      1,
		},
		{
			name:         "not found",
			fieldOffsets: map[string][]int{"%main.bpfCoreA": {0, 4, 8}},
			byteOffset:   12,
			wantType:     "",
			wantIdx:      -1,
		},
		{
			name:         "empty",
			fieldOffsets: map[string][]int{},
			byteOffset:   0,
			wantType:     "",
			wantIdx:      -1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &coreExistsContext{fieldOffsets: tt.fieldOffsets}
			gotType, gotIdx := ctx.resolveField(tt.byteOffset)
			if gotType != tt.wantType || gotIdx != tt.wantIdx {
				t.Errorf("resolveField(%d) = (%q, %d), want (%q, %d)",
					tt.byteOffset, gotType, gotIdx, tt.wantType, tt.wantIdx)
			}
		})
	}
}

func TestTypeNames(t *testing.T) {
	tests := []struct {
		name         string
		fieldOffsets map[string][]int
		want         string
	}{
		{
			name:         "empty",
			fieldOffsets: map[string][]int{},
			want:         "none",
		},
		{
			name:         "single",
			fieldOffsets: map[string][]int{"T": {0, 4}},
			want:         "T[0 4]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &coreExistsContext{fieldOffsets: tt.fieldOffsets}
			got := ctx.typeNames()
			if tt.name == "empty" && got != tt.want {
				t.Errorf("typeNames() = %q, want %q", got, tt.want)
			}
			if tt.name == "single" && got != tt.want {
				t.Errorf("typeNames() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFallbackTypeBody(t *testing.T) {
	tests := []struct {
		offsets []int
		want    string
	}{
		{[]int{0, 4, 8}, "[4 x i8], [4 x i8], [1 x i8]"},
		{[]int{0}, "[1 x i8]"},
	}
	for _, tt := range tests {
		if got := fallbackTypeBody(tt.offsets); got != tt.want {
			t.Errorf("fallbackTypeBody(%v) = %q, want %q", tt.offsets, got, tt.want)
		}
	}
}

func TestFallbackSegmentSize(t *testing.T) {
	offsets := []int{0, 4, 8}
	tests := []struct {
		idx  int
		want int
	}{
		{0, 4},
		{1, 4},
		{2, 1},
	}
	for _, tt := range tests {
		if got := fallbackSegmentSize(offsets, tt.idx); got != tt.want {
			t.Errorf("fallbackSegmentSize(%v, %d) = %d, want %d", offsets, tt.idx, got, tt.want)
		}
	}
}

func TestFallbackTotalSize(t *testing.T) {
	tests := []struct {
		offsets []int
		want    int
	}{
		{[]int{0, 4, 8}, 9},
		{[]int{0}, 1},
		{[]int{0, 4}, 5},
	}
	for _, tt := range tests {
		if got := fallbackTotalSize(tt.offsets); got != tt.want {
			t.Errorf("fallbackTotalSize(%v) = %d, want %d", tt.offsets, got, tt.want)
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
		if got := parseLeadingInt(tt.in); got != tt.want {
			t.Errorf("parseLeadingInt(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestIsMemberMeta(t *testing.T) {
	tests := []struct {
		line string
		want bool
	}{
		{`!5 = !DIDerivedType(tag: DW_TAG_member, name: "Pid", size: 32)`, true},
		{`!5 = !DICompositeType(tag: DW_TAG_structure_type)`, false},
		{`!5 = !DIDerivedType(tag: DW_TAG_pointer_type)`, false},
		{"", false},
	}
	for _, tt := range tests {
		if got := isMemberMeta(tt.line); got != tt.want {
			t.Errorf("isMemberMeta(%q) = %v, want %v", tt.line, got, tt.want)
		}
	}
}

func TestIRTypeSize(t *testing.T) {
	tests := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"i8", 1, false},
		{"i16", 2, false},
		{"i32", 4, false},
		{"i64", 8, false},
		{"ptr", 8, false},
		{"[16 x i8]", 16, false},
		{"[4 x i32]", 16, false},
		{"float", 0, true},
		{"[bad]", 0, true},
		{"[4 x float]", 0, true},
		{"[abc x i8]", 0, true},
	}
	for _, tt := range tests {
		got, err := irTypeSize(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("irTypeSize(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("irTypeSize(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestCumulativeOffsets(t *testing.T) {
	tests := []struct {
		sizes []int
		want  []int
	}{
		{[]int{4, 4, 16}, []int{0, 4, 8}},
		{[]int{8}, []int{0}},
		{[]int{1, 2, 4}, []int{0, 1, 3}},
	}
	for _, tt := range tests {
		got := cumulativeOffsets(tt.sizes)
		if len(got) != len(tt.want) {
			t.Errorf("cumulativeOffsets(%v) = %v, want %v", tt.sizes, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("cumulativeOffsets(%v)[%d] = %d, want %d", tt.sizes, i, got[i], tt.want[i])
			}
		}
	}
}

func TestIRTypeAlign(t *testing.T) {
	tests := []struct {
		name string
		typ  string
		want int
	}{
		{"i8", "i8", 1},
		{"i16", "i16", 2},
		{"i32", "i32", 4},
		{"i64", "i64", 8},
		{"ptr", "ptr", 8},
		{"array of i32", "[4 x i32]", 4},
		{"array of i8", "[16 x i8]", 1},
		{"unknown type", "float", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := irTypeAlign(tt.typ); got != tt.want {
				t.Errorf("irTypeAlign(%q) = %d, want %d", tt.typ, got, tt.want)
			}
		})
	}
}

func TestAlignedFieldOffsets(t *testing.T) {
	tests := []struct {
		name    string
		fields  []string
		want    []int
		wantErr bool
	}{
		{
			name:   "uniform i32 no padding",
			fields: []string{"i32", "i32", "i32"},
			want:   []int{0, 4, 8},
		},
		{
			name:   "i8 then i64 needs padding",
			fields: []string{"i8", "i64"},
			want:   []int{0, 8},
		},
		{
			name:   "i32 then i64 needs padding",
			fields: []string{"i32", "i64"},
			want:   []int{0, 8},
		},
		{
			name:   "i64 then i8 no padding",
			fields: []string{"i64", "i8"},
			want:   []int{0, 8},
		},
		{
			name:   "i8 i16 i32 i64 mixed alignment",
			fields: []string{"i8", "i16", "i32", "i64"},
			want:   []int{0, 2, 4, 8},
		},
		{
			name:   "single field",
			fields: []string{"i32"},
			want:   []int{0},
		},
		{
			name:    "unsupported type",
			fields:  []string{"i8", "x86_fp80"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := alignedFieldOffsets(tt.fields)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("alignedFieldOffsets(%v) = %v, want %v", tt.fields, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("alignedFieldOffsets(%v)[%d] = %d, want %d", tt.fields, got, got[i], tt.want[i])
				}
			}
		})
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
		if got := fieldIndexFromOffset(offsets, tt.offset); got != tt.want {
			t.Errorf("fieldIndexFromOffset(%v, %d) = %d, want %d", offsets, tt.offset, got, tt.want)
		}
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

func TestRenameCoreType(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "bpfCore prefix",
			line: `!5 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfCoreTaskStruct", size: 64)`,
			want: `!5 = !DICompositeType(tag: DW_TAG_structure_type, name: "task_struct", size: 64)`,
		},
		{
			name: "no name field",
			line: `!5 = !DICompositeType(tag: DW_TAG_structure_type)`,
			want: `!5 = !DICompositeType(tag: DW_TAG_structure_type)`,
		},
		{
			name: "name is just bpfCore",
			line: `name: "bpfCore"`,
			want: `name: "bpfCore"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := renameCoreType(tt.line); got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}

func TestRenameCoreField(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "camel to snake",
			line: `!10 = !DIDerivedType(tag: DW_TAG_member, name: "LoginUid", size: 32)`,
			want: `!10 = !DIDerivedType(tag: DW_TAG_member, name: "login_uid", size: 32)`,
		},
		{
			name: "single word",
			line: `!10 = !DIDerivedType(tag: DW_TAG_member, name: "Pid", size: 32)`,
			want: `!10 = !DIDerivedType(tag: DW_TAG_member, name: "pid", size: 32)`,
		},
		{
			name: "no name field",
			line: `!10 = !DIDerivedType(tag: DW_TAG_member)`,
			want: `!10 = !DIDerivedType(tag: DW_TAG_member)`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := renameCoreField(tt.line); got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}

func TestCorePassModule(t *testing.T) {
	tests := []struct {
		name    string
		module  *ir.Module
		wantErr bool
	}{
		{
			name:    "empty module succeeds",
			module:  &ir.Module{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := corePassModule(tt.module)
			if (err != nil) != tt.wantErr {
				t.Fatalf("corePassModule() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAddCoreExistsIntrinsics(t *testing.T) {
	tests := []struct {
		name      string
		field     bool
		typ       bool
		access    bool
		wantDecls int
	}{
		{"none needed", false, false, false, 0},
		{"field only", true, false, false, 1},
		{"type only", false, true, false, 1},
		{"all three", true, true, true, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &ir.Module{Entries: []ir.TopLevelEntry{{Kind: ir.TopFunction}}}
			addCoreExistsIntrinsics(m, tt.field, tt.typ, tt.access)
			if len(m.Declares) != tt.wantDecls {
				t.Errorf("declares = %d, want %d", len(m.Declares), tt.wantDecls)
			}
		})
	}
}

func TestResolveMetaRefsFromAST(t *testing.T) {
	tests := []struct {
		name        string
		elementsRef string
		metaByID    map[int]*ir.MetadataNode
		wantLen     int
	}{
		{
			name:        "bad ref",
			elementsRef: "not_a_ref",
			wantLen:     0,
		},
		{
			name:        "missing node",
			elementsRef: "!99",
			metaByID:    map[int]*ir.MetadataNode{},
			wantLen:     0,
		},
		{
			name:        "empty tuple",
			elementsRef: "!0",
			metaByID:    map[int]*ir.MetadataNode{0: {ID: 0, Tuple: nil}},
			wantLen:     0,
		},
		{
			name:        "direct refs",
			elementsRef: "!0",
			metaByID: map[int]*ir.MetadataNode{
				0: {ID: 0, Tuple: []string{"!1", "!2"}},
				1: {ID: 1, Kind: "DIDerivedType"},
				2: {ID: 2, Kind: "DIDerivedType"},
			},
			wantLen: 2,
		},
		{
			name:        "nested tuple",
			elementsRef: "!0",
			metaByID: map[int]*ir.MetadataNode{
				0: {ID: 0, Tuple: []string{"!1"}},
				1: {ID: 1, Kind: "", Tuple: []string{"!2", "!3"}},
				2: {ID: 2, Kind: "DIDerivedType"},
				3: {ID: 3, Kind: "DIDerivedType"},
			},
			wantLen: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveMetaRefsFromAST(tt.elementsRef, tt.metaByID)
			if len(got) != tt.wantLen {
				t.Errorf("resolveMetaRefsFromAST() returned %d refs, want %d: %v", len(got), tt.wantLen, got)
			}
		})
	}
}

func TestFindMaxMetaIDFromModule(t *testing.T) {
	tests := []struct {
		name  string
		nodes []*ir.MetadataNode
		extra []ir.TopLevelEntry
		want  int
	}{
		{
			name:  "from nodes",
			nodes: []*ir.MetadataNode{{ID: 3}, {ID: 7}, {ID: 1}},
			want:  7,
		},
		{
			name:  "from entries",
			extra: []ir.TopLevelEntry{{Kind: ir.TopMetadata, Raw: "!42 = !{}"}},
			want:  42,
		},
		{
			name: "empty",
			want: -1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &ir.Module{MetadataNodes: tt.nodes, Entries: tt.extra}
			if got := findMaxMetaIDFromModule(m); got != tt.want {
				t.Errorf("findMaxMetaIDFromModule() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestAppendMetaEntryToModule(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantLen int
		wantRaw string
	}{
		{
			name:    "appends single metadata entry",
			raw:     "!0 = !{}",
			wantLen: 1,
			wantRaw: "!0 = !{}",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &ir.Module{}
			appendMetaEntryToModule(m, tt.raw)
			if len(m.Entries) != tt.wantLen || m.Entries[0].Raw != tt.wantRaw {
				t.Errorf("unexpected entries: %v", m.Entries)
			}
		})
	}
}

func TestStripCoreExistsDeclsFromModule(t *testing.T) {
	tests := []struct {
		name        string
		declNames   []string
		wantRemoved []bool
	}{
		{
			name:        "strips core exists decls but keeps others",
			declNames:   []string{"main.bpfCoreFieldExists", "main.bpfCoreTypeExists", "main.bpfGetCurrentPidTgid"},
			wantRemoved: []bool{true, true, false},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var entries []ir.TopLevelEntry
			for _, name := range tt.declNames {
				entries = append(entries, ir.TopLevelEntry{
					Kind:    ir.TopDeclare,
					Declare: &ir.Declare{Name: name},
				})
			}
			m := &ir.Module{Entries: entries}
			stripCoreExistsDeclsFromModule(m)
			for i, want := range tt.wantRemoved {
				if m.Entries[i].Removed != want {
					t.Errorf("%s: Removed = %v, want %v", tt.declNames[i], m.Entries[i].Removed, want)
				}
			}
		})
	}
}

func TestAddIntrinsicDeclToModule(t *testing.T) {
	t.Run("adds new decl", func(t *testing.T) {
		m := &ir.Module{
			Entries: []ir.TopLevelEntry{
				{Kind: ir.TopFunction},
			},
		}
		addIntrinsicDeclToModule(m, "llvm.bpf.preserve.field.info", fieldInfoIntrinsicDecl)
		if len(m.Declares) != 1 {
			t.Fatalf("expected 1 declare, got %d", len(m.Declares))
		}
		if m.Declares[0].Name != "llvm.bpf.preserve.field.info" {
			t.Errorf("name = %q", m.Declares[0].Name)
		}
	})

	t.Run("skips when already exists in declares", func(t *testing.T) {
		existing := &ir.Declare{Name: "llvm.bpf.preserve.field.info"}
		m := &ir.Module{Declares: []*ir.Declare{existing}}
		addIntrinsicDeclToModule(m, "llvm.bpf.preserve.field.info", fieldInfoIntrinsicDecl)
		if len(m.Declares) != 1 {
			t.Errorf("expected 1 declare (no dup), got %d", len(m.Declares))
		}
	})

	t.Run("skips when already exists in entries", func(t *testing.T) {
		m := &ir.Module{
			Entries: []ir.TopLevelEntry{
				{Kind: ir.TopDeclare, Raw: fieldInfoIntrinsicDecl},
			},
		}
		addIntrinsicDeclToModule(m, "llvm.bpf.preserve.field.info", fieldInfoIntrinsicDecl)
		if len(m.Declares) != 0 {
			t.Errorf("expected 0 new declares, got %d", len(m.Declares))
		}
	})

	t.Run("appends when no func entry", func(t *testing.T) {
		m := &ir.Module{
			Entries: []ir.TopLevelEntry{
				{Kind: ir.TopGlobal},
			},
		}
		addIntrinsicDeclToModule(m, "llvm.bpf.preserve.field.info", fieldInfoIntrinsicDecl)
		if len(m.Entries) != 2 {
			t.Fatalf("expected 2 entries, got %d", len(m.Entries))
		}
		if m.Entries[1].Kind != ir.TopDeclare {
			t.Error("expected last entry to be declare")
		}
	})
}

func TestCollectCoreStructMetaIDs(t *testing.T) {
	tests := []struct {
		name      string
		entries   []ir.TopLevelEntry
		wantIn    []int
		wantNotIn []int
	}{
		{
			name: "collects core struct IDs only",
			entries: []ir.TopLevelEntry{
				{Kind: ir.TopMetadata, Raw: `!5 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfCoreTaskStruct", elements: !6)`},
				{Kind: ir.TopMetadata, Raw: `!6 = !{!7}`},
				{Kind: ir.TopMetadata, Raw: `!7 = !DIDerivedType(tag: DW_TAG_member, name: "Pid")`},
			},
			wantIn:    []int{5},
			wantNotIn: []int{6, 7},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &ir.Module{Entries: tt.entries}
			ids := collectCoreStructMetaIDs(m)
			for _, id := range tt.wantIn {
				if !ids[id] {
					t.Errorf("expected ID %d in core struct meta IDs", id)
				}
			}
			for _, id := range tt.wantNotIn {
				if ids[id] {
					t.Errorf("ID %d should not be in core struct meta IDs", id)
				}
			}
		})
	}
}

func TestCollectCoreMemberIDs(t *testing.T) {
	tests := []struct {
		name    string
		entries []ir.TopLevelEntry
		wantIn  []int
	}{
		{
			name: "collects elements ref ID",
			entries: []ir.TopLevelEntry{
				{Kind: ir.TopMetadata, Raw: `!5 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfCoreTaskStruct", elements: !6)`},
				{Kind: ir.TopMetadata, Raw: `!6 = !{!7, !8}`},
			},
			wantIn: []int{6},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &ir.Module{Entries: tt.entries}
			ids := collectCoreMemberIDs(m)
			for _, id := range tt.wantIn {
				if !ids[id] {
					t.Errorf("expected ID %d in core member IDs", id)
				}
			}
		})
	}
}
