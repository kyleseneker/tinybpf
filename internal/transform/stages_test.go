package transform

import (
	"io"
	"strings"
	"testing"

	"github.com/kyleseneker/tinybpf/internal/ir"
)

func TestBuildModuleStagesOrder(t *testing.T) {
	tests := []struct {
		idx  int
		name string
	}{
		{0, "module-rewrite"},
		{1, "extract-programs"},
		{2, "replace-alloc"},
		{3, "rewrite-helpers"},
		{4, "core"},
		{5, "sections"},
		{6, "map-btf"},
		{7, "finalize"},
	}

	stages := buildModuleStages(Options{Stdout: io.Discard})

	if len(stages) != len(tests) {
		t.Fatalf("expected %d stages, got %d", len(tests), len(stages))
	}
	for _, tt := range tests {
		if stages[tt.idx].name != tt.name {
			t.Errorf("stage %d: expected %q, got %q", tt.idx, tt.name, stages[tt.idx].name)
		}
	}
}

// ---------------------------------------------------------------------------
// moduleRewriteModule
// ---------------------------------------------------------------------------

func TestModuleRewriteModule(t *testing.T) {
	ag := &ir.AttrGroup{
		ID:   "0",
		Body: `{ "target-cpu"="generic" nounwind }`,
	}
	m := &ir.Module{
		Triple:     "x86_64-unknown-linux-gnu",
		DataLayout: "e-m:o",
		AttrGroups: []*ir.AttrGroup{ag},
	}
	if err := moduleRewriteModule(m); err != nil {
		t.Fatal(err)
	}
	if m.Triple != "bpf" {
		t.Errorf("triple = %q, want %q", m.Triple, "bpf")
	}
	if strings.Contains(ag.Body, "target-cpu") {
		t.Error("target-cpu not stripped")
	}
}

func TestRetargetModule(t *testing.T) {
	m := &ir.Module{Triple: "x86_64-unknown-linux-gnu", DataLayout: "e-m:o"}
	if err := retargetModule(m); err != nil {
		t.Fatal(err)
	}
	if m.Triple != "bpf" {
		t.Errorf("triple = %q, want %q", m.Triple, "bpf")
	}
}

// ---------------------------------------------------------------------------
// stripAttributesModule
// ---------------------------------------------------------------------------

func TestStripAttributesModule(t *testing.T) {
	ag := &ir.AttrGroup{
		ID:   "0",
		Body: `{ "target-cpu"="generic" "target-features"="+neon" nounwind }`,
	}
	m := &ir.Module{AttrGroups: []*ir.AttrGroup{ag}}
	if err := stripAttributesModule(m); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ag.Body, "target-cpu") {
		t.Error("target-cpu not stripped")
	}
	if strings.Contains(ag.Body, "target-features") {
		t.Error("target-features not stripped")
	}
	if !ag.Modified {
		t.Error("expected Modified = true")
	}
}

// ---------------------------------------------------------------------------
// markGlobalRemoved
// ---------------------------------------------------------------------------

func TestMarkGlobalRemoved(t *testing.T) {
	g := &ir.Global{Name: "runtime.scheduler"}
	m := &ir.Module{
		Entries: []ir.TopLevelEntry{
			{Kind: ir.TopGlobal, Global: g},
			{Kind: ir.TopFunction},
		},
	}
	markGlobalRemoved(m, g)
	if !m.Entries[0].Removed {
		t.Error("expected entry 0 to be removed")
	}
	if m.Entries[1].Removed {
		t.Error("entry 1 should not be removed")
	}
}

// ---------------------------------------------------------------------------
// classifyGlobalSectionFromAST
// ---------------------------------------------------------------------------

func TestClassifyGlobalSectionFromAST(t *testing.T) {
	tests := []struct {
		name   string
		global ir.Global
		want   string
	}{
		{"zeroinitializer -> .bss", ir.Global{Initializer: "zeroinitializer"}, ".bss"},
		{"constant -> .rodata", ir.Global{Linkage: "constant"}, ".rodata"},
		{"global with init -> .data", ir.Global{Linkage: "global", Initializer: "42"}, ".data"},
		{"global no init -> .data", ir.Global{Linkage: "global"}, ".data"},
		{"empty linkage with init -> .data", ir.Global{Initializer: "42"}, ".data"},
		{"empty -> empty", ir.Global{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyGlobalSectionFromAST(&tt.global); got != tt.want {
				t.Errorf("classifyGlobalSectionFromAST() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// addIntrinsicDeclToModule
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// findMaxMetaIDFromModule
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// appendMetaEntryToModule
// ---------------------------------------------------------------------------

func TestAppendMetaEntryToModule(t *testing.T) {
	m := &ir.Module{}
	appendMetaEntryToModule(m, "!0 = !{}")
	if len(m.Entries) != 1 || m.Entries[0].Raw != "!0 = !{}" {
		t.Errorf("unexpected entries: %v", m.Entries)
	}
}

// ---------------------------------------------------------------------------
// stripCoreExistsDeclsFromModule
// ---------------------------------------------------------------------------

func TestStripCoreExistsDeclsFromModule(t *testing.T) {
	fieldDecl := &ir.Declare{Name: "main.bpfCoreFieldExists"}
	typeDecl := &ir.Declare{Name: "main.bpfCoreTypeExists"}
	otherDecl := &ir.Declare{Name: "main.bpfGetCurrentPidTgid"}
	m := &ir.Module{
		Entries: []ir.TopLevelEntry{
			{Kind: ir.TopDeclare, Declare: fieldDecl},
			{Kind: ir.TopDeclare, Declare: typeDecl},
			{Kind: ir.TopDeclare, Declare: otherDecl},
		},
	}
	stripCoreExistsDeclsFromModule(m)
	if !m.Entries[0].Removed {
		t.Error("bpfCoreFieldExists not removed")
	}
	if !m.Entries[1].Removed {
		t.Error("bpfCoreTypeExists not removed")
	}
	if m.Entries[2].Removed {
		t.Error("unrelated declare should not be removed")
	}
}

// ---------------------------------------------------------------------------
// corePassModule
// ---------------------------------------------------------------------------

func TestCorePassModule(t *testing.T) {
	m := &ir.Module{}
	if err := corePassModule(m); err != nil {
		t.Fatalf("corePassModule on empty module: %v", err)
	}
}

// ---------------------------------------------------------------------------
// sectionsPassModule
// ---------------------------------------------------------------------------

func TestSectionsPassModule(t *testing.T) {
	fn := &ir.Function{Name: "probe_connect", Raw: "define i32 @probe_connect() {"}
	g := &ir.Global{Name: "counter", Linkage: "global", Initializer: "0", Raw: "@counter = global i32 0"}
	m := &ir.Module{
		Globals:   []*ir.Global{g},
		Functions: []*ir.Function{fn},
		Entries: []ir.TopLevelEntry{
			{Kind: ir.TopGlobal, Global: g, Raw: g.Raw},
			{Kind: ir.TopFunction, Function: fn, Raw: fn.Raw},
		},
	}
	sections := map[string]string{"probe_connect": "tracepoint/tcp/tcp_connect"}
	if err := sectionsPassModule(m, sections); err != nil {
		t.Fatal(err)
	}
	if g.Section != ".data" {
		t.Errorf("global section = %q, want %q", g.Section, ".data")
	}
	if !strings.Contains(fn.Raw, "section") {
		t.Error("function should have a section after sectionsPassModule")
	}
}

// ---------------------------------------------------------------------------
// mapBTFPassModule
// ---------------------------------------------------------------------------

func TestMapBTFPassModule(t *testing.T) {
	m := &ir.Module{}
	if err := mapBTFPassModule(m); err != nil {
		t.Fatalf("mapBTFPassModule on empty module: %v", err)
	}
}

// ---------------------------------------------------------------------------
// finalizeModule
// ---------------------------------------------------------------------------

func TestFinalizeModule(t *testing.T) {
	fn := &ir.Function{Name: "my_func", Raw: "define i32 @my_func() {"}
	orphanDecl := &ir.Declare{Name: "unused_func", Raw: "declare void @unused_func()"}
	m := &ir.Module{
		Functions: []*ir.Function{fn},
		Declares:  []*ir.Declare{orphanDecl},
		Entries: []ir.TopLevelEntry{
			{Kind: ir.TopDeclare, Declare: orphanDecl, Raw: orphanDecl.Raw},
			{Kind: ir.TopBlank, Raw: ""},
			{Kind: ir.TopFunction, Function: fn, Raw: fn.Raw},
			{Kind: ir.TopBlank, Raw: ""},
		},
	}
	if err := finalizeModule(m); err != nil {
		t.Fatal(err)
	}
	hasLicense := false
	for _, g := range m.Globals {
		if g.Section == "license" {
			hasLicense = true
		}
	}
	if !hasLicense {
		t.Error("expected license global after finalizeModule")
	}
	for _, e := range m.Entries {
		if e.Kind == ir.TopDeclare && !e.Removed && e.Declare != nil && e.Declare.Name == "unused_func" {
			t.Error("unreferenced declare should be cleaned up")
		}
	}
}

func TestBuildModuleIdentRefs(t *testing.T) {
	m := &ir.Module{
		Entries: []ir.TopLevelEntry{
			{Kind: ir.TopGlobal, Raw: `@my_global = global i32 42`},
			{Kind: ir.TopFunction, Function: &ir.Function{
				Raw:     `define i32 @my_func(ptr %ctx) {`,
				BodyRaw: []string{"  %0 = load i32, ptr @my_global"},
			}},
		},
	}
	refs := buildModuleIdentRefs(m)
	if len(refs["@my_global"]) != 2 {
		t.Errorf("expected @my_global referenced in 2 entries, got %d", len(refs["@my_global"]))
	}
	if len(refs["@my_func"]) != 1 {
		t.Errorf("expected @my_func referenced in 1 entry, got %d", len(refs["@my_func"]))
	}
}

func TestIdentReferencedElsewhere(t *testing.T) {
	tests := []struct {
		name   string
		refs   map[string][]int
		ident  string
		defIdx int
		want   bool
	}{
		{"referenced elsewhere", map[string][]int{"@foo": {0, 3}}, "@foo", 0, true},
		{"only self-reference", map[string][]int{"@foo": {2}}, "@foo", 2, false},
		{"no references", map[string][]int{}, "@foo", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := identReferencedElsewhere(tt.refs, tt.ident, tt.defIdx); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsAttrComment(t *testing.T) {
	tests := []struct {
		name  string
		entry ir.TopLevelEntry
		want  bool
	}{
		{"attrs comment", ir.TopLevelEntry{Kind: ir.TopComment, Raw: "; Function Attrs: nounwind"}, true},
		{"other comment", ir.TopLevelEntry{Kind: ir.TopComment, Raw: "; some comment"}, false},
		{"removed", ir.TopLevelEntry{Kind: ir.TopComment, Raw: "; Function Attrs:", Removed: true}, false},
		{"wrong kind", ir.TopLevelEntry{Kind: ir.TopBlank, Raw: "; Function Attrs:"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAttrComment(tt.entry); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCollectUsedAttrIDsFromModule(t *testing.T) {
	m := &ir.Module{
		Entries: []ir.TopLevelEntry{
			{Kind: ir.TopFunction, Function: &ir.Function{
				Raw:     `define i32 @f(ptr %ctx) #0 {`,
				BodyRaw: []string{"  ret i32 0"},
			}},
			{Kind: ir.TopAttrGroup, AttrGroup: &ir.AttrGroup{ID: "0", Body: "nounwind"}},
			{Kind: ir.TopAttrGroup, AttrGroup: &ir.AttrGroup{ID: "1", Body: "readonly"}},
		},
	}
	used := collectUsedAttrIDsFromModule(m)
	if !used["0"] {
		t.Error("attr #0 should be used")
	}
	if used["1"] {
		t.Error("attr #1 should not be used")
	}
}

func TestMarkOrphanedAttrCommentsInModule(t *testing.T) {
	m := &ir.Module{
		Entries: []ir.TopLevelEntry{
			{Kind: ir.TopComment, Raw: "; Function Attrs: nounwind"},
			{Kind: ir.TopFunction, Function: &ir.Function{Raw: "define i32 @f() {"}},
			{Kind: ir.TopComment, Raw: "; Function Attrs: readonly"},
			{Kind: ir.TopMetadata, Raw: "!0 = !{}"},
		},
	}
	markOrphanedAttrCommentsInModule(m)
	if m.Entries[0].Removed {
		t.Error("comment before function should be kept")
	}
	if !m.Entries[2].Removed {
		t.Error("orphaned comment (before metadata) should be removed")
	}
}

func TestCompactModuleEntries(t *testing.T) {
	m := &ir.Module{
		Entries: []ir.TopLevelEntry{
			{Kind: ir.TopGlobal, Raw: "@g = global i32 0"},
			{Kind: ir.TopBlank, Raw: ""},
			{Kind: ir.TopBlank, Raw: ""},
			{Kind: ir.TopFunction, Raw: "define i32 @f() {", Removed: true},
			{Kind: ir.TopBlank, Raw: ""},
			{Kind: ir.TopDeclare, Raw: "declare void @d()"},
			{Kind: ir.TopBlank, Raw: ""},
		},
	}
	compactModuleEntries(m)

	var kinds []ir.TopLevelKind
	for _, e := range m.Entries {
		kinds = append(kinds, e.Kind)
	}
	for i, e := range m.Entries {
		if e.Removed {
			t.Errorf("entry %d should not be removed after compaction", i)
		}
	}
	// Consecutive blanks should be collapsed, removed entries gone,
	// trailing blank is a single entry.
	wantKinds := []ir.TopLevelKind{ir.TopGlobal, ir.TopBlank, ir.TopDeclare, ir.TopBlank}
	if len(kinds) != len(wantKinds) {
		t.Fatalf("got %d entries, want %d: %v", len(kinds), len(wantKinds), kinds)
	}
	for i := range wantKinds {
		if kinds[i] != wantKinds[i] {
			t.Errorf("entry %d kind = %d, want %d", i, kinds[i], wantKinds[i])
		}
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

func TestAddLicenseModule(t *testing.T) {
	t.Run("adds license when missing", func(t *testing.T) {
		fn := &ir.Function{Name: "my_func", Raw: "define i32 @my_func() {"}
		m := &ir.Module{
			Entries: []ir.TopLevelEntry{
				{Kind: ir.TopGlobal, Raw: "@g = global i32 0"},
				{Kind: ir.TopBlank, Raw: ""},
				{Kind: ir.TopFunction, Function: fn},
				{Kind: ir.TopBlank, Raw: ""},
			},
			Functions: []*ir.Function{fn},
		}
		if err := addLicenseModule(m); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, g := range m.Globals {
			if g.Section == "license" {
				found = true
			}
		}
		if !found {
			t.Error("expected license global to be added")
		}
	})

	t.Run("skips when license exists", func(t *testing.T) {
		m := &ir.Module{
			Globals: []*ir.Global{{Name: "_license", Section: "license"}},
		}
		before := len(m.Globals)
		if err := addLicenseModule(m); err != nil {
			t.Fatal(err)
		}
		if len(m.Globals) != before {
			t.Error("should not add duplicate license")
		}
	})
}
