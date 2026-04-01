package transform

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/kyleseneker/tinybpf/diag"
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

func TestBuildProgramSet(t *testing.T) {
	tests := []struct {
		name     string
		funcs    []*ir.Function
		programs []string
		wantSet  map[string]bool
		wantErr  bool
	}{
		{
			name:     "explicit valid names",
			funcs:    []*ir.Function{{Name: "my_prog"}, {Name: "runtime.run"}},
			programs: []string{"my_prog"},
			wantSet:  map[string]bool{"my_prog": true},
		},
		{
			name:     "explicit missing name",
			funcs:    []*ir.Function{{Name: "my_prog"}},
			programs: []string{"nonexistent"},
			wantErr:  true,
		},
		{
			name:    "auto-detect skips runtime",
			funcs:   []*ir.Function{{Name: "handle"}, {Name: "runtime.run"}},
			wantSet: map[string]bool{"handle": true},
		},
		{
			name:    "all runtime returns error",
			funcs:   []*ir.Function{{Name: "runtime.run"}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &ir.Module{Functions: tt.funcs}
			got, err := buildProgramSet(m, tt.programs)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for k := range tt.wantSet {
				if !got[k] {
					t.Errorf("missing program %q in set", k)
				}
			}
		})
	}
}

func TestMarkRuntimeGlobalsRemoved(t *testing.T) {
	rt := &ir.Global{Name: "runtime.scheduler"}
	str := &ir.Global{Name: ".string"}
	core := &ir.Global{Name: "__bpf_core_foo"}
	user := &ir.Global{Name: "my_global"}
	m := &ir.Module{
		Globals: []*ir.Global{rt, str, core, user},
		Entries: []ir.TopLevelEntry{
			{Kind: ir.TopGlobal, Global: rt},
			{Kind: ir.TopGlobal, Global: str},
			{Kind: ir.TopGlobal, Global: core},
			{Kind: ir.TopGlobal, Global: user},
		},
	}
	markRuntimeGlobalsRemoved(m)
	if !m.Entries[0].Removed {
		t.Error("runtime.scheduler should be removed")
	}
	if !m.Entries[1].Removed {
		t.Error(".string should be removed")
	}
	if !m.Entries[2].Removed {
		t.Error("__bpf_core_foo should be removed")
	}
	if m.Entries[3].Removed {
		t.Error("my_global should not be removed")
	}
}

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

func TestReplaceAllocMultiError(t *testing.T) {
	fn := &ir.Function{
		Name: "f",
		BodyRaw: []string{
			"entry:",
			"  call void @runtime.alloc(badpattern1)",
			"  call void @runtime.alloc(badpattern2)",
		},
	}
	m := &ir.Module{Functions: []*ir.Function{fn}}
	err := replaceAllocModule(m)
	if err == nil {
		t.Fatal("expected error")
	}
	var merr *diag.Errors
	if !errors.As(err, &merr) {
		t.Fatalf("expected *diag.Errors, got %T", err)
	}
	if len(merr.Errs) != 2 {
		t.Fatalf("expected 2 errors, got %d", len(merr.Errs))
	}
}

func TestHasMemsetDecl(t *testing.T) {
	tests := []struct {
		name string
		m    *ir.Module
		want bool
	}{
		{
			name: "in declares",
			m:    &ir.Module{Declares: []*ir.Declare{{Name: memsetIntrinsicName}}},
			want: true,
		},
		{
			name: "in entries raw",
			m: &ir.Module{Entries: []ir.TopLevelEntry{
				{Kind: ir.TopDeclare, Raw: "declare void @" + memsetIntrinsicName + "(ptr, i8, i64, i1)"},
			}},
			want: true,
		},
		{
			name: "removed declare ignored",
			m:    &ir.Module{Declares: []*ir.Declare{{Name: memsetIntrinsicName, Removed: true}}},
			want: false,
		},
		{
			name: "not present",
			m:    &ir.Module{},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasMemsetDecl(tt.m); got != tt.want {
				t.Errorf("hasMemsetDecl() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRewriteHelpersMultiError(t *testing.T) {
	tests := []struct {
		name       string
		bodyLines  []string
		wantCount  int
		wantSubstr []string
	}{
		{
			name: "two unknown helpers collected",
			bodyLines: []string{
				"  %0 = call i64 @main.bpfFakeHelperAlpha(ptr undef)",
				"  %1 = call i64 @main.bpfFakeHelperBeta(ptr undef)",
			},
			wantCount:  2,
			wantSubstr: []string{"bpfFakeHelperAlpha", "bpfFakeHelperBeta"},
		},
		{
			name: "fuzzy suggestion included",
			bodyLines: []string{
				"  %0 = call i64 @main.bpfMapLookpElem(ptr undef)",
			},
			wantCount:  1,
			wantSubstr: []string{"did you mean"},
		},
		{
			name: "valid helper no error",
			bodyLines: []string{
				"  %0 = call i64 @main.bpfGetCurrentPidTgid(ptr undef)",
			},
			wantCount: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := &ir.Function{Name: "f", BodyRaw: tt.bodyLines}
			m := &ir.Module{Functions: []*ir.Function{fn}}
			err := rewriteHelpersModule(m)
			if tt.wantCount == 0 {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error")
			}
			var merr *diag.Errors
			if !errors.As(err, &merr) {
				t.Fatalf("expected *diag.Errors, got %T: %v", err, err)
			}
			if len(merr.Errs) != tt.wantCount {
				t.Fatalf("expected %d errors, got %d: %v", tt.wantCount, len(merr.Errs), merr.Errs)
			}
			msg := err.Error()
			for _, sub := range tt.wantSubstr {
				if !strings.Contains(msg, sub) {
					t.Errorf("missing %q in error:\n%s", sub, msg)
				}
			}
			if !diag.IsStage(err, diag.StageTransform) {
				t.Error("expected StageTransform")
			}
		})
	}
}

func TestCorePassModule(t *testing.T) {
	m := &ir.Module{}
	if err := corePassModule(m); err != nil {
		t.Fatalf("corePassModule on empty module: %v", err)
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
	m := &ir.Module{}
	appendMetaEntryToModule(m, "!0 = !{}")
	if len(m.Entries) != 1 || m.Entries[0].Raw != "!0 = !{}" {
		t.Errorf("unexpected entries: %v", m.Entries)
	}
}

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

func TestMapBTFPassModule(t *testing.T) {
	m := &ir.Module{}
	if err := mapBTFPassModule(m); err != nil {
		t.Fatalf("mapBTFPassModule on empty module: %v", err)
	}
}

func TestCollectMapRenames(t *testing.T) {
	tests := []struct {
		name    string
		entries []ir.TopLevelEntry
		want    int
	}{
		{
			name: "map global with prefix",
			entries: []ir.TopLevelEntry{
				{Kind: ir.TopGlobal, Global: &ir.Global{Name: "main.events"}, Raw: `@main.events = global %main.bpfMapDef section ".maps"`},
			},
			want: 1,
		},
		{
			name: "no dot in name",
			entries: []ir.TopLevelEntry{
				{Kind: ir.TopGlobal, Global: &ir.Global{Name: "events"}, Raw: `@events = global %bpfMapDef section ".maps"`},
			},
			want: 0,
		},
		{
			name: "not a maps section",
			entries: []ir.TopLevelEntry{
				{Kind: ir.TopGlobal, Global: &ir.Global{Name: "main.counter"}, Raw: `@main.counter = global i32 0`},
			},
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &ir.Module{Entries: tt.entries}
			got := collectMapRenames(m)
			if len(got) != tt.want {
				t.Errorf("collectMapRenames() = %d renames, want %d", len(got), tt.want)
			}
		})
	}
}

func TestApplyRenames(t *testing.T) {
	fn := &ir.Function{
		Raw:     "define i32 @f(ptr @main.events) {",
		BodyRaw: []string{"  store ptr @main.events, ptr %0"},
	}
	m := &ir.Module{
		Entries: []ir.TopLevelEntry{
			{Kind: ir.TopGlobal, Raw: `@main.events = global i32 0`},
			{Kind: ir.TopFunction, Function: fn, Raw: fn.Raw},
		},
	}
	renames := []mapRename{{oldRef: "@main.events", newRef: "@events"}}
	applyRenames(m, renames)

	if !strings.Contains(m.Entries[0].Raw, "@events") {
		t.Error("entry raw not renamed")
	}
	if strings.Contains(fn.Raw, "@main.events") {
		t.Error("function raw not renamed")
	}
	if strings.Contains(fn.BodyRaw[0], "@main.events") {
		t.Error("function body not renamed")
	}
}

func TestDetectMapFieldCount(t *testing.T) {
	tests := []struct {
		name    string
		types   []*ir.TypeDef
		want    int
		wantErr bool
	}{
		{
			name:  "5-field map",
			types: []*ir.TypeDef{{Name: "%main.bpfMapDef", Fields: []string{"i32", "i32", "i32", "i32", "i32"}}},
			want:  5,
		},
		{
			name:  "no bpfMapDef defaults to 5",
			types: []*ir.TypeDef{{Name: "%main.otherType"}},
			want:  5,
		},
		{
			name:    "too few fields",
			types:   []*ir.TypeDef{{Name: "%main.bpfMapDef", Fields: []string{"i32"}, Raw: "bad"}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &ir.Module{TypeDefs: tt.types}
			got, err := detectMapFieldCount(m)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("detectMapFieldCount() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestCollectMapDefs(t *testing.T) {
	tests := []struct {
		name    string
		entries []ir.TopLevelEntry
		fc      int
		want    int
		wantErr bool
	}{
		{
			name: "zeroinitializer map",
			entries: []ir.TopLevelEntry{
				{Kind: ir.TopGlobal, Global: &ir.Global{Name: "events"},
					Raw: `@events = global %main.bpfMapDef zeroinitializer, section ".maps"`},
			},
			fc:   5,
			want: 1,
		},
		{
			name:    "empty",
			entries: []ir.TopLevelEntry{},
			fc:      5,
			want:    0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &ir.Module{Entries: tt.entries}
			got, err := collectMapDefs(m, tt.fc)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tt.want {
				t.Errorf("collectMapDefs() = %d, want %d", len(got), tt.want)
			}
		})
	}
}

func TestCollectMapDefsMultiError(t *testing.T) {
	m := &ir.Module{
		Entries: []ir.TopLevelEntry{
			{
				Kind:   ir.TopGlobal,
				Global: &ir.Global{Name: "map_a"},
				Raw:    `@map_a = global %main.bpfMapDef { i32 1, i32 2 }, section ".maps"`,
			},
			{
				Kind:   ir.TopGlobal,
				Global: &ir.Global{Name: "map_b"},
				Raw:    `@map_b = global %main.bpfMapDef { i32 1, i32 2, i32 3 }, section ".maps"`,
			},
		},
	}
	_, err := collectMapDefs(m, 5)
	if err == nil {
		t.Fatal("expected error")
	}
	var merr *diag.Errors
	if !errors.As(err, &merr) {
		t.Fatalf("expected *diag.Errors, got %T", err)
	}
	if len(merr.Errs) != 2 {
		t.Fatalf("expected 2 errors, got %d: %v", len(merr.Errs), merr.Errs)
	}
}

func TestCollectCoreStructMetaIDs(t *testing.T) {
	m := &ir.Module{
		Entries: []ir.TopLevelEntry{
			{Kind: ir.TopMetadata, Raw: `!5 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfCoreTaskStruct", elements: !6)`},
			{Kind: ir.TopMetadata, Raw: `!6 = !{!7}`},
			{Kind: ir.TopMetadata, Raw: `!7 = !DIDerivedType(tag: DW_TAG_member, name: "Pid")`},
		},
	}
	ids := collectCoreStructMetaIDs(m)
	if !ids[5] {
		t.Error("expected ID 5 in core struct meta IDs")
	}
	if ids[6] || ids[7] {
		t.Error("non-core-struct entries should not be included")
	}
}

func TestCollectCoreMemberIDs(t *testing.T) {
	m := &ir.Module{
		Entries: []ir.TopLevelEntry{
			{Kind: ir.TopMetadata, Raw: `!5 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfCoreTaskStruct", elements: !6)`},
			{Kind: ir.TopMetadata, Raw: `!6 = !{!7, !8}`},
		},
	}
	ids := collectCoreMemberIDs(m)
	if !ids[6] {
		t.Error("expected ID 6 in core member IDs")
	}
}

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

func TestRemoveUnreferencedDeclares(t *testing.T) {
	fn := &ir.Function{Name: "f", Raw: "define i32 @f() { call void @used() }"}
	used := &ir.Declare{Name: "used", Raw: "declare void @used()"}
	unused := &ir.Declare{Name: "unused", Raw: "declare void @unused()"}
	m := &ir.Module{
		Entries: []ir.TopLevelEntry{
			{Kind: ir.TopDeclare, Declare: used, Raw: used.Raw},
			{Kind: ir.TopDeclare, Declare: unused, Raw: unused.Raw},
			{Kind: ir.TopFunction, Function: fn, Raw: fn.Raw},
		},
	}
	refs := buildModuleIdentRefs(m)
	removeUnreferencedDeclares(m, refs)
	if m.Entries[0].Removed {
		t.Error("used declare should not be removed")
	}
	if !m.Entries[1].Removed {
		t.Error("unused declare should be removed")
	}
}

func TestRemoveUnreferencedGlobals(t *testing.T) {
	fn := &ir.Function{Name: "f", Raw: "define i32 @f() {", BodyRaw: []string{"  load i32, ptr @used_g"}}
	usedG := &ir.Global{Name: "used_g", Raw: "@used_g = global i32 0"}
	unusedG := &ir.Global{Name: "unused_g", Raw: "@unused_g = global i32 0"}
	sectionG := &ir.Global{Name: "sec_g", Section: "license", Raw: `@sec_g = global [4 x i8] c"GPL\00", section "license"`}
	m := &ir.Module{
		Entries: []ir.TopLevelEntry{
			{Kind: ir.TopGlobal, Global: usedG, Raw: usedG.Raw},
			{Kind: ir.TopGlobal, Global: unusedG, Raw: unusedG.Raw},
			{Kind: ir.TopGlobal, Global: sectionG, Raw: sectionG.Raw},
			{Kind: ir.TopFunction, Function: fn, Raw: fn.Raw},
		},
	}
	refs := buildModuleIdentRefs(m)
	removeUnreferencedGlobals(m, refs)
	if m.Entries[0].Removed {
		t.Error("used global should not be removed")
	}
	if !m.Entries[1].Removed {
		t.Error("unused global should be removed")
	}
	if m.Entries[2].Removed {
		t.Error("section global should not be removed")
	}
}

func TestRemoveUnusedAttrGroups(t *testing.T) {
	m := &ir.Module{
		Entries: []ir.TopLevelEntry{
			{Kind: ir.TopFunction, Function: &ir.Function{
				Raw: "define i32 @f() #0 {",
			}},
			{Kind: ir.TopAttrGroup, AttrGroup: &ir.AttrGroup{ID: "0", Body: "nounwind"}},
			{Kind: ir.TopAttrGroup, AttrGroup: &ir.AttrGroup{ID: "1", Body: "readonly"}},
		},
	}
	removeUnusedAttrGroups(m)
	if m.Entries[1].Removed {
		t.Error("attr #0 should be kept (referenced by function)")
	}
	if !m.Entries[2].Removed {
		t.Error("attr #1 should be removed (unused)")
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

func TestWarnStackUsage(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantMsg string
	}{
		{
			name:    "large alloca triggers warning",
			body:    `  %buf = alloca [400 x i8], align 1`,
			wantMsg: "[transform] test_func: estimated stack usage ~400 bytes",
		},
		{
			name:    "small alloca no warning",
			body:    `  %buf = alloca [16 x i8], align 1`,
			wantMsg: "",
		},
		{
			name: "multiple allocas sum",
			body: `  %a = alloca [200 x i8], align 1
  %b = alloca [200 x i8], align 1`,
			wantMsg: "[transform] test_func: estimated stack usage ~400 bytes",
		},
		{
			name:    "no alloca no warning",
			body:    `  ret i32 0`,
			wantMsg: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &ir.Module{
				Functions: []*ir.Function{
					{Name: "test_func", BodyRaw: strings.Split(tt.body, "\n")},
				},
			}
			var buf bytes.Buffer
			warnStackUsage(m, &buf)
			got := buf.String()
			if tt.wantMsg == "" {
				if got != "" {
					t.Errorf("expected no warning, got: %s", got)
				}
			} else {
				if !strings.Contains(got, tt.wantMsg) {
					t.Errorf("expected warning containing %q, got: %q", tt.wantMsg, got)
				}
			}
		})
	}
}
