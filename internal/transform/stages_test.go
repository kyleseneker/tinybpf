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
	tests := []struct {
		name       string
		triple     string
		dataLayout string
		attrBody   string
		wantTriple string
		wantStrip  string
	}{
		{
			name:       "retargets and strips target-cpu",
			triple:     "x86_64-unknown-linux-gnu",
			dataLayout: "e-m:o",
			attrBody:   `{ "target-cpu"="generic" nounwind }`,
			wantTriple: "bpf",
			wantStrip:  "target-cpu",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ag := &ir.AttrGroup{
				ID:   "0",
				Body: tt.attrBody,
			}
			m := &ir.Module{
				Triple:     tt.triple,
				DataLayout: tt.dataLayout,
				AttrGroups: []*ir.AttrGroup{ag},
			}
			if err := moduleRewriteModule(m); err != nil {
				t.Fatal(err)
			}
			if m.Triple != tt.wantTriple {
				t.Errorf("triple = %q, want %q", m.Triple, tt.wantTriple)
			}
			if strings.Contains(ag.Body, tt.wantStrip) {
				t.Errorf("%s not stripped", tt.wantStrip)
			}
		})
	}
}

func TestRetargetModule(t *testing.T) {
	tests := []struct {
		name       string
		triple     string
		dataLayout string
		wantTriple string
	}{
		{
			name:       "x86 to bpf",
			triple:     "x86_64-unknown-linux-gnu",
			dataLayout: "e-m:o",
			wantTriple: "bpf",
		},
		{
			name:       "already bpf",
			triple:     "bpf",
			dataLayout: "",
			wantTriple: "bpf",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &ir.Module{Triple: tt.triple, DataLayout: tt.dataLayout}
			if err := retargetModule(m); err != nil {
				t.Fatal(err)
			}
			if m.Triple != tt.wantTriple {
				t.Errorf("triple = %q, want %q", m.Triple, tt.wantTriple)
			}
		})
	}
}

func TestStripAttributesModule(t *testing.T) {
	tests := []struct {
		name         string
		attrBody     string
		wantAbsent   []string
		wantModified bool
	}{
		{
			name:         "strips target-cpu and target-features",
			attrBody:     `{ "target-cpu"="generic" "target-features"="+neon" nounwind }`,
			wantAbsent:   []string{"target-cpu", "target-features"},
			wantModified: true,
		},
		{
			name:         "no target attrs leaves body unchanged",
			attrBody:     `{ nounwind }`,
			wantAbsent:   []string{"target-cpu", "target-features"},
			wantModified: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ag := &ir.AttrGroup{
				ID:   "0",
				Body: tt.attrBody,
			}
			m := &ir.Module{AttrGroups: []*ir.AttrGroup{ag}}
			if err := stripAttributesModule(m); err != nil {
				t.Fatal(err)
			}
			for _, absent := range tt.wantAbsent {
				if strings.Contains(ag.Body, absent) {
					t.Errorf("%s not stripped", absent)
				}
			}
			if ag.Modified != tt.wantModified {
				t.Errorf("Modified = %v, want %v", ag.Modified, tt.wantModified)
			}
		})
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
	tests := []struct {
		name        string
		globalNames []string
		wantRemoved []bool
	}{
		{
			name:        "removes runtime, string, and core globals but keeps user globals",
			globalNames: []string{"runtime.scheduler", ".string", "__bpf_core_foo", "my_global"},
			wantRemoved: []bool{true, true, true, false},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var globals []*ir.Global
			var entries []ir.TopLevelEntry
			for _, name := range tt.globalNames {
				g := &ir.Global{Name: name}
				globals = append(globals, g)
				entries = append(entries, ir.TopLevelEntry{Kind: ir.TopGlobal, Global: g})
			}
			m := &ir.Module{Globals: globals, Entries: entries}
			markRuntimeGlobalsRemoved(m)
			for i, want := range tt.wantRemoved {
				if m.Entries[i].Removed != want {
					t.Errorf("%s: Removed = %v, want %v", tt.globalNames[i], m.Entries[i].Removed, want)
				}
			}
		})
	}
}

func TestMarkGlobalRemoved(t *testing.T) {
	tests := []struct {
		name         string
		globalName   string
		wantRemoved0 bool
		wantRemoved1 bool
	}{
		{
			name:         "marks matching global entry removed",
			globalName:   "runtime.scheduler",
			wantRemoved0: true,
			wantRemoved1: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &ir.Global{Name: tt.globalName}
			m := &ir.Module{
				Entries: []ir.TopLevelEntry{
					{Kind: ir.TopGlobal, Global: g},
					{Kind: ir.TopFunction},
				},
			}
			markGlobalRemoved(m, g)
			if m.Entries[0].Removed != tt.wantRemoved0 {
				t.Errorf("entry 0 Removed = %v, want %v", m.Entries[0].Removed, tt.wantRemoved0)
			}
			if m.Entries[1].Removed != tt.wantRemoved1 {
				t.Errorf("entry 1 Removed = %v, want %v", m.Entries[1].Removed, tt.wantRemoved1)
			}
		})
	}
}

func TestReplaceAllocMultiError(t *testing.T) {
	tests := []struct {
		name      string
		bodyRaw   []string
		wantErrs  int
		wantError bool
	}{
		{
			name: "two bad patterns produce two errors",
			bodyRaw: []string{
				"entry:",
				"  call void @runtime.alloc(badpattern1)",
				"  call void @runtime.alloc(badpattern2)",
			},
			wantErrs:  2,
			wantError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := &ir.Function{Name: "f", BodyRaw: tt.bodyRaw}
			m := &ir.Module{Functions: []*ir.Function{fn}}
			err := replaceAllocModule(m)
			if !tt.wantError {
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
				t.Fatalf("expected *diag.Errors, got %T", err)
			}
			if len(merr.Errs) != tt.wantErrs {
				t.Fatalf("expected %d errors, got %d", tt.wantErrs, len(merr.Errs))
			}
		})
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

func TestSectionsPassModule(t *testing.T) {
	tests := []struct {
		name           string
		funcName       string
		funcRaw        string
		globalName     string
		globalLinkage  string
		globalInit     string
		globalRaw      string
		sections       map[string]string
		wantGlobalSect string
		wantFuncHasSec bool
	}{
		{
			name:           "assigns sections to globals and functions",
			funcName:       "probe_connect",
			funcRaw:        "define i32 @probe_connect() {",
			globalName:     "counter",
			globalLinkage:  "global",
			globalInit:     "0",
			globalRaw:      "@counter = global i32 0",
			sections:       map[string]string{"probe_connect": "tracepoint/tcp/tcp_connect"},
			wantGlobalSect: ".data",
			wantFuncHasSec: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := &ir.Function{Name: tt.funcName, Raw: tt.funcRaw}
			g := &ir.Global{Name: tt.globalName, Linkage: tt.globalLinkage, Initializer: tt.globalInit, Raw: tt.globalRaw}
			m := &ir.Module{
				Globals:   []*ir.Global{g},
				Functions: []*ir.Function{fn},
				Entries: []ir.TopLevelEntry{
					{Kind: ir.TopGlobal, Global: g, Raw: g.Raw},
					{Kind: ir.TopFunction, Function: fn, Raw: fn.Raw},
				},
			}
			if err := sectionsPassModule(m, tt.sections); err != nil {
				t.Fatal(err)
			}
			if g.Section != tt.wantGlobalSect {
				t.Errorf("global section = %q, want %q", g.Section, tt.wantGlobalSect)
			}
			if tt.wantFuncHasSec && !strings.Contains(fn.Raw, "section") {
				t.Error("function should have a section after sectionsPassModule")
			}
		})
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
			err := mapBTFPassModule(tt.module)
			if (err != nil) != tt.wantErr {
				t.Fatalf("mapBTFPassModule() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
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
	tests := []struct {
		name        string
		entryRaw    string
		funcRaw     string
		bodyRaw     []string
		renames     []mapRename
		wantInEntry string
		wantAbsent  string
	}{
		{
			name:        "renames refs in entries, function, and body",
			entryRaw:    `@main.events = global i32 0`,
			funcRaw:     "define i32 @f(ptr @main.events) {",
			bodyRaw:     []string{"  store ptr @main.events, ptr %0"},
			renames:     []mapRename{{oldRef: "@main.events", newRef: "@events"}},
			wantInEntry: "@events",
			wantAbsent:  "@main.events",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := &ir.Function{
				Raw:     tt.funcRaw,
				BodyRaw: tt.bodyRaw,
			}
			m := &ir.Module{
				Entries: []ir.TopLevelEntry{
					{Kind: ir.TopGlobal, Raw: tt.entryRaw},
					{Kind: ir.TopFunction, Function: fn, Raw: fn.Raw},
				},
			}
			applyRenames(m, tt.renames)

			if !strings.Contains(m.Entries[0].Raw, tt.wantInEntry) {
				t.Error("entry raw not renamed")
			}
			if strings.Contains(fn.Raw, tt.wantAbsent) {
				t.Error("function raw not renamed")
			}
			if len(fn.Blocks) == 0 {
				t.Fatal("expected blocks to be populated")
			}
			for _, block := range fn.Blocks {
				for _, inst := range block.Instructions {
					if strings.Contains(inst.Raw, tt.wantAbsent) {
						t.Error("instruction body not renamed")
					}
				}
			}
		})
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
	tests := []struct {
		name     string
		entries  []ir.TopLevelEntry
		fc       int
		wantErrs int
	}{
		{
			name: "two malformed maps produce two errors",
			entries: []ir.TopLevelEntry{
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
			fc:       5,
			wantErrs: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &ir.Module{Entries: tt.entries}
			_, err := collectMapDefs(m, tt.fc)
			if err == nil {
				t.Fatal("expected error")
			}
			var merr *diag.Errors
			if !errors.As(err, &merr) {
				t.Fatalf("expected *diag.Errors, got %T", err)
			}
			if len(merr.Errs) != tt.wantErrs {
				t.Fatalf("expected %d errors, got %d: %v", tt.wantErrs, len(merr.Errs), merr.Errs)
			}
		})
	}
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

func TestFinalizeModule(t *testing.T) {
	tests := []struct {
		name           string
		funcName       string
		orphanDeclName string
		wantLicense    bool
		wantOrphanGone bool
	}{
		{
			name:           "adds license and removes orphan declares",
			funcName:       "my_func",
			orphanDeclName: "unused_func",
			wantLicense:    true,
			wantOrphanGone: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := &ir.Function{Name: tt.funcName, Raw: "define i32 @" + tt.funcName + "() {"}
			orphanDecl := &ir.Declare{Name: tt.orphanDeclName, Raw: "declare void @" + tt.orphanDeclName + "()"}
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
			if hasLicense != tt.wantLicense {
				t.Errorf("license present = %v, want %v", hasLicense, tt.wantLicense)
			}
			if tt.wantOrphanGone {
				for _, e := range m.Entries {
					if e.Kind == ir.TopDeclare && !e.Removed && e.Declare != nil && e.Declare.Name == tt.orphanDeclName {
						t.Error("unreferenced declare should be cleaned up")
					}
				}
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

func TestRemoveUnreferencedDeclares(t *testing.T) {
	tests := []struct {
		name         string
		funcRaw      string
		usedName     string
		unusedName   string
		wantUsedKept bool
		wantUnusedRM bool
	}{
		{
			name:         "keeps referenced and removes unreferenced declares",
			funcRaw:      "define i32 @f() { call void @used() }",
			usedName:     "used",
			unusedName:   "unused",
			wantUsedKept: true,
			wantUnusedRM: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := &ir.Function{Name: "f", Raw: tt.funcRaw}
			used := &ir.Declare{Name: tt.usedName, Raw: "declare void @" + tt.usedName + "()"}
			unused := &ir.Declare{Name: tt.unusedName, Raw: "declare void @" + tt.unusedName + "()"}
			m := &ir.Module{
				Entries: []ir.TopLevelEntry{
					{Kind: ir.TopDeclare, Declare: used, Raw: used.Raw},
					{Kind: ir.TopDeclare, Declare: unused, Raw: unused.Raw},
					{Kind: ir.TopFunction, Function: fn, Raw: fn.Raw},
				},
			}
			refs := buildModuleIdentRefs(m)
			removeUnreferencedDeclares(m, refs)
			if m.Entries[0].Removed != !tt.wantUsedKept {
				t.Errorf("used declare Removed = %v, want %v", m.Entries[0].Removed, !tt.wantUsedKept)
			}
			if m.Entries[1].Removed != tt.wantUnusedRM {
				t.Errorf("unused declare Removed = %v, want %v", m.Entries[1].Removed, tt.wantUnusedRM)
			}
		})
	}
}

func TestRemoveUnreferencedGlobals(t *testing.T) {
	tests := []struct {
		name        string
		wantRemoved []bool
	}{
		{
			name:        "keeps used and section globals, removes unused",
			wantRemoved: []bool{false, true, false},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
			for i, want := range tt.wantRemoved {
				if m.Entries[i].Removed != want {
					t.Errorf("entry %d Removed = %v, want %v", i, m.Entries[i].Removed, want)
				}
			}
		})
	}
}

func TestRemoveUnusedAttrGroups(t *testing.T) {
	tests := []struct {
		name        string
		funcRaw     string
		attrGroups  []struct{ id, body string }
		wantRemoved []bool
	}{
		{
			name:        "keeps referenced attr group, removes unused",
			funcRaw:     "define i32 @f() #0 {",
			attrGroups:  []struct{ id, body string }{{"0", "nounwind"}, {"1", "readonly"}},
			wantRemoved: []bool{false, true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries := []ir.TopLevelEntry{
				{Kind: ir.TopFunction, Function: &ir.Function{Raw: tt.funcRaw}},
			}
			for _, ag := range tt.attrGroups {
				entries = append(entries, ir.TopLevelEntry{
					Kind:      ir.TopAttrGroup,
					AttrGroup: &ir.AttrGroup{ID: ag.id, Body: ag.body},
				})
			}
			m := &ir.Module{Entries: entries}
			removeUnusedAttrGroups(m)
			for i, want := range tt.wantRemoved {
				// attr group entries start at index 1
				if m.Entries[i+1].Removed != want {
					t.Errorf("attr #%s Removed = %v, want %v", tt.attrGroups[i].id, m.Entries[i+1].Removed, want)
				}
			}
		})
	}
}

func TestBuildModuleIdentRefs(t *testing.T) {
	tests := []struct {
		name     string
		entries  []ir.TopLevelEntry
		wantRefs map[string]int
	}{
		{
			name: "tracks global and function references",
			entries: []ir.TopLevelEntry{
				{Kind: ir.TopGlobal, Raw: `@my_global = global i32 42`},
				{Kind: ir.TopFunction, Function: &ir.Function{
					Raw:     `define i32 @my_func(ptr %ctx) {`,
					BodyRaw: []string{"  %0 = load i32, ptr @my_global"},
				}},
			},
			wantRefs: map[string]int{"@my_global": 2, "@my_func": 1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &ir.Module{Entries: tt.entries}
			refs := buildModuleIdentRefs(m)
			for ident, wantCount := range tt.wantRefs {
				if len(refs[ident]) != wantCount {
					t.Errorf("%s referenced in %d entries, want %d", ident, len(refs[ident]), wantCount)
				}
			}
		})
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
	tests := []struct {
		name       string
		funcRaw    string
		attrIDs    []string
		wantUsed   []string
		wantUnused []string
	}{
		{
			name:       "identifies used and unused attr IDs",
			funcRaw:    `define i32 @f(ptr %ctx) #0 {`,
			attrIDs:    []string{"0", "1"},
			wantUsed:   []string{"0"},
			wantUnused: []string{"1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries := []ir.TopLevelEntry{
				{Kind: ir.TopFunction, Function: &ir.Function{
					Raw:     tt.funcRaw,
					BodyRaw: []string{"  ret i32 0"},
				}},
			}
			for _, id := range tt.attrIDs {
				entries = append(entries, ir.TopLevelEntry{
					Kind:      ir.TopAttrGroup,
					AttrGroup: &ir.AttrGroup{ID: id, Body: "nounwind"},
				})
			}
			m := &ir.Module{Entries: entries}
			used := collectUsedAttrIDsFromModule(m)
			for _, id := range tt.wantUsed {
				if !used[id] {
					t.Errorf("attr #%s should be used", id)
				}
			}
			for _, id := range tt.wantUnused {
				if used[id] {
					t.Errorf("attr #%s should not be used", id)
				}
			}
		})
	}
}

func TestMarkOrphanedAttrCommentsInModule(t *testing.T) {
	tests := []struct {
		name        string
		entries     []ir.TopLevelEntry
		wantRemoved []bool
	}{
		{
			name: "keeps comment before function, removes orphaned comment",
			entries: []ir.TopLevelEntry{
				{Kind: ir.TopComment, Raw: "; Function Attrs: nounwind"},
				{Kind: ir.TopFunction, Function: &ir.Function{Raw: "define i32 @f() {"}},
				{Kind: ir.TopComment, Raw: "; Function Attrs: readonly"},
				{Kind: ir.TopMetadata, Raw: "!0 = !{}"},
			},
			wantRemoved: []bool{false, false, true, false},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &ir.Module{Entries: tt.entries}
			markOrphanedAttrCommentsInModule(m)
			for i, want := range tt.wantRemoved {
				if m.Entries[i].Removed != want {
					t.Errorf("entry %d Removed = %v, want %v", i, m.Entries[i].Removed, want)
				}
			}
		})
	}
}

func TestCompactModuleEntries(t *testing.T) {
	tests := []struct {
		name      string
		entries   []ir.TopLevelEntry
		wantKinds []ir.TopLevelKind
	}{
		{
			name: "removes duplicates blanks and removed entries",
			entries: []ir.TopLevelEntry{
				{Kind: ir.TopGlobal, Raw: "@g = global i32 0"},
				{Kind: ir.TopBlank, Raw: ""},
				{Kind: ir.TopBlank, Raw: ""},
				{Kind: ir.TopFunction, Raw: "define i32 @f() {", Removed: true},
				{Kind: ir.TopBlank, Raw: ""},
				{Kind: ir.TopDeclare, Raw: "declare void @d()"},
				{Kind: ir.TopBlank, Raw: ""},
			},
			wantKinds: []ir.TopLevelKind{ir.TopGlobal, ir.TopBlank, ir.TopDeclare, ir.TopBlank},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &ir.Module{Entries: tt.entries}
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
			if len(kinds) != len(tt.wantKinds) {
				t.Fatalf("got %d entries, want %d: %v", len(kinds), len(tt.wantKinds), kinds)
			}
			for i := range tt.wantKinds {
				if kinds[i] != tt.wantKinds[i] {
					t.Errorf("entry %d kind = %d, want %d", i, kinds[i], tt.wantKinds[i])
				}
			}
		})
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
