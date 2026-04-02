package transform

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kyleseneker/tinybpf/internal/ir"
)

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
