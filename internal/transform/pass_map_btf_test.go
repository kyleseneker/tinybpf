package transform

import (
	"errors"
	"strings"
	"testing"

	"github.com/kyleseneker/tinybpf/diag"
	"github.com/kyleseneker/tinybpf/internal/ir"
)

func TestParseI32Initializer(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
		wantNil bool
	}{
		{"valid 5 fields", "i32 27, i32 0, i32 0, i32 16777216, i32 0", 5, false},
		{"valid 1 field", "i32 42", 1, false},
		{"per-cpu hash 5 fields", "i32 9, i32 4, i32 8, i32 1024, i32 0", 5, false},
		{"per-cpu array 5 fields", "i32 6, i32 0, i32 8, i32 256, i32 0", 5, false},
		{"lru hash 5 fields", "i32 9, i32 4, i32 8, i32 1024, i32 0", 5, false},
		{"prog array 5 fields", "i32 3, i32 4, i32 4, i32 8, i32 0", 5, false},
		{"array of maps 7 fields", "i32 12, i32 4, i32 4, i32 16, i32 0, i32 0, i32 0", 7, false},
		{"lpm trie 5 fields", "i32 11, i32 8, i32 8, i32 1024, i32 1", 5, false},
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

func TestReplaceDotInNameFields(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "dot in name",
			line: `!5 = !DISubprogram(name: "main.handle", linkageName: "main.handle")`,
			want: `!5 = !DISubprogram(name: "main_handle", linkageName: "main_handle")`,
		},
		{
			name: "no dot",
			line: `!5 = !DISubprogram(name: "handle")`,
			want: `!5 = !DISubprogram(name: "handle")`,
		},
		{
			name: "no name field",
			line: `!5 = !DIBasicType(size: 32)`,
			want: `!5 = !DIBasicType(size: 32)`,
		},
		{
			name: "multiple dots",
			line: `!5 = !DISubprogram(name: "internal/task.start.func1")`,
			want: `!5 = !DISubprogram(name: "internal/task_start_func1")`,
		},
		{
			name: "unclosed quote",
			line: `name: "broken`,
			want: `name: "broken`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf strings.Builder
			got := replaceDotInNameFields(tt.line, &buf)
			if got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}

func TestStripPointerName(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "strips name field",
			line: `!5 = !DIDerivedType(tag: DW_TAG_pointer_type, name: "unsafe.Pointer", baseType: !6)`,
			want: `!5 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !6)`,
		},
		{
			name: "no name field",
			line: `!5 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !6)`,
			want: `!5 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !6)`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stripPointerName(tt.line); got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
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
