package transform

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kyleseneker/tinybpf/internal/ir"
)

func TestExtractProgramsModule(t *testing.T) {
	tests := []struct {
		name        string
		funcs       []*ir.Function
		entries     []ir.TopLevelEntry
		programs    []string
		verbose     bool
		wantOutput  string
		wantRemoved []bool
	}{
		{
			name:       "verbose logs kept programs",
			funcs:      []*ir.Function{{Name: "my_prog"}},
			programs:   []string{"my_prog"},
			verbose:    true,
			wantOutput: "keeping program: my_prog",
		},
		{
			name:       "auto-detect warns on multiple programs",
			funcs:      []*ir.Function{{Name: "prog_a"}, {Name: "prog_b"}},
			wantOutput: "auto-detected 2 programs",
		},
		{
			name:  "marks runtime function entries removed",
			funcs: []*ir.Function{{Name: "keep_me"}, {Name: "runtime.run"}},
			entries: []ir.TopLevelEntry{
				{Kind: ir.TopFunction, Function: &ir.Function{Name: "keep_me"}},
				{Kind: ir.TopFunction, Function: &ir.Function{Name: "runtime.run"}},
			},
			wantRemoved: []bool{false, true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Wire up entries to point to the same function objects
			entries := tt.entries
			if entries == nil {
				for _, fn := range tt.funcs {
					entries = append(entries, ir.TopLevelEntry{Kind: ir.TopFunction, Function: fn})
				}
			} else {
				// Sync Function pointers between entries and funcs list
				for i := range entries {
					if entries[i].Function != nil {
						for _, fn := range tt.funcs {
							if fn.Name == entries[i].Function.Name {
								entries[i].Function = fn
							}
						}
					}
				}
			}
			m := &ir.Module{Functions: tt.funcs, Entries: entries}

			var buf bytes.Buffer
			err := extractProgramsModule(m, tt.programs, tt.verbose, &buf)
			if err != nil {
				t.Fatal(err)
			}

			if tt.wantOutput != "" && !strings.Contains(buf.String(), tt.wantOutput) {
				t.Errorf("expected output containing %q, got: %q", tt.wantOutput, buf.String())
			}
			for i, want := range tt.wantRemoved {
				if m.Entries[i].Removed != want {
					t.Errorf("entry %d Removed = %v, want %v", i, m.Entries[i].Removed, want)
				}
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
