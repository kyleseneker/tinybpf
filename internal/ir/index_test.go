package ir

import "testing"

func TestBuildIndex(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		wantSSADefs   []string
		wantMeta      []int
		wantRefs      map[string]int
		wantMaxMetaID int
	}{
		{
			name:          "map and helper IR",
			input:         mapAndHelperIR,
			wantSSADefs:   []string{"%0"},
			wantRefs:      map[string]int{"@main.events": 1, "@my_func": 1, "@main.bpfGetCurrentPidTgid": 1},
			wantMaxMetaID: -1,
		},
		{
			name:          "metadata IR",
			input:         metadataIR,
			wantMeta:      []int{0, 1, 2, 3, 4, 5, 6, 7},
			wantMaxMetaID: 7,
		},
		{
			name:          "core field exists IR",
			input:         coreFieldExistsIR,
			wantSSADefs:   []string{"%core", "%1", "%2"},
			wantRefs:      map[string]int{"@main.bpfCoreFieldExists": 2, "@main.prog": 1},
			wantMaxMetaID: -1,
		},
		{
			name:          "core GEP IR",
			input:         coreGEPIR,
			wantSSADefs:   []string{"%task", "%pid_ptr", "%pid"},
			wantRefs:      map[string]int{"@tracepoint_handler": 1},
			wantMaxMetaID: -1,
		},
		{
			name:          "minimal IR no metadata no SSA defs",
			input:         minimalIR,
			wantMaxMetaID: -1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := mustParse(t, tt.input)
			idx := BuildIndex(m)

			for _, ssa := range tt.wantSSADefs {
				if _, ok := idx.SSADefs[ssa]; !ok {
					t.Errorf("missing SSA def for %s", ssa)
				}
			}
			for _, id := range tt.wantMeta {
				if _, ok := idx.MetaByID[id]; !ok {
					t.Errorf("missing metadata !%d", id)
				}
			}
			for name, minCount := range tt.wantRefs {
				refs := idx.IdentRefs[name]
				if len(refs) < minCount {
					t.Errorf("IdentRefs[%s] = %d refs, want >= %d", name, len(refs), minCount)
				}
			}
			if idx.MaxMetaID != tt.wantMaxMetaID {
				t.Errorf("MaxMetaID = %d, want %d", idx.MaxMetaID, tt.wantMaxMetaID)
			}
		})
	}
}

func TestNextMetaID(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{
			name:  "empty module no metadata",
			input: minimalIR,
			want:  0,
		},
		{
			name:  "populated metadata",
			input: metadataIR,
			want:  8,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := mustParse(t, tt.input)
			idx := BuildIndex(m)
			if got := idx.NextMetaID(); got != tt.want {
				t.Errorf("NextMetaID() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestIsReferencedElsewhere(t *testing.T) {
	const ir = "@myvar = global i32 0\n\ndefine void @user() {\nentry:\n  %0 = load i32, ptr @myvar\n  ret void\n}\n"
	m := mustParse(t, ir)
	idx := BuildIndex(m)

	tests := []struct {
		name        string
		ident       string
		defEntryIdx int
		want        bool
	}{
		{
			name:        "global referenced from function body",
			ident:       "@myvar",
			defEntryIdx: 0,
			want:        true,
		},
		{
			name:        "function only referenced from own entry",
			ident:       "@user",
			defEntryIdx: 2,
			want:        false,
		},
		{
			name:        "nonexistent identifier",
			ident:       "@nonexistent",
			defEntryIdx: 0,
			want:        false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := idx.IsReferencedElsewhere(tt.ident, tt.defEntryIdx)
			if got != tt.want {
				t.Errorf("IsReferencedElsewhere(%q, %d) = %v, want %v",
					tt.ident, tt.defEntryIdx, got, tt.want)
			}
		})
	}
}
