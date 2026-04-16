package transform

import (
	"strings"
	"testing"

	"github.com/kyleseneker/tinybpf/internal/ir"
)

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
			attrBody:   `"target-cpu"="generic" nounwind`,
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
		wantPresent  []string
		wantModified bool
	}{
		{
			name:         "strips target-cpu and target-features",
			attrBody:     ` "target-cpu"="generic" "target-features"="+neon" nounwind `,
			wantAbsent:   []string{"target-cpu", "target-features"},
			wantPresent:  []string{"nounwind"},
			wantModified: true,
		},
		{
			name:         "no target attrs leaves body unchanged",
			attrBody:     ` nounwind `,
			wantAbsent:   []string{"target-cpu", "target-features"},
			wantModified: false,
		},
		{
			name:         "strips alloc attributes",
			attrBody:     ` allockind("alloc,zeroed") allocsize(0) "alloc-family"="runtime.alloc" "target-cpu"="generic" "target-features"="+ete,+fp-armv8,+neon,+trbe,+v8a" `,
			wantAbsent:   []string{"allockind", "allocsize", "alloc-family", "target-cpu", "target-features"},
			wantPresent:  []string{"nounwind"},
			wantModified: true,
		},
		{
			name:         "empty after stripping substitutes nounwind",
			attrBody:     ` "target-cpu"="generic" "target-features"="+neon" `,
			wantAbsent:   []string{"target-cpu", "target-features"},
			wantPresent:  []string{"nounwind"},
			wantModified: true,
		},
		{
			name:         "preserves memory and other attrs",
			attrBody:     ` nounwind memory(readwrite, inaccessiblemem: write) "target-cpu"="generic" "target-features"="+neon" `,
			wantAbsent:   []string{"target-cpu", "target-features"},
			wantPresent:  []string{"nounwind", "memory(readwrite, inaccessiblemem: write)"},
			wantModified: true,
		},
		{
			name:         "preserves cold noreturn attrs",
			attrBody:     ` cold noreturn nounwind memory(inaccessiblemem: write) `,
			wantPresent:  []string{"cold", "noreturn", "nounwind", "memory(inaccessiblemem: write)"},
			wantModified: false,
		},
		{
			name:         "empty body",
			attrBody:     "",
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
					t.Errorf("%s not stripped from %q", absent, ag.Body)
				}
			}
			for _, present := range tt.wantPresent {
				if !strings.Contains(ag.Body, present) {
					t.Errorf("%s missing from %q", present, ag.Body)
				}
			}
			if ag.Modified != tt.wantModified {
				t.Errorf("Modified = %v, want %v", ag.Modified, tt.wantModified)
			}
		})
	}
}

func TestTokenizeAttrs(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "mixed attrs from tinygo",
			body: ` allockind("alloc,zeroed") allocsize(0) "alloc-family"="runtime.alloc" "target-cpu"="generic" "target-features"="+ete,+fp-armv8" `,
			want: []string{`allockind("alloc,zeroed")`, `allocsize(0)`, `"alloc-family"="runtime.alloc"`, `"target-cpu"="generic"`, `"target-features"="+ete,+fp-armv8"`},
		},
		{
			name: "bare words",
			body: `nounwind cold noreturn`,
			want: []string{"nounwind", "cold", "noreturn"},
		},
		{
			name: "memory with nested parens",
			body: `nounwind memory(readwrite, inaccessiblemem: write)`,
			want: []string{"nounwind", "memory(readwrite, inaccessiblemem: write)"},
		},
		{
			name: "empty",
			body: "",
			want: nil,
		},
		{
			name: "only spaces",
			body: "   ",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tokenizeAttrs(tt.body)
			if len(got) != len(tt.want) {
				t.Fatalf("tokenizeAttrs() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("token[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
