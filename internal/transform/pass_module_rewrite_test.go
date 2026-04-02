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
