package transform

import (
	"io"
	"testing"
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
