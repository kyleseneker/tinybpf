package transform

import (
	"io"
	"testing"
)

func TestBuildModuleStagesOrder(t *testing.T) {
	expected := []struct {
		idx  int
		name string
	}{
		{0, "retarget"},
		{1, "strip-attributes"},
		{2, "extract-programs"},
		{3, "replace-alloc"},
		{4, "rewrite-helpers"},
		{5, "rewrite-core-access"},
		{6, "rewrite-core-exists"},
		{7, "assign-data-sections"},
		{8, "assign-program-sections"},
		{9, "strip-map-prefix"},
		{10, "rewrite-map-btf"},
		{11, "sanitize-btf-names"},
		{12, "sanitize-core-fields"},
		{13, "add-license"},
		{14, "cleanup"},
	}

	stages := buildModuleStages(Options{Stdout: io.Discard})

	if len(stages) != len(expected) {
		t.Fatalf("expected %d stages, got %d", len(expected), len(stages))
	}
	for _, tt := range expected {
		if stages[tt.idx].name != tt.name {
			t.Errorf("stage %d: expected %q, got %q", tt.idx, tt.name, stages[tt.idx].name)
		}
	}
}
