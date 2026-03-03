package transform

import (
	"io"
	"testing"
)

func TestBuildStagesOrder(t *testing.T) {
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

	stages := buildStages(Options{Stdout: io.Discard})

	if len(stages) != len(expected) {
		t.Fatalf("expected %d stages, got %d", len(expected), len(stages))
	}
	for _, tt := range expected {
		if stages[tt.idx].name != tt.name {
			t.Errorf("stage %d: expected %q, got %q", tt.idx, tt.name, stages[tt.idx].name)
		}
	}
}

func TestBuildStagesPassthrough(t *testing.T) {
	stages := buildStages(Options{Stdout: io.Discard})
	input := []string{
		`target triple = "bpf"`,
		"define i32 @my_prog(ptr %ctx) {",
		"entry:",
		"  ret i32 0",
		"}",
	}

	tests := make([]struct {
		name string
		fn   func([]string) ([]string, error)
	}, len(stages))
	for i, s := range stages {
		tests[i].name = s.name
		tests[i].fn = s.fn
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.fn == nil {
				t.Fatal("stage fn is nil")
			}
			out, err := tt.fn(input)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if out == nil {
				t.Error("returned nil lines")
			}
		})
	}
}
