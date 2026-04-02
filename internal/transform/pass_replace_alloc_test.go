package transform

import (
	"errors"
	"strings"
	"testing"

	"github.com/kyleseneker/tinybpf/diag"
	"github.com/kyleseneker/tinybpf/internal/ir"
)

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

// Verify memsetIntrinsicName is accessible from this test file (defined in irutil.go).
func TestMemsetConstants(t *testing.T) {
	if !strings.Contains(memsetDecl, memsetIntrinsicName) {
		t.Error("memsetDecl should contain memsetIntrinsicName")
	}
}
