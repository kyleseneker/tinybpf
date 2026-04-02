package transform

import (
	"errors"
	"strings"
	"testing"

	"github.com/kyleseneker/tinybpf/diag"
	"github.com/kyleseneker/tinybpf/internal/ir"
)

func TestRewriteHelpersMultiError(t *testing.T) {
	tests := []struct {
		name       string
		bodyLines  []string
		wantCount  int
		wantSubstr []string
	}{
		{
			name: "two unknown helpers collected",
			bodyLines: []string{
				"  %0 = call i64 @main.bpfFakeHelperAlpha(ptr undef)",
				"  %1 = call i64 @main.bpfFakeHelperBeta(ptr undef)",
			},
			wantCount:  2,
			wantSubstr: []string{"bpfFakeHelperAlpha", "bpfFakeHelperBeta"},
		},
		{
			name: "fuzzy suggestion included",
			bodyLines: []string{
				"  %0 = call i64 @main.bpfMapLookpElem(ptr undef)",
			},
			wantCount:  1,
			wantSubstr: []string{"did you mean"},
		},
		{
			name: "valid helper no error",
			bodyLines: []string{
				"  %0 = call i64 @main.bpfGetCurrentPidTgid(ptr undef)",
			},
			wantCount: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := &ir.Function{Name: "f", BodyRaw: tt.bodyLines}
			m := &ir.Module{Functions: []*ir.Function{fn}}
			err := rewriteHelpersModule(m)
			if tt.wantCount == 0 {
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
				t.Fatalf("expected *diag.Errors, got %T: %v", err, err)
			}
			if len(merr.Errs) != tt.wantCount {
				t.Fatalf("expected %d errors, got %d: %v", tt.wantCount, len(merr.Errs), merr.Errs)
			}
			msg := err.Error()
			for _, sub := range tt.wantSubstr {
				if !strings.Contains(msg, sub) {
					t.Errorf("missing %q in error:\n%s", sub, msg)
				}
			}
			if !diag.IsStage(err, diag.StageTransform) {
				t.Error("expected StageTransform")
			}
		})
	}
}
