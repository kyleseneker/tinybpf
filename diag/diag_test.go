package diag

import (
	"errors"
	"strings"
	"testing"
)

func TestErrorFormat(t *testing.T) {
	tests := []struct {
		name    string
		err     *Error
		want    []string
		notWant []string
	}{
		{
			name: "full",
			err: &Error{
				Stage:   StageLink,
				Command: "llvm-link in.ll",
				Stderr:  "some error output",
				Hint:    "check your IR",
				Err:     errors.New("exit status 1"),
			},
			want: []string{
				`stage "llvm-link" failed`,
				"llvm-link in.ll",
				"exit status 1",
				"--- stderr ---",
				"some error output",
				"--- hint ---",
				"check your IR",
			},
		},
		{
			name: "minimal",
			err:  &Error{Stage: StageOpt, Err: errors.New("fail")},
			want: []string{`stage "opt" failed`},
			notWant: []string{
				"--- stderr ---",
				"--- hint ---",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.err.Error()
			for _, w := range tt.want {
				if !strings.Contains(s, w) {
					t.Errorf("missing %q in:\n%s", w, s)
				}
			}
			for _, nw := range tt.notWant {
				if strings.Contains(s, nw) {
					t.Errorf("should not include %q when empty", nw)
				}
			}
		})
	}
}

func TestErrorUnwrap(t *testing.T) {
	inner := errors.New("root cause")
	err := &Error{Stage: StageOpt, Err: inner}
	if !errors.Is(err, inner) {
		t.Fatal("Unwrap should expose inner error")
	}
}

func TestIsStage(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		stage Stage
		want  bool
	}{
		{"Error match", &Error{Stage: StageOpt, Err: errors.New("fail")}, StageOpt, true},
		{"Error no match", &Error{Stage: StageOpt, Err: errors.New("fail")}, StageLink, false},
		{"Errors match", &Errors{Stage: StageTransform, PassName: "p", Errs: []error{errors.New("x")}}, StageTransform, true},
		{"Errors no match", &Errors{Stage: StageTransform, PassName: "p", Errs: []error{errors.New("x")}}, StageOpt, false},
		{"non-diag error", errors.New("plain"), StageOpt, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsStage(tt.err, tt.stage); got != tt.want {
				t.Fatalf("IsStage = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestErrorsFormat(t *testing.T) {
	tests := []struct {
		name    string
		errs    *Errors
		want    []string
		notWant []string
	}{
		{
			name: "multiple errors with hint",
			errs: &Errors{
				Stage:    StageTransform,
				PassName: "rewrite-helpers",
				Errs:     []error{errors.New("unknown helper A"), errors.New("unknown helper B")},
				Hint:     "check helper names",
			},
			want: []string{
				`stage "transform" failed: 2 problem(s) in rewrite-helpers:`,
				"unknown helper A",
				"unknown helper B",
				"--- hint ---",
				"check helper names",
			},
		},
		{
			name: "single error no hint",
			errs: &Errors{
				Stage:    StageTransform,
				PassName: "core",
				Errs:     []error{errors.New("bad GEP")},
			},
			want:    []string{`1 problem(s) in core:`},
			notWant: []string{"--- hint ---"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.errs.Error()
			for _, w := range tt.want {
				if !strings.Contains(s, w) {
					t.Errorf("missing %q in:\n%s", w, s)
				}
			}
			for _, nw := range tt.notWant {
				if strings.Contains(s, nw) {
					t.Errorf("should not include %q when empty", nw)
				}
			}
		})
	}
}

func TestErrorsUnwrap(t *testing.T) {
	inner := errors.New("root cause")
	merr := &Errors{
		Stage:    StageTransform,
		PassName: "test",
		Errs:     []error{inner, errors.New("other")},
	}
	if !errors.Is(merr, inner) {
		t.Fatal("errors.Is should find inner error through Unwrap")
	}
}

func TestWrapErrors(t *testing.T) {
	tests := []struct {
		name    string
		errs    []error
		wantNil bool
	}{
		{"nil for empty", nil, true},
		{"nil for zero-length", []error{}, true},
		{"non-nil for errors", []error{errors.New("a")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WrapErrors(StageTransform, "pass", tt.errs, "hint")
			if tt.wantNil && got != nil {
				t.Fatalf("expected nil, got %v", got)
			}
			if !tt.wantNil && got == nil {
				t.Fatal("expected non-nil")
			}
		})
	}
}

func TestWrap(t *testing.T) {
	inner := errors.New("underlying")
	got := Wrap(StageInput, inner, "try something")
	literal := &Error{Stage: StageInput, Err: inner, Hint: "try something"}

	if got.Error() != literal.Error() {
		t.Fatalf("Wrap output mismatch:\ngot:    %s\nwant:   %s", got.Error(), literal.Error())
	}
	if !IsStage(got, StageInput) {
		t.Fatal("expected StageInput")
	}
	if !errors.Is(got, inner) {
		t.Fatal("Unwrap should expose inner error")
	}
}

func TestWrapCmd(t *testing.T) {
	inner := errors.New("exit 1")
	got := WrapCmd(StageLink, inner, "llvm-link a.ll", "link error", "check IR")
	literal := &Error{Stage: StageLink, Err: inner, Command: "llvm-link a.ll", Stderr: "link error", Hint: "check IR"}

	if got.Error() != literal.Error() {
		t.Fatalf("WrapCmd output mismatch:\ngot:    %s\nwant:   %s", got.Error(), literal.Error())
	}
	if !IsStage(got, StageLink) {
		t.Fatal("expected StageLink")
	}
	if !errors.Is(got, inner) {
		t.Fatal("Unwrap should expose inner error")
	}
}

func TestTrimLong(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		maxLines  int
		wantTrunc bool
	}{
		{"no truncation", "line1\nline2\nline3", 5, false},
		{"truncated", strings.Repeat("line\n", 30), 5, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := trimLong(tt.input, tt.maxLines)
			if tt.wantTrunc {
				if !strings.HasSuffix(got, "...(truncated)") {
					t.Fatalf("expected truncation suffix, got: %q", got)
				}
			} else {
				if strings.Contains(got, "truncated") {
					t.Fatalf("unexpected truncation: %q", got)
				}
			}
		})
	}
}
