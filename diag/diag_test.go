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
	tests := []struct {
		name  string
		inner error
		stage Stage
	}{
		{
			name:  "exposes inner error",
			inner: errors.New("root cause"),
			stage: StageOpt,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &Error{Stage: tt.stage, Err: tt.inner}
			if !errors.Is(err, tt.inner) {
				t.Fatal("Unwrap should expose inner error")
			}
		})
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
	tests := []struct {
		name  string
		inner error
		other []error
		stage Stage
	}{
		{
			name:  "finds inner error through Unwrap",
			inner: errors.New("root cause"),
			other: []error{errors.New("other")},
			stage: StageTransform,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			merr := &Errors{
				Stage:    tt.stage,
				PassName: "test",
				Errs:     append([]error{tt.inner}, tt.other...),
			}
			if !errors.Is(merr, tt.inner) {
				t.Fatal("errors.Is should find inner error through Unwrap")
			}
		})
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
	tests := []struct {
		name  string
		stage Stage
		inner error
		hint  string
	}{
		{
			name:  "wraps error with stage and hint",
			stage: StageInput,
			inner: errors.New("underlying"),
			hint:  "try something",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Wrap(tt.stage, tt.inner, tt.hint)
			literal := &Error{Stage: tt.stage, Err: tt.inner, Hint: tt.hint}

			if got.Error() != literal.Error() {
				t.Fatalf("Wrap output mismatch:\ngot:    %s\nwant:   %s", got.Error(), literal.Error())
			}
			if !IsStage(got, tt.stage) {
				t.Fatalf("expected stage %v", tt.stage)
			}
			if !errors.Is(got, tt.inner) {
				t.Fatal("Unwrap should expose inner error")
			}
		})
	}
}

func TestWrapCmd(t *testing.T) {
	tests := []struct {
		name    string
		stage   Stage
		inner   error
		command string
		stderr  string
		hint    string
	}{
		{
			name:    "wraps command error with all fields",
			stage:   StageLink,
			inner:   errors.New("exit 1"),
			command: "llvm-link a.ll",
			stderr:  "link error",
			hint:    "check IR",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WrapCmd(tt.stage, tt.inner, tt.command, tt.stderr, tt.hint)
			literal := &Error{Stage: tt.stage, Err: tt.inner, Command: tt.command, Stderr: tt.stderr, Hint: tt.hint}

			if got.Error() != literal.Error() {
				t.Fatalf("WrapCmd output mismatch:\ngot:    %s\nwant:   %s", got.Error(), literal.Error())
			}
			if !IsStage(got, tt.stage) {
				t.Fatalf("expected stage %v", tt.stage)
			}
			if !errors.Is(got, tt.inner) {
				t.Fatal("Unwrap should expose inner error")
			}
		})
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
