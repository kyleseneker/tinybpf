package diag

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		name      string
		stage     Stage
		err       error
		wantCode  Code
		wantRetry bool
	}{
		{
			name:      "deadline exceeded",
			stage:     StageOpt,
			err:       context.DeadlineExceeded,
			wantCode:  CodeTimeout,
			wantRetry: true,
		},
		{
			name:      "timed out message",
			stage:     StageCodegen,
			err:       errors.New("command timed out"),
			wantCode:  CodeTimeout,
			wantRetry: true,
		},
		{
			name:     "input stage",
			stage:    StageInput,
			err:      errors.New("bad input"),
			wantCode: CodeInvalidInput,
		},
		{
			name:     "discover stage",
			stage:    StageDiscover,
			err:      errors.New("not found"),
			wantCode: CodeToolNotFound,
		},
		{
			name:     "validate stage",
			stage:    StageValidate,
			err:      errors.New("bad elf"),
			wantCode: CodeValidation,
		},
		{
			name:     "default (codegen)",
			stage:    StageCodegen,
			err:      errors.New("llc failed"),
			wantCode: CodeToolExecution,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diagErr := New(tt.stage, tt.err, "", "", "")
			var derr *Error
			if !errors.As(diagErr, &derr) {
				t.Fatal("expected diag.Error")
			}
			if derr.Code != tt.wantCode {
				t.Fatalf("code: got %s, want %s", derr.Code, tt.wantCode)
			}
			if derr.Retry != tt.wantRetry {
				t.Fatalf("retry: got %v, want %v", derr.Retry, tt.wantRetry)
			}
		})
	}
}

func TestErrorFormat(t *testing.T) {
	t.Run("full", func(t *testing.T) {
		err := &Error{
			Stage:   StageLink,
			Code:    CodeToolExecution,
			Retry:   true,
			Command: "llvm-link in.ll",
			Stderr:  "some error output",
			Hint:    "check your IR",
			Err:     errors.New("exit status 1"),
		}
		s := err.Error()
		for _, want := range []string{
			`stage "llvm-link" failed`,
			"[TOOL_EXECUTION_FAILED]",
			"llvm-link in.ll",
			"exit status 1",
			"--- stderr ---",
			"some error output",
			"--- hint ---",
			"check your IR",
			"--- retry ---",
		} {
			if !strings.Contains(s, want) {
				t.Errorf("missing %q in:\n%s", want, s)
			}
		}
	})

	t.Run("minimal", func(t *testing.T) {
		err := &Error{Stage: StageOpt, Err: errors.New("fail")}
		s := err.Error()
		if !strings.Contains(s, `stage "opt" failed`) {
			t.Errorf("unexpected: %s", s)
		}
		for _, absent := range []string{"--- stderr ---", "--- hint ---", "--- retry ---"} {
			if strings.Contains(s, absent) {
				t.Errorf("should not include %q when empty/false", absent)
			}
		}
	})
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
		{"match", New(StageOpt, errors.New("fail"), "", "", ""), StageOpt, true},
		{"no match", New(StageOpt, errors.New("fail"), "", "", ""), StageLink, false},
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

func TestTrimLong(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		maxLines  int
		wantTrunc bool
		wantLines int
	}{
		{"no truncation", "line1\nline2\nline3", 5, false, 3},
		{"truncated", strings.Repeat("line\n", 30), 5, true, 5},
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
