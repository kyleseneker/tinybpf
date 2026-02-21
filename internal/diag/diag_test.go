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
		{"match", &Error{Stage: StageOpt, Err: errors.New("fail")}, StageOpt, true},
		{"no match", &Error{Stage: StageOpt, Err: errors.New("fail")}, StageLink, false},
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
