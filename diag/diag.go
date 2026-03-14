// Package diag provides structured, stage-attributed error types for the tinybpf pipeline.
package diag

import (
	"errors"
	"fmt"
	"strings"
)

// Stage identifies which pipeline step produced an error.
type Stage string

const (
	StageDiscover  Stage = "discover-tools"
	StageInput     Stage = "input-normalization"
	StageLink      Stage = "llvm-link"
	StageTransform Stage = "transform"
	StageOpt       Stage = "opt"
	StageCodegen   Stage = "llc"
	StageFinalize  Stage = "finalize"
	StageBTF       Stage = "btf"
	StageValidate  Stage = "elf-validate"
	StageCompile   Stage = "tinygo-compile"
)

// Error is a structured pipeline error carrying stage context and a user-facing hint.
type Error struct {
	Stage   Stage
	Command string
	Stderr  string
	Hint    string
	Err     error
}

// Error formats the diagnostic into a multi-section string.
func (e *Error) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "stage %q failed", e.Stage)
	if e.Command != "" {
		fmt.Fprintf(&b, ": %s", e.Command)
	}
	if e.Err != nil {
		fmt.Fprintf(&b, ": %v", e.Err)
	}
	if e.Stderr != "" {
		b.WriteString("\n--- stderr ---\n")
		b.WriteString(trimLong(e.Stderr, 20))
	}
	if e.Hint != "" {
		b.WriteString("\n--- hint ---\n")
		b.WriteString(e.Hint)
	}
	return b.String()
}

// Unwrap returns the underlying error for use with errors.Is/As.
func (e *Error) Unwrap() error {
	return e.Err
}

// IsStage reports whether err is a diag.Error or diag.Errors from the given stage.
func IsStage(err error, stage Stage) bool {
	var derr *Error
	if errors.As(err, &derr) {
		return derr.Stage == stage
	}
	var merr *Errors
	if errors.As(err, &merr) {
		return merr.Stage == stage
	}
	return false
}

// Errors aggregates multiple errors from a single stage so all problems are reported at once.
type Errors struct {
	Stage    Stage
	PassName string
	Errs     []error
	Hint     string
}

// Error formats the aggregated diagnostics into a numbered list.
func (e *Errors) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "stage %q failed: %d problem(s) in %s:", e.Stage, len(e.Errs), e.PassName)
	for _, err := range e.Errs {
		fmt.Fprintf(&b, "\n  %v", err)
	}
	if e.Hint != "" {
		b.WriteString("\n--- hint ---\n")
		b.WriteString(e.Hint)
	}
	return b.String()
}

// Unwrap returns the individual errors for use with errors.Is/As.
func (e *Errors) Unwrap() []error {
	return e.Errs
}

// WrapErrors creates a multi-error for a stage/pass, returning nil when errs is empty.
func WrapErrors(stage Stage, passName string, errs []error, hint string) error {
	if len(errs) == 0 {
		return nil
	}
	return &Errors{Stage: stage, PassName: passName, Errs: errs, Hint: hint}
}

// Wrap creates a stage-attributed error with a user-facing hint.
func Wrap(stage Stage, err error, hint string) *Error {
	return &Error{Stage: stage, Err: err, Hint: hint}
}

// WrapCmd creates a stage-attributed error for a failed command invocation.
func WrapCmd(stage Stage, err error, command, stderr, hint string) *Error {
	return &Error{Stage: stage, Err: err, Command: command, Stderr: stderr, Hint: hint}
}

// trimLong truncates s to maxLines, appending a truncation marker if needed.
func trimLong(s string, maxLines int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) <= maxLines {
		return strings.Join(lines, "\n")
	}
	return strings.Join(lines[:maxLines], "\n") + "\n...(truncated)"
}
