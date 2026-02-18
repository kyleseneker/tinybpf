// Package diag provides structured, stage-attributed error types for the
// tinybpf pipeline. Every failure includes the stage that produced it,
// a machine-readable error code, and an actionable hint.
package diag

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Stage identifies which pipeline step produced an error.
type Stage string

// Code is a machine-readable error classification.
type Code string

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
)

const (
	CodeToolNotFound  Code = "TOOL_NOT_FOUND"
	CodeInvalidInput  Code = "INVALID_INPUT"
	CodeTimeout       Code = "TIMEOUT"
	CodeToolExecution Code = "TOOL_EXECUTION_FAILED"
	CodeValidation    Code = "ELF_VALIDATION_FAILED"
)

// Error is a structured pipeline error carrying stage context, diagnostic
// output, and a user-facing hint for remediation.
type Error struct {
	Stage   Stage
	Code    Code
	Retry   bool
	Command string
	Stderr  string
	Hint    string
	Err     error
}

// Error formats the diagnostic into a multi-section string.
func (e *Error) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "stage %q failed", e.Stage)
	if e.Code != "" {
		fmt.Fprintf(&b, " [%s]", e.Code)
	}
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
	if e.Retry {
		b.WriteString("\n--- retry ---\n")
		b.WriteString("This failure might be transient. Verify toolchain/process state and retry.")
	}
	return b.String()
}

// Unwrap returns the underlying error for use with errors.Is/As.
func (e *Error) Unwrap() error {
	return e.Err
}

// New creates a stage-attributed diagnostic error with automatic
// code classification based on the stage and error content.
func New(stage Stage, err error, command, stderr, hint string) error {
	code, retry := classify(stage, err)
	return &Error{
		Stage:   stage,
		Code:    code,
		Retry:   retry,
		Command: command,
		Stderr:  stderr,
		Hint:    hint,
		Err:     err,
	}
}

// IsStage reports whether err is a diag.Error from the given pipeline stage.
func IsStage(err error, stage Stage) bool {
	var derr *Error
	if !errors.As(err, &derr) {
		return false
	}
	return derr.Stage == stage
}

func trimLong(s string, maxLines int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) <= maxLines {
		return strings.Join(lines, "\n")
	}
	return strings.Join(lines[:maxLines], "\n") + "\n...(truncated)"
}

func classify(stage Stage, err error) (Code, bool) {
	if errors.Is(err, context.DeadlineExceeded) ||
		strings.Contains(strings.ToLower(err.Error()), "timed out") {
		return CodeTimeout, true
	}
	switch stage {
	case StageDiscover:
		return CodeToolNotFound, false
	case StageInput:
		return CodeInvalidInput, false
	case StageValidate:
		return CodeValidation, false
	default:
		return CodeToolExecution, false
	}
}
