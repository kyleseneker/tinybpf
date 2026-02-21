// Package diag provides structured, stage-attributed error types for the
// tinybpf pipeline. Every failure includes the stage that produced it
// and an actionable hint.
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

// Error is a structured pipeline error carrying stage context, diagnostic
// output, and a user-facing hint for remediation.
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
