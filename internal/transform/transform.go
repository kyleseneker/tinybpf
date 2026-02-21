// Package transform converts TinyGo-emitted host-targeted LLVM IR into
// BPF-compatible IR suitable for llc -march=bpf. All transformations operate
// on text lines — no CGo or libLLVM dependency required.
package transform

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// Shared LLVM IR patterns used by multiple transformation passes.
var (
	reDefine  = regexp.MustCompile(`^define\s+.*@(\w[\w.]*)\(`)
	reDeclare = regexp.MustCompile(`^declare\s+.*@([\w.]+)\(`)
	reGlobal  = regexp.MustCompile(`^@([\w.]+)\s*=`)
)

// Options configures the IR transformation pass.
type Options struct {
	Programs []string
	Sections map[string]string

	Verbose bool
	Stdout  io.Writer
}

// Run reads a .ll file, applies all transformations, and writes the result.
func Run(ctx context.Context, inputLL, outputLL string, opts Options) error {
	data, err := os.ReadFile(inputLL)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}
	lines, err := TransformLines(ctx, strings.Split(string(data), "\n"), opts)
	if err != nil {
		return err
	}
	size := len(lines) // newlines
	for _, line := range lines {
		size += len(line)
	}
	buf := bytes.NewBuffer(make([]byte, 0, size))
	for i, line := range lines {
		if i > 0 {
			buf.WriteByte('\n')
		}
		buf.WriteString(line)
	}
	return os.WriteFile(outputLL, buf.Bytes(), 0o600)
}

// TransformLines applies the full transformations to IR text lines:
// - retarget
// - strip attributes
// - extract programs
// - replace alloc
// - rewrite helpers
// - assign sections
// - strip map prefix
// - rewrite map BTF
// - sanitize BTF names
// - add license
// - cleanup
func TransformLines(ctx context.Context, lines []string, opts Options) ([]string, error) {
	if opts.Stdout == nil {
		opts.Stdout = io.Discard
	}
	var err error

	lines = retarget(lines)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	lines = stripAttributes(lines)

	lines, err = extractPrograms(lines, opts.Programs, opts.Verbose, opts.Stdout)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	lines, err = replaceAlloc(lines)
	if err != nil {
		return nil, err
	}
	lines, err = rewriteHelpers(lines)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	lines = assignSections(lines, opts.Sections)
	lines = stripMapPrefix(lines)
	lines = rewriteMapForBTF(lines)
	lines = sanitizeBTFNames(lines)
	lines = addLicense(lines)
	lines = cleanup(lines)
	return lines, nil
}
