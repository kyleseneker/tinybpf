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
	"strings"
)

// parseDefineName extracts the function name from a trimmed "define ... @name("
// line. Equivalent to regexp `^define\s+.*@(\w[\w.]*)\(`.
func parseDefineName(trimmed string) (string, bool) {
	if !strings.HasPrefix(trimmed, "define ") {
		return "", false
	}
	atIdx := strings.IndexByte(trimmed, '@')
	if atIdx < 0 {
		return "", false
	}
	start := atIdx + 1
	if start >= len(trimmed) || !isWordChar(trimmed[start]) {
		return "", false
	}
	end := start + 1
	for end < len(trimmed) && isIdentChar(trimmed[end]) {
		end++
	}
	if end >= len(trimmed) || trimmed[end] != '(' {
		return "", false
	}
	return trimmed[start:end], true
}

// isDefineLine reports whether a trimmed line is a define statement.
func isDefineLine(trimmed string) bool {
	_, ok := parseDefineName(trimmed)
	return ok
}

// parseDeclareName extracts the function name from a trimmed "declare ... @name("
// line. Equivalent to regexp `^declare\s+.*@([\w.]+)\(`.
func parseDeclareName(trimmed string) (string, bool) {
	if !strings.HasPrefix(trimmed, "declare ") {
		return "", false
	}
	atIdx := strings.IndexByte(trimmed, '@')
	if atIdx < 0 {
		return "", false
	}
	start := atIdx + 1
	if start >= len(trimmed) || !isIdentChar(trimmed[start]) {
		return "", false
	}
	end := start + 1
	for end < len(trimmed) && isIdentChar(trimmed[end]) {
		end++
	}
	if end >= len(trimmed) || trimmed[end] != '(' {
		return "", false
	}
	return trimmed[start:end], true
}

// parseGlobalName extracts the global name from a trimmed "@name = ..." line.
// Equivalent to regexp `^@([\w.]+)\s*=`.
func parseGlobalName(trimmed string) (string, bool) {
	if len(trimmed) == 0 || trimmed[0] != '@' {
		return "", false
	}
	start := 1
	if start >= len(trimmed) || !isIdentChar(trimmed[start]) {
		return "", false
	}
	end := start + 1
	for end < len(trimmed) && isIdentChar(trimmed[end]) {
		end++
	}
	rest := trimmed[end:]
	if len(rest) == 0 {
		return "", false
	}
	i := 0
	for i < len(rest) && (rest[i] == ' ' || rest[i] == '\t') {
		i++
	}
	if i >= len(rest) || rest[i] != '=' {
		return "", false
	}
	return trimmed[start:end], true
}

// isGlobalLine reports whether a trimmed line is a global variable definition.
func isGlobalLine(trimmed string) bool {
	_, ok := parseGlobalName(trimmed)
	return ok
}

func isWordChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '_'
}

// Options configures the IR transformation pass.
type Options struct {
	Programs []string
	Sections map[string]string
	Verbose  bool
	Stdout   io.Writer
	DumpDir  string
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

	dumper := newStageDumper(opts.DumpDir, opts.Verbose, opts.Stdout)

	var err error

	lines = retarget(lines)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dumper.dump("retarget", lines)

	lines = stripAttributes(lines)
	dumper.dump("strip-attributes", lines)

	lines, err = extractPrograms(lines, opts.Programs, opts.Verbose, opts.Stdout)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dumper.dump("extract-programs", lines)

	lines, err = replaceAlloc(lines)
	if err != nil {
		return nil, err
	}
	dumper.dump("replace-alloc", lines)

	lines, err = rewriteHelpers(lines)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dumper.dump("rewrite-helpers", lines)

	lines = assignSections(lines, opts.Sections)
	dumper.dump("assign-sections", lines)

	lines = stripMapPrefix(lines)
	dumper.dump("strip-map-prefix", lines)

	lines = rewriteMapForBTF(lines)
	dumper.dump("rewrite-map-btf", lines)

	lines = sanitizeBTFNames(lines)
	dumper.dump("sanitize-btf-names", lines)

	lines = addLicense(lines)
	dumper.dump("add-license", lines)

	lines = cleanup(lines)
	dumper.dump("cleanup", lines)

	return lines, nil
}

// stageDumper writes numbered IR snapshots to a directory for debugging.
type stageDumper struct {
	dir     string
	verbose bool
	out     io.Writer
	seq     int
}

func newStageDumper(dir string, verbose bool, out io.Writer) *stageDumper {
	return &stageDumper{dir: dir, verbose: verbose, out: out}
}

func (d *stageDumper) dump(stage string, lines []string) {
	if d.dir == "" {
		return
	}
	d.seq++
	name := fmt.Sprintf("%02d-%s.ll", d.seq, stage)
	path := d.dir + "/" + name
	data := strings.Join(lines, "\n")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		if d.verbose {
			fmt.Fprintf(d.out, "[dump-ir] failed to write %s: %v\n", path, err)
		}
		return
	}
	if d.verbose {
		fmt.Fprintf(d.out, "[dump-ir] %s (%d lines)\n", name, len(lines))
	}
}
