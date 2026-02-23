// Package transform converts TinyGo-emitted host-targeted LLVM IR into
// BPF-compatible IR suitable for llc -march=bpf. All transformations operate
// on text lines — no CGo or libLLVM dependency required.
package transform

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
)

// parseFuncName extracts the function name from a trimmed line starting with
// prefix ("define " or "declare ") followed by ... @name(. The noLeadingDot
// flag rejects identifiers starting with '.', which is invalid for defines.
func parseFuncName(trimmed, prefix string, noLeadingDot bool) (string, bool) {
	if !strings.HasPrefix(trimmed, prefix) {
		return "", false
	}
	atIdx := strings.IndexByte(trimmed, '@')
	if atIdx < 0 {
		return "", false
	}
	start := atIdx + 1
	if start >= len(trimmed) || !isIdentChar(trimmed[start]) || (noLeadingDot && trimmed[start] == '.') {
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

func parseDefineName(trimmed string) (string, bool) {
	return parseFuncName(trimmed, "define ", true)
}

func parseDeclareName(trimmed string) (string, bool) {
	return parseFuncName(trimmed, "declare ", false)
}

// parseGlobalName extracts the global name from a trimmed "@name = ..." line.
func parseGlobalName(trimmed string) (string, bool) {
	if len(trimmed) < 3 || trimmed[0] != '@' || !isIdentChar(trimmed[1]) {
		return "", false
	}
	i := 2
	for i < len(trimmed) && isIdentChar(trimmed[i]) {
		i++
	}
	nameEnd := i
	for i < len(trimmed) && (trimmed[i] == ' ' || trimmed[i] == '\t') {
		i++
	}
	if i >= len(trimmed) || trimmed[i] != '=' {
		return "", false
	}
	return trimmed[1:nameEnd], true
}

// extractMetadataID parses "!N = ..." and returns N, or -1 on failure.
func extractMetadataID(line string) int {
	if len(line) < 2 || line[0] != '!' || line[1] < '0' || line[1] > '9' {
		return -1
	}
	n := int(line[1] - '0')
	for i := 2; i < len(line) && line[i] >= '0' && line[i] <= '9'; i++ {
		n = n*10 + int(line[i]-'0')
	}
	return n
}

// irSnippet returns up to radius lines before and after index center for error context.
func irSnippet(lines []string, center, radius int) string {
	start := center - radius
	if start < 0 {
		start = 0
	}
	end := center + radius + 1
	if end > len(lines) {
		end = len(lines)
	}
	var b strings.Builder
	for i := start; i < end; i++ {
		marker := "  "
		if i == center {
			marker = "> "
		}
		fmt.Fprintf(&b, "%s%d: %s\n", marker, i+1, lines[i])
	}
	return b.String()
}

// camelToSnake converts "TaskStruct" to "task_struct".
func camelToSnake(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 4)
	for i, c := range s {
		if c >= 'A' && c <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteByte(byte(c - 'A' + 'a'))
		} else {
			b.WriteByte(byte(c))
		}
	}
	return b.String()
}

// Options configures the IR transformation pass.
type Options struct {
	Programs []string
	Sections map[string]string
	Verbose  bool
	Stdout   io.Writer
	DumpDir  string
}

// hasDeclare reports whether any declare line contains substr.
func hasDeclare(lines []string, substr string) bool {
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "declare") && strings.Contains(trimmed, substr) {
			return true
		}
	}
	return false
}

// insertBeforeFunc splices toInsert lines before the first declare or define
// statement. Falls back to appending if no function statement is found.
func insertBeforeFunc(lines []string, toInsert ...string) []string {
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "declare ") || strings.HasPrefix(trimmed, "define ") {
			result := make([]string, 0, len(lines)+len(toInsert))
			result = append(result, lines[:i]...)
			result = append(result, toInsert...)
			result = append(result, lines[i:]...)
			return result
		}
	}
	return append(lines, toInsert...)
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
	return os.WriteFile(outputLL, []byte(strings.Join(lines, "\n")), 0o600)
}

// transformStage pairs a human-readable name with a transform function.
type transformStage struct {
	name string
	fn   func([]string) ([]string, error)
}

// TransformLines applies the full IR transformation pipeline.
func TransformLines(ctx context.Context, lines []string, opts Options) ([]string, error) {
	if opts.Stdout == nil {
		opts.Stdout = io.Discard
	}

	dumper := newStageDumper(opts.DumpDir, opts.Verbose, opts.Stdout)

	extractProgs := func(l []string) ([]string, error) {
		return extractPrograms(l, opts.Programs, opts.Verbose, opts.Stdout)
	}
	assignProgSections := func(l []string) ([]string, error) {
		return assignProgramSections(l, opts.Sections)
	}

	stages := []transformStage{
		{"retarget", retarget},
		{"strip-attributes", stripAttributes},
		{"extract-programs", extractProgs},
		{"replace-alloc", replaceAlloc},
		{"rewrite-helpers", rewriteHelpers},
		{"rewrite-core-access", rewriteCoreAccess},
		{"rewrite-core-exists", rewriteCoreExistsChecks},
		{"assign-data-sections", assignDataSections},
		{"assign-program-sections", assignProgSections},
		{"strip-map-prefix", stripMapPrefix},
		{"rewrite-map-btf", rewriteMapForBTF},
		{"sanitize-btf-names", sanitizeBTFNames},
		{"sanitize-core-fields", sanitizeCoreFieldNames},
		{"add-license", addLicense},
		{"cleanup", cleanup},
	}

	var err error
	for _, s := range stages {
		lines, err = s.fn(lines)
		if err != nil {
			return nil, err
		}
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		dumper.dump(s.name, lines)
	}

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
