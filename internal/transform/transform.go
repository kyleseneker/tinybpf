// Package transform converts TinyGo-emitted host-targeted LLVM IR into
// BPF-compatible IR suitable for llc -march=bpf. All transformations operate
// on text lines — no CGo or libLLVM dependency required.
package transform

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
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

func parseDefineName(trimmed string) (string, bool) { return parseFuncName(trimmed, "define ", true) }
func parseDeclareName(trimmed string) (string, bool) {
	return parseFuncName(trimmed, "declare ", false)
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

// extractMetadataID parses "!N = ..." and returns N, or -1 on failure.
func extractMetadataID(line string) int {
	if len(line) == 0 || line[0] != '!' {
		return -1
	}
	i := 1
	for i < len(line) && line[i] >= '0' && line[i] <= '9' {
		i++
	}
	if i == 1 {
		return -1
	}
	n, err := strconv.Atoi(line[1:i])
	if err != nil {
		return -1
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

// Options configures the IR transformation pass.
type Options struct {
	Programs []string
	Sections map[string]string
	Verbose  bool
	Stdout   io.Writer
	DumpDir  string
	CoreMode bool
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
			result := make([]string, 0, len(lines)+len(toInsert)+1)
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

// TransformLines applies the full transformations to IR text lines:
// - retarget
// - strip attributes
// - extract programs
// - replace alloc
// - rewrite helpers
// - rewrite CO-RE access (when --core is enabled)
// - assign data sections
// - assign program sections
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

	if opts.CoreMode {
		lines = rewriteCoreAccess(lines)
		dumper.dump("rewrite-core-access", lines)
	}

	lines = assignDataSections(lines)
	dumper.dump("assign-data-sections", lines)

	lines = assignProgramSections(lines, opts.Sections)
	dumper.dump("assign-program-sections", lines)

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
