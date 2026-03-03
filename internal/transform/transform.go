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

// TransformLines applies the full IR transformation pipeline.
func TransformLines(ctx context.Context, lines []string, opts Options) ([]string, error) {
	if opts.Stdout == nil {
		opts.Stdout = io.Discard
	}

	dumper := newStageDumper(opts.DumpDir, opts.Verbose, opts.Stdout)
	stages := buildStages(opts)

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
