// Package transform converts TinyGo-emitted LLVM IR into BPF-compatible IR via structured AST rewrites.
package transform

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kyleseneker/tinybpf/internal/ir"
)

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
	module, err := ir.Parse(string(data))
	if err != nil {
		return fmt.Errorf("parse IR: %w", err)
	}
	if err := TransformModule(ctx, module, opts); err != nil {
		return err
	}
	return os.WriteFile(filepath.Clean(outputLL), []byte(ir.Serialize(module)), 0o600) //nolint:gosec // outputLL is a CLI-supplied build artifact path
}

// TransformModule applies the full IR transformation pipeline to a parsed module.
func TransformModule(ctx context.Context, m *ir.Module, opts Options) error {
	if opts.Stdout == nil {
		opts.Stdout = io.Discard
	}

	dumper := newModuleDumper(opts.DumpDir, opts.Verbose, opts.Stdout)
	stages := buildModuleStages(opts)

	for _, s := range stages {
		if err := s.fn(m); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		dumper.dump(s.name, m)
	}
	warnStackUsage(m, opts.Stdout)
	return nil
}

// TransformLines applies the full IR transformation pipeline to text lines.
func TransformLines(ctx context.Context, lines []string, opts Options) ([]string, error) {
	module, err := ir.Parse(strings.Join(lines, "\n"))
	if err != nil {
		return nil, fmt.Errorf("parse IR: %w", err)
	}
	if err := TransformModule(ctx, module, opts); err != nil {
		return nil, err
	}
	return strings.Split(ir.Serialize(module), "\n"), nil
}

// moduleDumper writes numbered IR snapshots to a directory for debugging.
type moduleDumper struct {
	dir     string
	verbose bool
	out     io.Writer
	seq     int
}

// newModuleDumper returns a dumper that writes snapshots to dir when non-empty.
func newModuleDumper(dir string, verbose bool, out io.Writer) *moduleDumper {
	return &moduleDumper{dir: dir, verbose: verbose, out: out}
}

// dump writes a numbered IR snapshot for the given stage to the dump directory.
func (d *moduleDumper) dump(stage string, m *ir.Module) {
	if d.dir == "" {
		return
	}
	d.seq++
	name := fmt.Sprintf("%02d-%s.ll", d.seq, stage)
	path := filepath.Join(d.dir, name)
	data := ir.Serialize(m)
	if err := os.WriteFile(filepath.Clean(path), []byte(data), 0o600); err != nil { //nolint:gosec // path is under the configured dump-IR dir
		if d.verbose {
			fmt.Fprintf(d.out, "[dump-ir] failed to write %s: %v\n", path, err)
		}
		return
	}
	if d.verbose {
		lines := strings.Split(data, "\n")
		fmt.Fprintf(d.out, "[dump-ir] %s (%d lines)\n", name, len(lines))
	}
}
