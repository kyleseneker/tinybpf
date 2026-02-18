// Package doctor implements the `tinybpf doctor` subcommand,
// which discovers and version-checks all LLVM toolchain binaries.
package doctor

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/kyleseneker/tinybpf/internal/llvm"
)

// Config holds settings for the doctor check.
type Config struct {
	Tools   llvm.ToolOverrides
	Stdout  io.Writer
	Stderr  io.Writer
	Timeout time.Duration
}

// Run discovers LLVM tools and prints their resolved paths and versions.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Stdout == nil {
		cfg.Stdout = io.Discard
	}
	if cfg.Stderr == nil {
		cfg.Stderr = io.Discard
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}

	tools, err := llvm.DiscoverTools(cfg.Tools)
	if err != nil {
		return err
	}

	fmt.Fprintln(cfg.Stdout, "tinybpf doctor")

	for _, t := range tools.List() {
		label := t.Name + ":"
		if t.Path == "" {
			fmt.Fprintf(cfg.Stdout, "  %-14s (not found, %s)\n", label, t.Note)
			continue
		}
		fmt.Fprintf(cfg.Stdout, "  %-14s %s\n", label, t.Path)

		res, runErr := llvm.Run(ctx, cfg.Timeout, t.Path, "--version")
		if runErr != nil {
			fmt.Fprintf(cfg.Stderr, "  [FAIL] %s --version: %v\n", t.Name, runErr)
			continue
		}
		line := firstNonEmptyLine(res.Stdout)
		if line == "" {
			line = firstNonEmptyLine(res.Stderr)
		}
		if line == "" {
			line = "(no version output)"
		}
		fmt.Fprintf(cfg.Stdout, "  [OK]   %s: %s\n", t.Name, line)
	}

	return nil
}

func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return ""
}
