// Package doctor implements the `tinybpf doctor` subcommand,
// which discovers and version-checks all LLVM toolchain binaries.
package doctor

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/kyleseneker/tinybpf/internal/llvm"
)

const minLLVMMajor = 20

// lookPath is the function used to locate binaries on PATH.
var lookPath = exec.LookPath

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

	var warnings []string
	var llvmMajor int

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

		if major, ok := parseLLVMMajor(line); ok && llvmMajor == 0 {
			llvmMajor = major
		}
	}

	tinygoPath, _ := lookPath("tinygo")
	if tinygoPath == "" {
		fmt.Fprintf(cfg.Stdout, "  %-14s (not found)\n", "tinygo:")
		warnings = append(warnings,
			"TinyGo is not installed; install from https://tinygo.org/getting-started/install/")
	} else {
		fmt.Fprintf(cfg.Stdout, "  %-14s %s\n", "tinygo:", tinygoPath)
		res, runErr := llvm.Run(ctx, cfg.Timeout, tinygoPath, "version")
		if runErr != nil {
			fmt.Fprintf(cfg.Stderr, "  [FAIL] tinygo version: %v\n", runErr)
		} else {
			line := firstNonEmptyLine(res.Stdout)
			if line == "" {
				line = firstNonEmptyLine(res.Stderr)
			}
			if line == "" {
				line = "(no version output)"
			}
			fmt.Fprintf(cfg.Stdout, "  [OK]   tinygo: %s\n", line)
		}
	}

	if llvmMajor > 0 && llvmMajor < minLLVMMajor {
		warnings = append(warnings,
			fmt.Sprintf("LLVM %d detected; TinyGo 0.40.x requires LLVM %d+. "+
				"Install from https://apt.llvm.org or use the LLVM bundled with TinyGo.",
				llvmMajor, minLLVMMajor))
	}

	if len(warnings) > 0 {
		fmt.Fprintln(cfg.Stdout, "")
		fmt.Fprintln(cfg.Stdout, "warnings:")
		for _, w := range warnings {
			fmt.Fprintf(cfg.Stdout, "  - %s\n", w)
		}
	}

	fmt.Fprintln(cfg.Stdout, "")
	if len(warnings) == 0 {
		fmt.Fprintln(cfg.Stdout, "all checks passed")
	} else {
		fmt.Fprintf(cfg.Stdout, "%d warning(s); see above\n", len(warnings))
	}

	return nil
}

// parseLLVMMajor extracts the LLVM major version from a version string
// like "Ubuntu LLVM version 20.1.1" or "LLVM version 18.1.8".
func parseLLVMMajor(s string) (int, bool) {
	const prefix = "LLVM version "
	idx := strings.Index(s, prefix)
	if idx < 0 {
		return 0, false
	}
	rest := s[idx+len(prefix):]
	end := strings.IndexAny(rest, ". \t\n")
	if end < 0 {
		end = len(rest)
	}
	if end == 0 {
		return 0, false
	}
	major, err := strconv.Atoi(rest[:end])
	if err != nil {
		return 0, false
	}
	return major, true
}

func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return ""
}
