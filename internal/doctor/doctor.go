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

		line := getToolVersion(ctx, cfg, t.Path, t.Name, "--version")
		fmt.Fprintf(cfg.Stdout, "  [OK]   %s: %s\n", t.Name, line)

		if major, ok := parseLLVMMajor(line); ok && llvmMajor == 0 {
			llvmMajor = major
		}
	}

	if w := checkExternalTool(ctx, cfg, "tinygo", "version",
		"TinyGo is not installed; install from https://tinygo.org/getting-started/install/"); w != "" {
		warnings = append(warnings, w)
	}

	if llvmMajor > 0 && llvmMajor < minLLVMMajor {
		warnings = append(warnings,
			fmt.Sprintf("LLVM %d detected; TinyGo 0.40.x requires LLVM %d+. "+
				"Install from https://apt.llvm.org or use the LLVM bundled with TinyGo.",
				llvmMajor, minLLVMMajor))
	}

	if w := checkExternalTool(ctx, cfg, "pahole", "--version",
		"pahole is not installed; needed for --btf flag. Install dwarves package."); w != "" {
		warnings = append(warnings, w)
	}

	printSummary(cfg.Stdout, warnings)
	return nil
}

// checkExternalTool looks up a binary on PATH, prints its path and version,
// and returns a warning string if the binary is not found (empty otherwise).
func checkExternalTool(ctx context.Context, cfg Config, name, versionFlag, notFoundMsg string) string {
	label := name + ":"
	path, _ := lookPath(name)
	if path == "" {
		fmt.Fprintf(cfg.Stdout, "  %-14s (not found)\n", label)
		return notFoundMsg
	}
	fmt.Fprintf(cfg.Stdout, "  %-14s %s\n", label, path)
	line := getToolVersion(ctx, cfg, path, name, versionFlag)
	fmt.Fprintf(cfg.Stdout, "  [OK]   %s: %s\n", name, line)
	return ""
}

// getToolVersion runs a binary with the given version flag and returns
// the first non-empty line of output.
func getToolVersion(ctx context.Context, cfg Config, path, name, flag string) string {
	res, runErr := llvm.Run(ctx, cfg.Timeout, path, flag)
	if runErr != nil {
		fmt.Fprintf(cfg.Stderr, "  [FAIL] %s --version: %v\n", name, runErr)
		return "(version check failed)"
	}
	line := firstNonEmptyLine(res.Stdout)
	if line == "" {
		line = firstNonEmptyLine(res.Stderr)
	}
	if line == "" {
		line = "(no version output)"
	}
	return line
}

// printSummary outputs the warnings list and final status.
func printSummary(w io.Writer, warnings []string) {
	if len(warnings) > 0 {
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "warnings:")
		for _, msg := range warnings {
			fmt.Fprintf(w, "  - %s\n", msg)
		}
	}
	fmt.Fprintln(w, "")
	if len(warnings) == 0 {
		fmt.Fprintln(w, "all checks passed")
	} else {
		fmt.Fprintf(w, "%d warning(s); see above\n", len(warnings))
	}
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
