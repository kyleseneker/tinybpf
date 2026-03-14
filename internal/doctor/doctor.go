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

// pathLookup is a function that looks up a tool path by name.
type pathLookup func(name string) (string, error)

// Config holds settings for the doctor check.
type Config struct {
	Tools   llvm.ToolOverrides
	Stdout  io.Writer
	Stderr  io.Writer
	Timeout time.Duration
}

// Run discovers LLVM tools and prints their resolved paths and versions.
func Run(ctx context.Context, cfg Config) error {
	return runWith(ctx, cfg, exec.LookPath)
}

// runWith runs the doctor check with a custom path lookup function.
func runWith(ctx context.Context, cfg Config, lookup pathLookup) error {
	normalizeConfig(&cfg)

	tools, err := llvm.DiscoverTools(cfg.Tools)
	if err != nil {
		return err
	}

	fmt.Fprintln(cfg.Stdout, "tinybpf doctor")

	llvmMajor := reportLLVMTools(ctx, cfg, tools)

	var warnings []string

	if w := checkExternalTool(ctx, cfg, lookup, "tinygo", "version",
		"TinyGo is not installed; install from https://tinygo.org/getting-started/install/"); w != "" {
		warnings = append(warnings, w)
	}

	if w := llvmVersionWarning(llvmMajor); w != "" {
		warnings = append(warnings, w)
	}

	if w := checkExternalTool(ctx, cfg, lookup, "pahole", "--version",
		"pahole is not installed; needed for --btf flag. Install dwarves package."); w != "" {
		warnings = append(warnings, w)
	}

	printSummary(cfg.Stdout, warnings)
	return nil
}

// normalizeConfig normalizes the config.
func normalizeConfig(cfg *Config) {
	if cfg.Stdout == nil {
		cfg.Stdout = io.Discard
	}
	if cfg.Stderr == nil {
		cfg.Stderr = io.Discard
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
}

// reportLLVMTools reports the LLVM tools and their versions.
func reportLLVMTools(ctx context.Context, cfg Config, tools llvm.Tools) int {
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
	return llvmMajor
}

// checkExternalTool checks an external tool and returns a warning message if it is not found.
func checkExternalTool(ctx context.Context, cfg Config, lookup pathLookup, name, versionFlag, notFoundMsg string) string {
	label := name + ":"
	path, _ := lookup(name)
	if path == "" {
		fmt.Fprintf(cfg.Stdout, "  %-14s (not found)\n", label)
		return notFoundMsg
	}
	fmt.Fprintf(cfg.Stdout, "  %-14s %s\n", label, path)
	line := getToolVersion(ctx, cfg, path, name, versionFlag)
	fmt.Fprintf(cfg.Stdout, "  [OK]   %s: %s\n", name, line)
	return ""
}

// getToolVersion gets the version of a tool.
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

// printSummary prints the summary of the doctor check.
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

// llvmVersionWarning returns a warning message if the LLVM version is too old.
func llvmVersionWarning(llvmMajor int) string {
	if llvmMajor > 0 && llvmMajor < minLLVMMajor {
		return fmt.Sprintf("LLVM %d detected; TinyGo 0.40.x requires LLVM %d+. "+
			"Install from https://apt.llvm.org or use the LLVM bundled with TinyGo.",
			llvmMajor, minLLVMMajor)
	}
	return ""
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

// firstNonEmptyLine returns the first non-empty line from a string.
func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return ""
}
