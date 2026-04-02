// Package llvm provides typed wrappers for discovering and executing
// LLVM toolchain binaries (llvm-link, opt, llc, and optional helpers).
package llvm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kyleseneker/tinybpf/diag"
)

// allowedToolBases is the canonical set of tool basenames this linker
// is permitted to execute.
var allowedToolBases = map[string]bool{
	"llvm-link":    true,
	"opt":          true,
	"llc":          true,
	"llvm-ar":      true,
	"llvm-objcopy": true,
	"pahole":       true,
	"tinygo":       true,
	"ld.lld":       true,
}

// ValidateBinary checks that a resolved binary path refers to an allowed
// tool and does not contain characters indicative of shell injection.
func ValidateBinary(binPath string) error {
	if strings.ContainsAny(binPath, ";|&$`\n") {
		return fmt.Errorf("binary path %q contains prohibited characters", binPath)
	}
	if !isAllowedTool(binPath) {
		return fmt.Errorf("binary %q (basename %q) is not in the allowed tool set",
			binPath, filepath.Base(binPath))
	}
	return nil
}

// isAllowedTool reports whether binPath's basename matches an allowed tool,
// including version-suffixed names like "opt-18" or "llvm-link-17.0.6".
func isAllowedTool(binPath string) bool {
	base := filepath.Base(binPath)
	if allowedToolBases[base] {
		return true
	}
	for name := range allowedToolBases {
		if strings.HasPrefix(base, name+"-") {
			suffix := base[len(name)+1:]
			if isVersionSuffix(suffix) {
				return true
			}
		}
	}
	return false
}

// isVersionSuffix reports whether s looks like a version (e.g. "18", "17.0.6").
func isVersionSuffix(s string) bool {
	if s == "" {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if part == "" {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// sanitizedEnv returns a minimal, deterministic environment for subprocess execution.
func sanitizedEnv() []string {
	env := []string{
		"LC_ALL=C",
		"TZ=UTC",
	}
	for _, key := range []string{"PATH", "HOME", "TMPDIR"} {
		if v := os.Getenv(key); v != "" {
			env = append(env, key+"="+v)
		}
	}
	return env
}

// Tools holds resolved paths to all required and optional LLVM binaries.
type Tools struct {
	LLVMLink    string
	Opt         string
	LLC         string
	LLVMAr      string // optional; needed for .a input expansion
	Objcopy     string // optional; needed for .o bitcode extraction
	Pahole      string // optional; needed for --btf
	VersionHash string
}

// ToolOverrides allows callers to specify explicit binary paths,
// bypassing PATH-based discovery.
type ToolOverrides struct {
	LLVMLink string
	Opt      string
	LLC      string
	LLVMAr   string
	Objcopy  string
	Pahole   string
}

// NamedTool pairs a human-readable label with a resolved path.
type NamedTool struct {
	Name     string
	Path     string
	Required bool
	Note     string // description shown when an optional tool is missing
}

// List returns all discovered tools in a stable order.
func (t Tools) List() []NamedTool {
	return []NamedTool{
		{"llvm-link", t.LLVMLink, true, ""},
		{"opt", t.Opt, true, ""},
		{"llc", t.LLC, true, ""},
		{"llvm-ar", t.LLVMAr, false, "needed for .a inputs"},
		{"llvm-objcopy", t.Objcopy, false, "needed for .o bitcode extraction"},
		{"pahole", t.Pahole, false, "needed for --btf"},
	}
}

// toolSpec describes a single tool to discover.
type toolSpec struct {
	override string
	name     string
	flag     string
	required bool
}

// DiscoverTools resolves LLVM binary paths from overrides or PATH.
func DiscoverTools(o ToolOverrides) (Tools, error) {
	specs := []toolSpec{
		{o.LLVMLink, "llvm-link", "--llvm-link", true},
		{o.Opt, "opt", "--opt", true},
		{o.LLC, "llc", "--llc", true},
		{o.LLVMAr, "llvm-ar", "--llvm-ar", false},
		{o.Objcopy, "llvm-objcopy", "--llvm-objcopy", false},
		{o.Pahole, "pahole", "--pahole", false},
	}

	paths := make([]string, len(specs))
	for i, s := range specs {
		var (
			path string
			err  error
		)
		if s.required {
			path, err = resolveRequired(firstNonEmpty(s.override, s.name))
		} else {
			path, err = resolveOptional(s.override, s.name)
		}
		if err != nil {
			hint := fmt.Sprintf("install %s or pass %s explicitly", s.name, s.flag)
			if s.required {
				hint = "install LLVM tools or pass " + s.flag + " explicitly"
			}
			return Tools{}, diag.WrapCmd(diag.StageDiscover, err, s.name, "", hint)
		}
		paths[i] = path
	}

	tools := Tools{
		LLVMLink: paths[0],
		Opt:      paths[1],
		LLC:      paths[2],
		LLVMAr:   paths[3],
		Objcopy:  paths[4],
		Pahole:   paths[5],
	}
	tools.VersionHash = toolVersionHash(tools)
	return tools, nil
}

// toolVersionHash produces a short fingerprint of the required tools' --version
// output so that cache keys change when LLVM is upgraded in-place.
func toolVersionHash(t Tools) string {
	h := sha256.New()
	for _, bin := range []string{t.LLVMLink, t.Opt, t.LLC} {
		if bin == "" {
			continue
		}
		out, err := exec.Command(bin, "--version").CombinedOutput()
		if err != nil {
			h.Write([]byte(bin))
		} else {
			h.Write(out)
		}
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// resolveRequired resolves and validates a required tool path.
func resolveRequired(name string) (string, error) {
	path, err := findRequired(name)
	if err != nil {
		return "", err
	}
	if err := ValidateBinary(path); err != nil {
		return "", err
	}
	return path, nil
}

// resolveOptional resolves and validates an optional tool path.
func resolveOptional(override, defaultName string) (string, error) {
	path, err := findOptional(override, defaultName)
	if err != nil {
		return "", err
	}
	if path != "" {
		if err := ValidateBinary(path); err != nil {
			return "", err
		}
	}
	return path, nil
}

// Result captures the command string and stdout/stderr of an LLVM tool run.
type Result struct {
	Command string
	Stdout  string
	Stderr  string
}

// commandRunner is a function that executes a command and returns the stdout and stderr.
type commandRunner func(ctx context.Context, bin string, args, env []string) (stdout, stderr []byte, err error)

// Run executes an LLVM binary with a per-invocation timeout.
func Run(ctx context.Context, timeout time.Duration, bin string, args ...string) (Result, error) {
	return runWith(ctx, timeout, bin, args, execCommand)
}

// runWith executes a command with a timeout and returns the result.
func runWith(ctx context.Context, timeout time.Duration, bin string, args []string, run commandRunner) (Result, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	stdout, stderr, runErr := run(cmdCtx, bin, args, sanitizedEnv())
	result := Result{
		Command: formatCommand(bin, args),
		Stdout:  string(stdout),
		Stderr:  string(stderr),
	}
	if runErr == nil {
		return result, nil
	}
	if errors.Is(cmdCtx.Err(), context.DeadlineExceeded) {
		return result, fmt.Errorf("command timed out after %s: %w", timeout, runErr)
	}
	return result, runErr
}

// execCommand executes a command and returns the stdout and stderr.
func execCommand(ctx context.Context, bin string, args, env []string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = env
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	err := cmd.Run()
	return stdoutBuf.Bytes(), stderrBuf.Bytes(), err
}

// findRequired resolves a tool name that must exist (absolute path or PATH lookup).
func findRequired(name string) (string, error) {
	if strings.ContainsRune(name, '/') {
		info, err := os.Stat(name)
		if err != nil {
			return "", err
		}
		if info.Mode()&0o111 == 0 {
			return "", fmt.Errorf("%s is not executable", name)
		}
		return name, nil
	}
	return exec.LookPath(name)
}

// findOptional resolves a tool that is not required, returning "" if absent.
func findOptional(override, defaultName string) (string, error) {
	if strings.TrimSpace(override) != "" {
		return findRequired(override)
	}
	path, err := exec.LookPath(defaultName)
	if err != nil {
		return "", nil
	}
	return path, nil
}

// firstNonEmpty returns the first non-empty string from a list.
func firstNonEmpty(v, fallback string) string {
	if strings.TrimSpace(v) != "" {
		return v
	}
	return fallback
}

// formatCommand formats a command and its arguments as a single string.
func formatCommand(bin string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, shellQuote(bin))
	for _, arg := range args {
		parts = append(parts, shellQuote(arg))
	}
	return strings.Join(parts, " ")
}

// shellQuote quotes a string if it contains special characters.
func shellQuote(v string) string {
	if v == "" {
		return "''"
	}
	if !strings.ContainsAny(v, " \t\n\"'\\") {
		return v
	}
	return "'" + strings.ReplaceAll(v, "'", "'\"'\"'") + "'"
}
