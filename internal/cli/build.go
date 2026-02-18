package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kyleseneker/tinybpf/internal/diag"
	"github.com/kyleseneker/tinybpf/internal/pipeline"
)

// runBuild compiles Go source with TinyGo and links the resulting IR into a BPF ELF object.
func runBuild(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	var programs multiStringFlag
	var sectionFlags multiStringFlag
	var tinygoPath string
	cfg := pipeline.Config{
		Stdout: stdout,
		Stderr: stderr,
	}

	fs := newFlagSet(stderr, "tinybpf build [flags] <package>", "Compile Go source to a BPF ELF object in one step.")
	registerPipelineFlags(fs, &cfg, &programs, &sectionFlags)
	fs.StringVar(&tinygoPath, "tinygo", "", "Path to tinygo binary (default: discovered from PATH).")

	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	if fs.NArg() != 1 {
		return usageErrorf(fs, stderr, "exactly one package argument is required")
	}
	pkg := fs.Arg(0)

	tinygo, err := findTinyGo(tinygoPath)
	if err != nil {
		return cliErrorf(stderr, "%v", err)
	}

	workDir, cleanup, err := buildWorkDir(cfg.TempDir)
	if err != nil {
		return cliErrorf(stderr, "creating temp directory: %v", err)
	}
	if !cfg.KeepTemp {
		defer cleanup()
	}

	irFile := filepath.Join(workDir, "program.ll")
	tinygoArgs := []string{
		"build",
		"-gc=none", "-scheduler=none", "-panic=trap", "-opt=1",
		"-o", irFile,
		pkg,
	}

	if cfg.Verbose {
		fmt.Fprintf(stdout, "[tinygo-compile] %s %s\n", tinygo, strings.Join(tinygoArgs, " "))
	}
	tgRes, tgErr := runTinyGo(ctx, cfg.Timeout, tinygo, tinygoArgs...)
	if cfg.Verbose && strings.TrimSpace(tgRes.stderr) != "" {
		fmt.Fprintln(stderr, tgRes.stderr)
	}
	if tgErr != nil {
		cmd := tinygo + " " + strings.Join(tinygoArgs, " ")
		diagErr := diag.New(diag.StageCompile, tgErr, cmd, tgRes.stderr,
			"ensure TinyGo is installed and the package compiles with: tinygo build -gc=none -scheduler=none -panic=trap -opt=1 "+pkg)
		fmt.Fprintln(stderr, diagErr.Error())
		return 1
	}

	cfg.Inputs = []string{irFile}
	cfg.Programs = programs
	cfg.Sections = parseSectionFlags(sectionFlags)

	return runPipelineAndReport(ctx, cfg, stdout, stderr)
}

// buildWorkDir returns the working directory for intermediate build artifacts
// and a cleanup function. If explicit is set, no cleanup is performed.
func buildWorkDir(explicit string) (dir string, cleanup func(), err error) {
	if explicit != "" {
		return explicit, func() {}, nil
	}
	dir, err = os.MkdirTemp("", "tinybpf-build-")
	if err != nil {
		return "", nil, err
	}
	return dir, func() { _ = os.RemoveAll(dir) }, nil
}

type tinyGoResult struct{ stderr string }

// runTinyGo executes TinyGo with the full process environment so it can
// resolve GOPATH, GOMODCACHE, and other Go toolchain variables.
var runTinyGo = func(ctx context.Context, timeout time.Duration, bin string, args ...string) (tinyGoResult, error) {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, bin, args...)
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	err := cmd.Run()
	return tinyGoResult{stderr: stderrBuf.String()}, err
}

// findTinyGo resolves the tinygo binary from an explicit path or PATH.
func findTinyGo(override string) (string, error) {
	if override != "" {
		if _, err := os.Stat(override); err != nil {
			return "", fmt.Errorf("tinygo not found at %q: %w", override, err)
		}
		return override, nil
	}
	path, err := exec.LookPath("tinygo")
	if err != nil {
		return "", fmt.Errorf("tinygo not found on PATH (install from tinygo.org or pass --tinygo)")
	}
	return path, nil
}
