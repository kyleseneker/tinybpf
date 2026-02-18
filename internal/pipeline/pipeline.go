// Package pipeline orchestrates the LLVM tool stages that transform
// input IR/bitcode into a valid eBPF ELF object.
package pipeline

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kyleseneker/tinybpf/internal/diag"
	"github.com/kyleseneker/tinybpf/internal/elfcheck"
	"github.com/kyleseneker/tinybpf/internal/llvm"
	"github.com/kyleseneker/tinybpf/internal/transform"
)

// Config holds all user-provided settings for a linker pipeline run.
type Config struct {
	Inputs       []string
	Output       string
	CPU          string
	KeepTemp     bool
	Verbose      bool
	PassPipeline string
	OptProfile   string
	Timeout      time.Duration
	TempDir      string
	EnableBTF    bool
	Programs     []string
	Sections     map[string]string
	Tools        llvm.ToolOverrides
	Stdout       io.Writer
	Stderr       io.Writer
	Jobs         int
	ConfigPath   string
	CustomPasses []string
}

// Artifacts records the paths of intermediate and final build products.
type Artifacts struct {
	TempDir       string
	LinkedBC      string
	TransformedLL string
	OptimizedLL   string
	CodegenObj    string
	OutputObj     string
}

// Run executes the full linking pipeline: normalize → llvm-link →
// IR transform → opt → llc → finalize → optional BTF → ELF validation.
func Run(ctx context.Context, cfg Config) (*Artifacts, error) {
	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}

	tools, err := llvm.DiscoverTools(cfg.Tools)
	if err != nil {
		return nil, err
	}

	workDir, cleanup, err := makeWorkDir(cfg.TempDir, cfg.KeepTemp)
	if err != nil {
		return nil, diag.New(diag.StageInput, err, "", "", "failed to create temporary workspace")
	}
	defer cleanup()

	artifacts := &Artifacts{
		TempDir:       workDir,
		LinkedBC:      filepath.Join(workDir, "01-linked.ll"),
		TransformedLL: filepath.Join(workDir, "02-transformed.ll"),
		OptimizedLL:   filepath.Join(workDir, "03-optimized.ll"),
		CodegenObj:    filepath.Join(workDir, "04-codegen.o"),
		OutputObj:     cfg.Output,
	}

	inputs, err := normalizeInputs(ctx, cfg, tools, workDir)
	if err != nil {
		return nil, err
	}

	linkArgs := append(append([]string{}, inputs...), "-S", "-o", artifacts.LinkedBC)
	if err := runStage(ctx, cfg, diag.StageLink, tools.LLVMLink, linkArgs,
		"validate your IR files and ensure they are LLVM .ll/.bc modules"); err != nil {
		return nil, err
	}

	transformOpts := transform.Options{
		Programs: cfg.Programs,
		Sections: cfg.Sections,
		Verbose:  cfg.Verbose,
		Stdout:   cfg.Stdout,
	}
	if err := transform.Run(artifacts.LinkedBC, artifacts.TransformedLL, transformOpts); err != nil {
		return nil, diag.New(diag.StageTransform, err, "", "",
			"check that the input IR was produced by TinyGo with --gc=none --scheduler=none")
	}

	if err := stripHostPaths(artifacts.TransformedLL, workDir); err != nil {
		return nil, diag.New(diag.StageOpt, err, "", "",
			"failed to sanitize paths in intermediate IR")
	}

	optArgs := llvm.BuildOptArgs(artifacts.TransformedLL, artifacts.OptimizedLL, cfg.PassPipeline, cfg.OptProfile)
	if len(cfg.CustomPasses) > 0 {
		validated, vErr := llvm.AppendCustomPasses(optArgs, cfg.CustomPasses)
		if vErr != nil {
			return nil, diag.New(diag.StageOpt, vErr, "", "",
				"custom pass validation failed; check linker-config.json")
		}
		optArgs = validated
	}
	if err := runStage(ctx, cfg, diag.StageOpt, tools.Opt, optArgs,
		"try a less aggressive --pass-pipeline or inspect linked IR"); err != nil {
		return nil, err
	}

	llcArgs := buildLLCArgs(cfg.CPU, artifacts.OptimizedLL, artifacts.CodegenObj)
	if err := runStage(ctx, cfg, diag.StageCodegen, tools.LLC, llcArgs,
		"ensure llc supports BPF target and input IR is valid"); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Output), 0o755); err != nil {
		return nil, diag.New(diag.StageFinalize, err, "", "", "failed to create output directory")
	}
	if err := copyFile(artifacts.CodegenObj, cfg.Output); err != nil {
		return nil, diag.New(diag.StageFinalize, err, "", "",
			"failed to produce final output object")
	}

	if cfg.EnableBTF {
		if err := injectBTF(ctx, cfg, tools); err != nil {
			return nil, err
		}
	}

	if err := elfcheck.Validate(cfg.Output); err != nil {
		return nil, err
	}

	return artifacts, nil
}

// validateConfig applies defaults and checks required fields.
func validateConfig(cfg *Config) error {
	if len(cfg.Inputs) == 0 {
		return diag.New(diag.StageInput, fmt.Errorf("no inputs provided"), "", "",
			"provide at least one --input file")
	}
	if strings.TrimSpace(cfg.Output) == "" {
		return diag.New(diag.StageInput, fmt.Errorf("no output path provided"), "", "",
			"provide --output path")
	}

	for _, input := range cfg.Inputs {
		if err := ensureInputSupported(input); err != nil {
			return err
		}
	}

	if cfg.CPU == "" {
		cfg.CPU = "v3"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.Stdout == nil {
		cfg.Stdout = io.Discard
	}
	if cfg.Stderr == nil {
		cfg.Stderr = io.Discard
	}
	return nil
}

// ensureInputSupported validates the file extension is one we can process.
func ensureInputSupported(path string) error {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".ll", ".bc", ".o", ".a":
		return nil
	default:
		return diag.New(diag.StageInput,
			fmt.Errorf("unsupported input format %q", path), "", "",
			"supported inputs are .ll, .bc, .o, and .a")
	}
}

// runStage executes a single LLVM tool invocation with logging and error wrapping.
func runStage(ctx context.Context, cfg Config, stage diag.Stage, bin string, args []string, hint string) error {
	res, err := llvm.Run(ctx, cfg.Timeout, bin, args...)
	if cfg.Verbose {
		fmt.Fprintf(cfg.Stdout, "[%s] %s\n", stage, res.Command)
		if s := strings.TrimSpace(res.Stdout); s != "" {
			fmt.Fprintf(cfg.Stdout, "%s\n", s)
		}
		if s := strings.TrimSpace(res.Stderr); s != "" {
			fmt.Fprintf(cfg.Stderr, "%s\n", s)
		}
	}
	if err != nil {
		return diag.New(stage, err, res.Command, res.Stderr, hint)
	}
	return nil
}

// makeWorkDir creates or reuses a directory for intermediate artifacts.
func makeWorkDir(baseDir string, keepTemp bool) (string, func(), error) {
	noop := func() {}
	if strings.TrimSpace(baseDir) != "" {
		if err := os.MkdirAll(baseDir, 0o700); err != nil {
			return "", noop, err
		}
		if err := os.Chmod(baseDir, 0o700); err != nil { //nolint:gosec
			return "", noop, err
		}
		return baseDir, noop, nil
	}
	dir, err := os.MkdirTemp("", "tinybpf-")
	if err != nil {
		return "", noop, err
	}
	if keepTemp {
		return dir, noop, nil
	}
	return dir, func() { _ = os.RemoveAll(dir) }, nil
}

// stripHostPaths rewrites absolute temp-directory references in an LLVM IR
// text file to relative paths.
func stripHostPaths(llPath, tempDir string) error {
	data, err := os.ReadFile(llPath)
	if err != nil {
		return err
	}
	cleaned := bytes.ReplaceAll(data, []byte(tempDir), []byte("."))
	return os.WriteFile(llPath, cleaned, 0o600)
}

// buildLLCArgs constructs the argument list for llc BPF code generation.
func buildLLCArgs(cpu, inputPath, outputPath string) []string {
	return []string{
		"-march=bpf",
		"-mcpu=" + cpu,
		"-filetype=obj",
		inputPath,
		"-o",
		outputPath,
	}
}

// copyFile copies src to dst, creating or overwriting dst.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o600)
}
