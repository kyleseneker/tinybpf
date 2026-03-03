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
	DumpIR       bool
	ProgramType  string
	ValidateELF  func(path string) error
}

// Artifacts records the paths of intermediate and final build products.
type Artifacts struct {
	TempDir       string
	LinkedBC      string
	TransformedLL string
	OptimizedLL   string
	CodegenObj    string
	OutputObj     string
	DumpIRDir     string
}

// runContext holds the resolved state for a single pipeline execution.
type runContext struct {
	ctx       context.Context
	cfg       Config
	tools     llvm.Tools
	workDir   string
	artifacts *Artifacts
}

// Run executes the full linking pipeline: normalize -> llvm-link ->
// IR transform -> opt -> llc -> finalize -> optional BTF -> ELF validation.
func Run(ctx context.Context, cfg Config) (*Artifacts, error) {
	rc, cleanup, err := prepareRunContext(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	if err := rc.linkInputs(); err != nil {
		return nil, err
	}
	if err := rc.transformAndOptimize(); err != nil {
		return nil, err
	}
	if err := rc.finalizeAndValidate(); err != nil {
		return nil, err
	}
	return rc.artifacts, nil
}

// prepareRunContext validates the config, discovers tools, creates the work
// directory, and initializes artifact paths.
func prepareRunContext(ctx context.Context, cfg Config) (*runContext, func(), error) {
	noop := func() {}
	if err := validateConfig(&cfg); err != nil {
		return nil, noop, err
	}

	tools, err := llvm.DiscoverTools(cfg.Tools)
	if err != nil {
		return nil, noop, err
	}

	workDir, cleanup, err := makeWorkDir(cfg.TempDir, cfg.KeepTemp)
	if err != nil {
		return nil, noop, &diag.Error{Stage: diag.StageInput, Err: err, Hint: "failed to create temporary workspace"}
	}

	rc := &runContext{
		ctx:   ctx,
		cfg:   cfg,
		tools: tools,
		workDir: workDir,
		artifacts: &Artifacts{
			TempDir:       workDir,
			LinkedBC:      filepath.Join(workDir, "01-linked.ll"),
			TransformedLL: filepath.Join(workDir, "02-transformed.ll"),
			OptimizedLL:   filepath.Join(workDir, "03-optimized.ll"),
			CodegenObj:    filepath.Join(workDir, "04-codegen.o"),
			OutputObj:     cfg.Output,
		},
	}
	return rc, cleanup, nil
}

// linkInputs normalizes input files and links them into a single IR module.
func (rc *runContext) linkInputs() error {
	inputs, err := normalizeInputs(rc.ctx, rc.cfg, rc.tools, rc.workDir)
	if err != nil {
		return err
	}

	linkArgs := append(append([]string{}, inputs...), "-S", "-o", rc.artifacts.LinkedBC)
	return runStage(rc.ctx, rc.cfg, diag.StageLink, rc.tools.LLVMLink, linkArgs,
		"validate your IR files and ensure they are LLVM .ll/.bc modules")
}

// transformAndOptimize runs the IR transform pass, strips host paths, and
// invokes the opt stage.
func (rc *runContext) transformAndOptimize() error {
	dumpDir, err := setupDumpIR(rc.cfg, rc.workDir)
	if err != nil {
		return err
	}
	rc.artifacts.DumpIRDir = dumpDir

	transformOpts := transform.Options{
		Programs: rc.cfg.Programs,
		Sections: rc.cfg.Sections,
		Verbose:  rc.cfg.Verbose,
		Stdout:   rc.cfg.Stdout,
		DumpDir:  dumpDir,
	}
	if err := transform.Run(rc.ctx, rc.artifacts.LinkedBC, rc.artifacts.TransformedLL, transformOpts); err != nil {
		return &diag.Error{Stage: diag.StageTransform, Err: err,
			Hint: "check that the input IR was produced by TinyGo with --gc=none --scheduler=none"}
	}

	if err := stripHostPaths(rc.artifacts.TransformedLL, rc.workDir); err != nil {
		return &diag.Error{Stage: diag.StageOpt, Err: err,
			Hint: "failed to sanitize paths in intermediate IR"}
	}

	return rc.runOptStage()
}

// finalizeAndValidate runs code generation, copies the output, optionally
// injects BTF, and validates the final ELF.
func (rc *runContext) finalizeAndValidate() error {
	if err := rc.runCodegenAndFinalize(); err != nil {
		return err
	}
	return rc.cfg.ValidateELF(rc.cfg.Output)
}

// runOptStage runs the opt pass with optional custom passes.
func (rc *runContext) runOptStage() error {
	optArgs := llvm.BuildOptArgs(rc.artifacts.TransformedLL, rc.artifacts.OptimizedLL, rc.cfg.PassPipeline, rc.cfg.OptProfile)
	if len(rc.cfg.CustomPasses) > 0 {
		validated, vErr := llvm.AppendCustomPasses(optArgs, rc.cfg.CustomPasses)
		if vErr != nil {
			return &diag.Error{Stage: diag.StageOpt, Err: vErr,
				Hint: "custom pass validation failed; check linker-config.json"}
		}
		optArgs = validated
	}
	return runStage(rc.ctx, rc.cfg, diag.StageOpt, rc.tools.Opt, optArgs,
		"try a less aggressive --pass-pipeline or inspect linked IR")
}

// runCodegenAndFinalize runs llc code generation, copies the output, and
// optionally injects BTF.
func (rc *runContext) runCodegenAndFinalize() error {
	llcArgs := buildLLCArgs(rc.cfg.CPU, rc.artifacts.OptimizedLL, rc.artifacts.CodegenObj)
	if err := runStage(rc.ctx, rc.cfg, diag.StageCodegen, rc.tools.LLC, llcArgs,
		"ensure llc supports BPF target and input IR is valid"); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(rc.cfg.Output), 0o755); err != nil {
		return &diag.Error{Stage: diag.StageFinalize, Err: err, Hint: "failed to create output directory"}
	}
	if err := copyFile(rc.artifacts.CodegenObj, rc.cfg.Output); err != nil {
		return &diag.Error{Stage: diag.StageFinalize, Err: err,
			Hint: "failed to produce final output object"}
	}
	if rc.cfg.EnableBTF {
		if err := injectBTF(rc.ctx, rc.cfg, rc.tools); err != nil {
			return err
		}
	}
	return nil
}

// setupDumpIR creates the dump-ir directory when --dump-ir is enabled
// and returns the path (empty string when disabled).
func setupDumpIR(cfg Config, workDir string) (string, error) {
	if !cfg.DumpIR {
		return "", nil
	}
	dir := filepath.Join(workDir, "dump-ir")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", &diag.Error{Stage: diag.StageTransform, Err: err,
			Hint: "failed to create dump-ir directory"}
	}
	if cfg.Verbose {
		fmt.Fprintf(cfg.Stdout, "[dump-ir] writing stage snapshots to %s\n", dir)
	}
	return dir, nil
}

// validateConfig checks required fields and applies defaults.
func validateConfig(cfg *Config) error {
	if err := validateRequiredFields(cfg); err != nil {
		return err
	}
	applyConfigDefaults(cfg)
	return nil
}

// validateRequiredFields rejects configs missing mandatory inputs/output or
// containing unsupported file types and inconsistent program-type flags.
func validateRequiredFields(cfg *Config) error {
	if len(cfg.Inputs) == 0 {
		return &diag.Error{Stage: diag.StageInput, Err: fmt.Errorf("no inputs provided"),
			Hint: "provide at least one --input file"}
	}
	if strings.TrimSpace(cfg.Output) == "" {
		return &diag.Error{Stage: diag.StageInput, Err: fmt.Errorf("no output path provided"),
			Hint: "provide --output path"}
	}

	for _, input := range cfg.Inputs {
		if err := ensureInputSupported(input); err != nil {
			return err
		}
	}

	if err := ValidateProgramType(cfg.ProgramType, cfg.Sections); err != nil {
		return &diag.Error{Stage: diag.StageInput, Err: err,
			Hint: "check --program-type and --section flags are consistent"}
	}
	return nil
}

// applyConfigDefaults fills in zero-valued optional fields with sensible
// production defaults.
func applyConfigDefaults(cfg *Config) {
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
	if cfg.ValidateELF == nil {
		cfg.ValidateELF = elfcheck.Validate
	}
}

// ensureInputSupported validates the file extension is one we can process.
func ensureInputSupported(path string) error {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".ll", ".bc", ".o", ".a":
		return nil
	default:
		return &diag.Error{Stage: diag.StageInput,
			Err:  fmt.Errorf("unsupported input format %q", path),
			Hint: "supported inputs are .ll, .bc, .o, and .a"}
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
		return &diag.Error{Stage: stage, Err: err, Command: res.Command, Stderr: res.Stderr, Hint: hint}
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

// ParseSectionFlags parses "name=section" flag strings into a map.
func ParseSectionFlags(flags []string) (map[string]string, error) {
	if len(flags) == 0 {
		return nil, nil
	}
	m := make(map[string]string, len(flags))
	for _, f := range flags {
		parts := strings.SplitN(f, "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return nil, fmt.Errorf("invalid --section %q: expected format name=section", f)
		}
		m[parts[0]] = parts[1]
	}
	return m, nil
}

// copyFile copies src to dst, creating or overwriting dst.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o600)
}
