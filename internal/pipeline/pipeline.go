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

	"github.com/kyleseneker/tinybpf/diag"
	"github.com/kyleseneker/tinybpf/elfcheck"
	"github.com/kyleseneker/tinybpf/internal/cache"
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
	CustomPasses []string
	DumpIR       bool
	ProgramType  string
	Cache        bool
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
	store     *cache.Store
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
		return nil, noop, diag.Wrap(diag.StageInput, err, "failed to create temporary workspace")
	}

	var store *cache.Store
	if cfg.Cache {
		s, cacheErr := cache.Open()
		if cacheErr != nil && cfg.Verbose {
			fmt.Fprintf(cfg.Stdout, "[cache] warning: %v (continuing without cache)\n", cacheErr)
		}
		if s != nil {
			if n, _ := s.Evict(cache.DefaultMaxAge); n > 0 && cfg.Verbose {
				fmt.Fprintf(cfg.Stdout, "[cache] evicted %d stale entries\n", n)
			}
		}
		store = s
	}

	rc := &runContext{
		ctx:     ctx,
		cfg:     cfg,
		tools:   tools,
		workDir: workDir,
		store:   store,
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

	if rc.store != nil {
		inputHash, hashErr := cache.HashFiles(inputs)
		if hashErr == nil {
			key := cache.Key("link", inputHash, rc.tools.LLVMLink, rc.tools.VersionHash)
			if cached, hit := rc.store.Lookup(key); hit {
				rc.logCache("link", key, true)
				return copyFile(cached, rc.artifacts.LinkedBC)
			}
			rc.logCache("link", key, false)
			defer rc.storeArtifact(key, rc.artifacts.LinkedBC)
		}
	}

	linkArgs := append(append([]string{}, inputs...), "-S", "-o", rc.artifacts.LinkedBC)
	return runStage(rc.ctx, rc.cfg, diag.StageLink, rc.tools.LLVMLink, linkArgs,
		"validate your IR files and ensure they are LLVM .ll/.bc modules")
}

// transformAndOptimize runs the IR transform pass, strips host paths, and
// invokes the opt stage.
func (rc *runContext) transformAndOptimize() error {
	if err := rc.runTransformStage(); err != nil {
		return err
	}
	return rc.runOptStage()
}

// runTransformStage applies the IR transform pass with optional caching.
func (rc *runContext) runTransformStage() error {
	dumpDir, err := setupDumpIR(rc.cfg, rc.workDir)
	if err != nil {
		return err
	}
	rc.artifacts.DumpIRDir = dumpDir

	if rc.store != nil {
		inputHash, hashErr := cache.HashFile(rc.artifacts.LinkedBC)
		if hashErr == nil {
			key := cache.Key("transform", inputHash,
				strings.Join(rc.cfg.Programs, ","),
				cache.SortedSections(rc.cfg.Sections))
			if cached, hit := rc.store.Lookup(key); hit {
				rc.logCache("transform", key, true)
				return copyFile(cached, rc.artifacts.TransformedLL)
			}
			rc.logCache("transform", key, false)
			defer rc.storeArtifact(key, rc.artifacts.TransformedLL)
		}
	}

	transformOpts := transform.Options{
		Programs: rc.cfg.Programs,
		Sections: rc.cfg.Sections,
		Verbose:  rc.cfg.Verbose,
		Stdout:   rc.cfg.Stdout,
		DumpDir:  dumpDir,
	}
	if err := transform.Run(rc.ctx, rc.artifacts.LinkedBC, rc.artifacts.TransformedLL, transformOpts); err != nil {
		if diag.IsStage(err, diag.StageTransform) {
			return err
		}
		return diag.Wrap(diag.StageTransform, err,
			"check that the input IR was produced by TinyGo with --gc=none --scheduler=none")
	}

	if err := stripHostPaths(rc.artifacts.TransformedLL, rc.workDir); err != nil {
		return diag.Wrap(diag.StageOpt, err, "failed to sanitize paths in intermediate IR")
	}
	return nil
}

// finalizeAndValidate runs code generation, copies the output, optionally
// injects BTF, and validates the final ELF.
func (rc *runContext) finalizeAndValidate() error {
	if err := rc.runCodegenAndFinalize(); err != nil {
		return err
	}
	return elfcheck.Validate(rc.cfg.Output)
}

// runOptStage runs the opt pass with optional custom passes.
func (rc *runContext) runOptStage() error {
	optArgs := llvm.BuildOptArgs(rc.artifacts.TransformedLL, rc.artifacts.OptimizedLL, rc.cfg.PassPipeline, rc.cfg.OptProfile)
	if len(rc.cfg.CustomPasses) > 0 {
		validated, vErr := llvm.AppendCustomPasses(optArgs, rc.cfg.CustomPasses)
		if vErr != nil {
			return diag.Wrap(diag.StageOpt, vErr, "custom pass validation failed; check tinybpf.json custom_passes")
		}
		optArgs = validated
	}

	if rc.store != nil {
		inputHash, hashErr := cache.HashFile(rc.artifacts.TransformedLL)
		if hashErr == nil {
			key := cache.Key("opt", inputHash,
				rc.tools.Opt, rc.tools.VersionHash,
				rc.cfg.PassPipeline,
				rc.cfg.OptProfile,
				strings.Join(rc.cfg.CustomPasses, ","))
			if cached, hit := rc.store.Lookup(key); hit {
				rc.logCache("opt", key, true)
				return copyFile(cached, rc.artifacts.OptimizedLL)
			}
			rc.logCache("opt", key, false)
			defer rc.storeArtifact(key, rc.artifacts.OptimizedLL)
		}
	}

	return runStage(rc.ctx, rc.cfg, diag.StageOpt, rc.tools.Opt, optArgs,
		"try a less aggressive --pass-pipeline or inspect linked IR")
}

// runCodegenAndFinalize runs llc code generation, copies the output, and
// optionally injects BTF.
func (rc *runContext) runCodegenAndFinalize() error {
	if rc.store != nil {
		inputHash, hashErr := cache.HashFile(rc.artifacts.OptimizedLL)
		if hashErr == nil {
			key := cache.Key("codegen", inputHash, rc.tools.LLC, rc.tools.VersionHash, rc.cfg.CPU)
			if cached, hit := rc.store.Lookup(key); hit {
				rc.logCache("codegen", key, true)
				if err := copyFile(cached, rc.artifacts.CodegenObj); err != nil {
					return err
				}
				return rc.finalizeOutput()
			}
			rc.logCache("codegen", key, false)
			defer rc.storeArtifact(key, rc.artifacts.CodegenObj)
		}
	}

	llcArgs := buildLLCArgs(rc.cfg.CPU, rc.artifacts.OptimizedLL, rc.artifacts.CodegenObj)
	if err := runStage(rc.ctx, rc.cfg, diag.StageCodegen, rc.tools.LLC, llcArgs,
		"ensure llc supports BPF target and input IR is valid"); err != nil {
		return err
	}
	return rc.finalizeOutput()
}

// finalizeOutput copies the codegen object to the output path and optionally injects BTF.
func (rc *runContext) finalizeOutput() error {
	if err := os.MkdirAll(filepath.Dir(rc.cfg.Output), 0o755); err != nil {
		return diag.Wrap(diag.StageFinalize, err, "failed to create output directory")
	}
	if err := copyFile(rc.artifacts.CodegenObj, rc.cfg.Output); err != nil {
		return diag.Wrap(diag.StageFinalize, err, "failed to produce final output object")
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
		return "", diag.Wrap(diag.StageTransform, err, "failed to create dump-ir directory")
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
		return diag.Wrap(diag.StageInput, fmt.Errorf("no inputs provided"),
			"provide at least one --input file")
	}
	if strings.TrimSpace(cfg.Output) == "" {
		return diag.Wrap(diag.StageInput, fmt.Errorf("no output path provided"),
			"provide --output path")
	}

	for _, input := range cfg.Inputs {
		if err := ensureInputSupported(input); err != nil {
			return err
		}
	}

	if cfg.ProgramType == "" {
		inferred, err := InferProgramType(cfg.Sections)
		if err != nil {
			return diag.Wrap(diag.StageInput, err, "sections map to conflicting program types; use --program-type to override")
		}
		cfg.ProgramType = inferred
	}

	if err := ValidateProgramType(cfg.ProgramType, cfg.Sections); err != nil {
		return diag.Wrap(diag.StageInput, err, "check --program-type and --section flags are consistent")
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
}

// ensureInputSupported validates the file extension is one we can process.
func ensureInputSupported(path string) error {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".ll", ".bc", ".o", ".a":
		return nil
	default:
		return diag.Wrap(diag.StageInput, fmt.Errorf("unsupported input format %q", path),
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
		return diag.WrapCmd(stage, err, res.Command, res.Stderr, hint)
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

// logCache logs a cache hit or miss when verbose mode is enabled.
func (rc *runContext) logCache(stage, key string, hit bool) {
	if !rc.cfg.Verbose {
		return
	}
	status := "miss"
	if hit {
		status = "hit"
	}
	fmt.Fprintf(rc.cfg.Stdout, "[cache] %s stage=%s key=%s\n", status, stage, key[:12])
}

// storeArtifact stores an artifact in the cache, silently ignoring errors.
func (rc *runContext) storeArtifact(key, path string) {
	if rc.store == nil {
		return
	}
	if _, err := os.Stat(path); err != nil {
		return
	}
	_ = rc.store.Put(key, path)
}

// copyFile streams src to dst, creating or overwriting dst.
func copyFile(src, dst string) (retErr error) {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if cErr := out.Close(); retErr == nil {
			retErr = cErr
		}
	}()

	_, retErr = io.Copy(out, in)
	return retErr
}

// injectBTF runs pahole -J on the output object to embed BTF type information.
func injectBTF(ctx context.Context, cfg Config, tools llvm.Tools) error {
	if tools.Pahole == "" {
		return diag.WrapCmd(diag.StageBTF, fmt.Errorf("pahole not found"),
			"pahole", "", "install pahole or pass --pahole when using --btf")
	}

	res, err := llvm.Run(ctx, cfg.Timeout, tools.Pahole, "-J", cfg.Output)
	if cfg.Verbose && strings.TrimSpace(res.Stderr) != "" {
		fmt.Fprintf(cfg.Stderr, "%s\n", res.Stderr)
	}
	if err != nil {
		return diag.WrapCmd(diag.StageBTF, err, res.Command, res.Stderr,
			"failed to inject BTF data into output object")
	}
	return nil
}
