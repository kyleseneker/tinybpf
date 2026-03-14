package tinybpf

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

	"github.com/kyleseneker/tinybpf/diag"
	"github.com/kyleseneker/tinybpf/internal/pipeline"
)

// Build compiles Go source or links pre-compiled LLVM IR into a BPF ELF
// object.
func Build(ctx context.Context, req Request) (*Result, error) {
	if err := validateRequest(&req); err != nil {
		return nil, err
	}
	applyRequestDefaults(&req)

	inputs := req.Inputs
	var cleanTempDir func()

	if req.Package != "" {
		tinygo, err := resolveTinyGo(req.Toolchain.TinyGo)
		if err != nil {
			return nil, err
		}

		buildDir := req.TempDir
		if buildDir == "" {
			var err error
			buildDir, cleanTempDir, err = makeTempBuildDir()
			if err != nil {
				return nil, fmt.Errorf("creating build directory: %w", err)
			}
			defer func() {
				if cleanTempDir != nil {
					cleanTempDir()
				}
			}()
		}

		irFile, err := compileTinyGo(ctx, req, tinygo, req.Package, buildDir)
		if err != nil {
			return nil, err
		}
		inputs = []string{irFile}
	}

	cfg := requestToPipelineConfig(req, inputs)
	artifacts, err := pipeline.Run(ctx, cfg)
	if err != nil {
		return nil, err
	}

	if req.KeepTemp {
		cleanTempDir = nil
	}

	return &Result{
		Output:  req.Output,
		TempDir: artifacts.TempDir,
	}, nil
}

// validateRequest validates the request and returns an error if the request is invalid.
func validateRequest(req *Request) error {
	hasPackage := req.Package != ""
	hasInputs := len(req.Inputs) > 0
	if hasPackage == hasInputs {
		return fmt.Errorf("exactly one of Package or Inputs must be set")
	}
	return nil
}

// applyRequestDefaults applies the default values to the request.
func applyRequestDefaults(req *Request) {
	if req.Output == "" {
		req.Output = "bpf.o"
	}
	if req.CPU == "" {
		req.CPU = "v3"
	}
	if req.Timeout <= 0 {
		req.Timeout = 30 * time.Second
	}
	if req.Stdout == nil {
		req.Stdout = io.Discard
	}
	if req.Stderr == nil {
		req.Stderr = io.Discard
	}
}

// requestToPipelineConfig converts the request to a pipeline configuration.
func requestToPipelineConfig(req Request, inputs []string) pipeline.Config {
	return pipeline.Config{
		Inputs:       inputs,
		Output:       req.Output,
		CPU:          req.CPU,
		KeepTemp:     req.KeepTemp,
		Verbose:      req.Verbose,
		PassPipeline: req.PassPipeline,
		OptProfile:   req.OptProfile,
		Timeout:      req.Timeout,
		TempDir:      req.TempDir,
		EnableBTF:    req.EnableBTF,
		Programs:     req.Programs,
		Sections:     req.Sections,
		Tools: pipeline.ToolOverrides{
			LLVMLink: req.Toolchain.LLVMLink,
			Opt:      req.Toolchain.Opt,
			LLC:      req.Toolchain.LLC,
			LLVMAr:   req.Toolchain.LLVMAr,
			Objcopy:  req.Toolchain.Objcopy,
			Pahole:   req.Toolchain.Pahole,
		},
		Stdout:       req.Stdout,
		Stderr:       req.Stderr,
		Jobs:         req.Jobs,
		CustomPasses: req.CustomPasses,
		DumpIR:       req.DumpIR,
		ProgramType:  req.ProgramType,
		Cache:        req.Cache,
	}
}

// compileTinyGo compiles the TinyGo package and returns the IR file.
func compileTinyGo(ctx context.Context, req Request, tinygo, pkg, workDir string) (string, error) {
	irFile := filepath.Join(workDir, "program.ll")
	args := []string{
		"build",
		"-gc=none", "-scheduler=none", "-panic=trap", "-opt=1",
		"-o", irFile,
		pkg,
	}

	if req.Verbose {
		fmt.Fprintf(req.Stdout, "[tinygo-compile] %s %s\n", tinygo, strings.Join(args, " "))
	}

	cmdCtx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, tinygo, args...)
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	if err := cmd.Run(); err != nil {
		cmdStr := tinygo + " " + strings.Join(args, " ")
		return "", diag.WrapCmd(diag.StageCompile, err, cmdStr, stderrBuf.String(),
			"ensure TinyGo is installed and the package compiles with: tinygo build -gc=none -scheduler=none -panic=trap -opt=1 "+pkg)
	}
	return irFile, nil
}

// resolveTinyGo resolves the TinyGo binary and returns the path.
func resolveTinyGo(override string) (string, error) {
	if override != "" {
		if _, err := os.Stat(override); err != nil {
			return "", fmt.Errorf("tinygo not found at %q: %w", override, err)
		}
		return override, nil
	}
	path, err := exec.LookPath("tinygo")
	if err != nil {
		return "", fmt.Errorf("tinygo not found on PATH (install from tinygo.org or set Toolchain.TinyGo)")
	}
	return path, nil
}

// makeTempBuildDir makes a temporary build directory and returns the path and a cleanup function.
func makeTempBuildDir() (dir string, cleanup func(), err error) {
	dir, err = os.MkdirTemp("", "tinybpf-build-")
	if err != nil {
		return "", nil, err
	}
	return dir, func() { _ = os.RemoveAll(dir) }, nil
}
