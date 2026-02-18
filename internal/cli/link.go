package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/kyleseneker/tinybpf/internal/llvm"
	"github.com/kyleseneker/tinybpf/internal/pipeline"
)

// runLink links the TinyGo LLVM IR into a BPF ELF object.
func runLink(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	var inputs multiStringFlag
	var programs multiStringFlag
	var sectionFlags multiStringFlag
	var profilePath string
	cfg := pipeline.Config{
		Stdout: stdout,
		Stderr: stderr,
	}

	fs := newFlagSet(stderr, "tinybpf link --input <file> [flags]", "Link TinyGo LLVM IR into a BPF ELF object.")
	fs.Var(&inputs, "input", "Input LLVM file (.ll, .bc, .o, .a). Repeat for multiple modules.")
	registerPipelineFlags(fs, &cfg, &programs, &sectionFlags)
	fs.IntVar(&cfg.Jobs, "jobs", 1, "Number of parallel input normalization workers.")
	fs.IntVar(&cfg.Jobs, "j", 1, "Number of parallel input normalization workers (shorthand).")
	fs.StringVar(&profilePath, "profile", "", "")
	fs.StringVar(&cfg.ConfigPath, "config", "", "Path to linker-config.json for custom passes and settings.")

	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	if len(inputs) == 0 {
		return usageErrorf(fs, stderr, "at least one --input is required")
	}
	cfg.Inputs = inputs
	cfg.Programs = programs
	cfg.Sections = parseSectionFlags(sectionFlags)

	if cfg.ConfigPath != "" {
		linkerCfg, err := llvm.LoadConfig(cfg.ConfigPath)
		if err != nil {
			return cliErrorf(stderr, "%v", err)
		}
		cfg.CustomPasses = linkerCfg.CustomPasses
	}

	if profilePath != "" {
		cleanup, err := startProfiling(profilePath, stderr)
		if err != nil {
			fmt.Fprintf(stderr, "warning: profiling failed to start: %v\n", err)
		} else {
			defer cleanup()
		}
	}

	return runPipelineAndReport(ctx, cfg, stdout, stderr)
}

var writeHeapProfile = pprof.WriteHeapProfile

// startProfiling starts CPU profiling and returns a cleanup function that
// stops the CPU profile and writes a heap memory profile on completion.
func startProfiling(basePath string, w io.Writer) (func(), error) {
	cpuPath := basePath + ".cpu.prof"
	f, err := os.Create(cpuPath)
	if err != nil {
		return nil, fmt.Errorf("creating CPU profile: %w", err)
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("starting CPU profile: %w", err)
	}

	cleanup := func() {
		pprof.StopCPUProfile()
		_ = f.Close()
		fmt.Fprintf(w, "cpu profile: %s\n", cpuPath)

		memPath := basePath + ".mem.prof"
		mf, err := os.Create(memPath)
		if err != nil {
			fmt.Fprintf(w, "warning: memory profile: %v\n", err)
			return
		}
		defer func() { _ = mf.Close() }()
		runtime.GC()
		if err := writeHeapProfile(mf); err != nil {
			fmt.Fprintf(w, "warning: memory profile: %v\n", err)
			return
		}
		fmt.Fprintf(w, "memory profile: %s\n", memPath)
	}
	return cleanup, nil
}
