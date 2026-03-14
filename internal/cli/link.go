package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/kyleseneker/tinybpf/pipeline"
)

type heapProfileWriter func(w io.Writer) error

// runLink links pre-compiled LLVM IR into a BPF ELF object.
func runLink(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runLinkWith(ctx, args, stdout, stderr, pprof.WriteHeapProfile)
}

// runLinkWith is the testable core of runLink with an injected heap profile writer.
func runLinkWith(ctx context.Context, args []string, stdout, stderr io.Writer, writeHeap heapProfileWriter) int {
	var inputs multiStringFlag
	var programs multiStringFlag
	var sectionFlags multiStringFlag
	var profilePath string
	var configPath string
	cfg := pipeline.Config{
		Stdout: stdout,
		Stderr: stderr,
	}

	fs := newFlagSet(stderr, "tinybpf link --input <file> [flags]", "Link TinyGo LLVM IR into a BPF ELF object.")
	fs.Var(&inputs, "input", "Input LLVM file (.ll, .bc, .o, .a). Repeat for multiple modules.")
	fs.Var(&inputs, "i", "Input LLVM file (shorthand).")
	registerPipelineFlags(fs, &cfg, &programs, &sectionFlags, &configPath)
	fs.IntVar(&cfg.Jobs, "jobs", 1, "Number of parallel input normalization workers.")
	fs.IntVar(&cfg.Jobs, "j", 1, "Number of parallel input normalization workers (shorthand).")
	fs.StringVar(&profilePath, "profile", "", "")

	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	if _, cfgErr := loadProjectConfig(fs, configPath, &cfg, stderr); cfgErr != nil {
		return cliErrorf(stderr, "%v", cfgErr)
	}

	if len(inputs) == 0 {
		return usageErrorf(fs, stderr, "at least one --input is required")
	}
	cfg.Inputs = inputs
	if len(programs) > 0 {
		cfg.Programs = programs
	}

	sections, secErr := pipeline.ParseSectionFlags(sectionFlags)
	if secErr != nil {
		return cliErrorf(stderr, "%v", secErr)
	}
	if len(sections) > 0 {
		cfg.Sections = sections
	}

	if profilePath != "" {
		cleanup, err := startProfiling(profilePath, stderr, writeHeap)
		if err != nil {
			fmt.Fprintf(stderr, "warning: profiling failed to start: %v\n", err)
		} else {
			defer cleanup()
		}
	}

	return runPipelineAndReport(ctx, cfg, stdout, stderr)
}

// startProfiling starts CPU profiling and returns a cleanup function that
// stops the CPU profile and writes a heap memory profile on completion.
func startProfiling(basePath string, w io.Writer, writeHeap heapProfileWriter) (func(), error) {
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
		if err := writeHeap(mf); err != nil {
			fmt.Fprintf(w, "warning: memory profile: %v\n", err)
			return
		}
		fmt.Fprintf(w, "memory profile: %s\n", memPath)
	}
	return cleanup, nil
}
