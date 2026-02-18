// Package cli implements the tinybpf command-line interface,
// including the default link subcommand and the doctor and version subcommands.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/kyleseneker/tinybpf/internal/doctor"
	"github.com/kyleseneker/tinybpf/internal/llvm"
	"github.com/kyleseneker/tinybpf/internal/pipeline"
)

// Version is set at build time via ldflags:
//
//	go build -ldflags "-X github.com/kyleseneker/tinybpf/internal/cli.Version=v0.1.0"
var Version = "(dev)"

type multiStringFlag []string

func (m *multiStringFlag) String() string {
	return strings.Join(*m, ",")
}

func (m *multiStringFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("value cannot be empty")
	}
	*m = append(*m, value)
	return nil
}

// Run is the top-level entrypoint. It dispatches to the appropriate
// subcommand based on the first argument.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "doctor":
			return runDoctor(ctx, args[1:], stdout, stderr)
		case "version":
			return runVersion(stdout)
		case "--version", "-version":
			return runVersion(stdout)
		}
	}
	return runLink(ctx, args, stdout, stderr)
}

func runVersion(stdout io.Writer) int {
	fmt.Fprintf(stdout, "tinybpf %s\n", Version)
	return 0
}

func runLink(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	var inputs multiStringFlag
	var probes multiStringFlag
	var sectionFlags multiStringFlag
	var profilePath string
	cfg := pipeline.Config{
		Stdout: stdout,
		Stderr: stderr,
	}

	fs := flag.NewFlagSet("tinybpf", flag.ContinueOnError)
	fs.SetOutput(stderr)

	fs.Var(&inputs, "input", "Input LLVM file (.ll, .bc, .o, .a). Repeat for multiple modules.")
	fs.StringVar(&cfg.Output, "output", "bpf.o", "Output eBPF ELF object path.")
	fs.StringVar(&cfg.Output, "o", "bpf.o", "Output eBPF ELF object path (shorthand).")
	fs.StringVar(&cfg.CPU, "cpu", "v3", "BPF CPU version passed to llc as -mcpu.")
	fs.BoolVar(&cfg.KeepTemp, "keep-temp", false, "Keep temporary intermediate files after run.")
	fs.BoolVar(&cfg.Verbose, "verbose", false, "Enable verbose stage logging.")
	fs.BoolVar(&cfg.Verbose, "v", false, "Enable verbose stage logging (shorthand).")
	fs.StringVar(&cfg.PassPipeline, "pass-pipeline", "", "Explicit LLVM opt pass pipeline string.")
	fs.StringVar(&cfg.OptProfile, "opt-profile", "default", "Optimization profile: conservative, default, aggressive, verifier-safe.")
	fs.DurationVar(&cfg.Timeout, "timeout", 30*time.Second, "Per-stage command timeout.")
	fs.StringVar(&cfg.TempDir, "tmpdir", "", "Directory for intermediate artifacts (kept after run).")
	fs.BoolVar(&cfg.EnableBTF, "btf", false, "Enable BTF injection via pahole.")
	fs.Var(&probes, "probe", "Probe function name to keep. Repeat for multiple probes. Auto-detected if omitted.")
	fs.Var(&sectionFlags, "section", "Probe-to-section mapping (e.g., handle_connect=tracepoint/syscalls/sys_enter_connect). Repeat for multiple.")
	registerToolFlags(fs, &cfg.Tools)

	fs.IntVar(&cfg.Jobs, "jobs", 1, "Number of parallel input normalization workers.")
	fs.IntVar(&cfg.Jobs, "j", 1, "Number of parallel input normalization workers (shorthand).")
	fs.StringVar(&profilePath, "profile", "", "") // hidden: pprof output base path
	fs.StringVar(&cfg.ConfigPath, "config", "", "Path to linker-config.json for custom passes and settings.")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if len(inputs) == 0 {
		fmt.Fprintln(stderr, "error: at least one --input is required")
		fs.Usage()
		return 2
	}
	cfg.Inputs = inputs
	cfg.Probes = probes
	cfg.Sections = parseSectionFlags(sectionFlags)

	if cfg.ConfigPath != "" {
		linkerCfg, err := llvm.LoadConfig(cfg.ConfigPath)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
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

	artifacts, err := pipeline.Run(ctx, cfg)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1
	}

	if cfg.Verbose || cfg.KeepTemp || cfg.TempDir != "" {
		fmt.Fprintf(stdout, "intermediates: %s\n", artifacts.TempDir)
	}
	fmt.Fprintf(stdout, "wrote %s\n", cfg.Output)
	return 0
}

// startProfiling begins CPU profiling and returns a cleanup function that
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
		if err := pprof.WriteHeapProfile(mf); err != nil {
			fmt.Fprintf(w, "warning: memory profile: %v\n", err)
			return
		}
		fmt.Fprintf(w, "memory profile: %s\n", memPath)
	}
	return cleanup, nil
}

func runDoctor(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	cfg := doctor.Config{
		Stdout: stdout,
		Stderr: stderr,
	}

	fs := flag.NewFlagSet("tinybpf doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.DurationVar(&cfg.Timeout, "timeout", 10*time.Second, "Timeout for each version check.")
	registerToolFlags(fs, &cfg.Tools)

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if err := doctor.Run(ctx, cfg); err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1
	}
	return 0
}

// registerToolFlags binds the standard LLVM tool path flags to a ToolOverrides.
func registerToolFlags(fs *flag.FlagSet, tools *llvm.ToolOverrides) {
	fs.StringVar(&tools.LLVMLink, "llvm-link", "", "Path to llvm-link binary.")
	fs.StringVar(&tools.Opt, "opt", "", "Path to opt binary.")
	fs.StringVar(&tools.LLC, "llc", "", "Path to llc binary.")
	fs.StringVar(&tools.LLVMAr, "llvm-ar", "", "Path to llvm-ar binary.")
	fs.StringVar(&tools.Objcopy, "llvm-objcopy", "", "Path to llvm-objcopy binary.")
	fs.StringVar(&tools.Pahole, "pahole", "", "Path to pahole binary (used with --btf).")
}

// parseSectionFlags converts "name=section" strings into a map.
func parseSectionFlags(flags []string) map[string]string {
	if len(flags) == 0 {
		return nil
	}
	m := make(map[string]string, len(flags))
	for _, f := range flags {
		parts := strings.SplitN(f, "=", 2)
		if len(parts) == 2 {
			m[parts[0]] = parts[1]
		}
	}
	return m
}
