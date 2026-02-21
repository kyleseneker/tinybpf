// Package cli implements the tinybpf command-line interface.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/kyleseneker/tinybpf/internal/llvm"
	"github.com/kyleseneker/tinybpf/internal/pipeline"
)

// Version is set at build time via ldflags:
//
//	go build -ldflags "-X github.com/kyleseneker/tinybpf/internal/cli.Version=v0.1.0"
var Version = "(dev)"

// multiStringFlag is a flag that can be set multiple times.
type multiStringFlag []string

// String returns the multiStringFlag as a comma-separated string.
func (m *multiStringFlag) String() string {
	return strings.Join(*m, ",")
}

// Set appends the value to the multiStringFlag.
func (m *multiStringFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("value cannot be empty")
	}
	*m = append(*m, value)
	return nil
}

// Run is the top-level entrypoint.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	switch args[0] {
	case "help", "--help", "-h":
		printUsage(stdout)
		return 0
	case "build":
		return runBuild(ctx, args[1:], stdout, stderr)
	case "link":
		return runLink(ctx, args[1:], stdout, stderr)
	case "doctor":
		return runDoctor(ctx, args[1:], stdout, stderr)
	case "init":
		return runInit(ctx, args[1:], stdout, stderr)
	case "version", "--version", "-version":
		return runVersion(stdout)
	default:
		return runLink(ctx, args, stdout, stderr)
	}
}

// printUsage prints the usage information for the CLI.
func printUsage(w io.Writer) {
	fmt.Fprintf(w, `tinybpf %s — Write eBPF programs in Go

Usage:
  tinybpf build [flags] <package>   Compile Go source to BPF ELF (one step)
  tinybpf link --input <file> [flags]
                                    Link TinyGo LLVM IR into a BPF ELF object
  tinybpf init <name>               Scaffold a new BPF project
  tinybpf doctor [flags]            Check toolchain installation
  tinybpf version                   Print version information
  tinybpf help                      Show this message

Run 'tinybpf <command> --help' for details on a specific command.

The bare-flag form 'tinybpf --input <file> [flags]' still works as an
alias for 'tinybpf link'.
`, Version)
}

// newFlagSet creates a FlagSet with consistent usage formatting.
func newFlagSet(w io.Writer, usage, desc string) *flag.FlagSet {
	fs := flag.NewFlagSet("tinybpf", flag.ContinueOnError)
	fs.SetOutput(w)
	fs.Usage = func() {
		fmt.Fprintf(w, "Usage: %s\n\n%s\n", usage, desc)
		var hasFlags bool
		fs.VisitAll(func(f *flag.Flag) {
			if f.Usage != "" {
				hasFlags = true
			}
		})
		if !hasFlags {
			return
		}
		fmt.Fprintln(w, "\nFlags:")
		fs.VisitAll(func(f *flag.Flag) {
			if f.Usage == "" {
				return
			}
			fmt.Fprintf(w, "  -%s", f.Name)
			if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "0" {
				fmt.Fprintf(w, " (default %s)", f.DefValue)
			}
			fmt.Fprintf(w, "\n    \t%s\n", f.Usage)
		})
	}
	return fs
}

// parseFlags parses args and returns (exitCode, ok).
func parseFlags(fs *flag.FlagSet, args []string) (code int, ok bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, false
		}
		return 2, false
	}
	return 0, true
}

// runVersion prints the version information for the CLI.
func runVersion(stdout io.Writer) int {
	fmt.Fprintf(stdout, "tinybpf %s\n", Version)
	return 0
}

// registerPipelineFlags registers the flags shared by build and link.
func registerPipelineFlags(fs *flag.FlagSet, cfg *pipeline.Config, programs, sections *multiStringFlag) {
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
	fs.Var(programs, "program", "Program function name to keep. Repeat for multiple programs. Auto-detected if omitted.")
	fs.Var(sections, "section", "Program-to-section mapping (e.g., handle_connect=tracepoint/syscalls/sys_enter_connect). Repeat for multiple.")
	registerToolFlags(fs, &cfg.Tools)
}

// runPipelineAndReport runs the link pipeline and prints the result.
func runPipelineAndReport(ctx context.Context, cfg pipeline.Config, stdout, stderr io.Writer) int {
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

// registerToolFlags binds the standard LLVM tool path flags to a ToolOverrides.
func registerToolFlags(fs *flag.FlagSet, tools *llvm.ToolOverrides) {
	fs.StringVar(&tools.LLVMLink, "llvm-link", "", "Path to llvm-link binary.")
	fs.StringVar(&tools.Opt, "opt", "", "Path to opt binary.")
	fs.StringVar(&tools.LLC, "llc", "", "Path to llc binary.")
	fs.StringVar(&tools.LLVMAr, "llvm-ar", "", "Path to llvm-ar binary.")
	fs.StringVar(&tools.Objcopy, "llvm-objcopy", "", "Path to llvm-objcopy binary.")
	fs.StringVar(&tools.Pahole, "pahole", "", "Path to pahole binary (used with --btf).")
}

// cliErrorf prints a formatted error message and returns exit code 1.
func cliErrorf(w io.Writer, format string, args ...any) int {
	fmt.Fprintf(w, "error: "+format+"\n", args...)
	return 1
}

// usageErrorf prints a formatted error message, shows the flagset usage, and returns exit code 2.
func usageErrorf(fs *flag.FlagSet, w io.Writer, format string, args ...any) int {
	fmt.Fprintf(w, "error: "+format+"\n", args...)
	fs.Usage()
	return 2
}

