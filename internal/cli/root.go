// Package cli implements the tinybpf command-line interface.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/kyleseneker/tinybpf/config"
	"github.com/kyleseneker/tinybpf/llvm"
	"github.com/kyleseneker/tinybpf/pipeline"
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
	case "verify":
		return runVerify(ctx, args[1:], stdout, stderr)
	case "version", "--version", "-version":
		return runVersion(stdout)
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n", args[0])
		printUsage(stderr)
		return 2
	}
}

// printUsage prints the usage information for the CLI.
func printUsage(w io.Writer) {
	fmt.Fprintf(w, `tinybpf %s — Write eBPF programs in Go

Usage:
  tinybpf build [flags] <package>   Compile Go source to BPF ELF (one step)
  tinybpf link --input <file> [flags]   Link pre-compiled LLVM IR into a BPF ELF
  tinybpf init <name>               Scaffold a new BPF project
  tinybpf verify --input <file>     Validate a BPF ELF object
  tinybpf doctor [flags]            Check toolchain installation
  tinybpf version                   Print version information
  tinybpf help                      Show this message

Run 'tinybpf <command> --help' for details on a specific command.
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
func registerPipelineFlags(fs *flag.FlagSet, cfg *pipeline.Config, programs, sections *multiStringFlag, configPath *string) {
	fs.StringVar(configPath, "config", "", "Path to tinybpf.json project config (default: auto-discovered).")
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
	fs.BoolVar(&cfg.DumpIR, "dump-ir", false, "Write intermediate IR after each transform stage for debugging.")
	fs.StringVar(&cfg.ProgramType, "program-type", "", "Expected BPF program type (e.g. kprobe, xdp, tracepoint). Validates --section values.")
	fs.Var(programs, "program", "Program function name to keep. Repeat for multiple programs. Auto-detected if omitted.")
	fs.Var(sections, "section", "Program-to-section mapping (e.g., handle_connect=tracepoint/syscalls/sys_enter_connect). Repeat for multiple.")
	registerToolFlags(fs, &cfg.Tools)
}

// configResult holds the loaded project config and tinygo path override.
type configResult struct {
	tinygo string
}

// loadProjectConfig discovers, loads, and applies tinybpf.json settings to
// the pipeline config. CLI flags that were explicitly set take precedence.
func loadProjectConfig(fs *flag.FlagSet, configPath string, cfg *pipeline.Config, stderr io.Writer) (*configResult, error) {
	path, err := resolveConfigPath(configPath)
	if err != nil {
		return nil, err
	}
	if path == "" {
		return &configResult{}, nil
	}

	fileCfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}

	set := flagsSet(fs)
	pc := config.ToPipeline(fileCfg)
	applyBuildDefaults(set, cfg, &pc, fileCfg)
	applyToolOverrides(set, &cfg.Tools, pc.Tools)

	return &configResult{tinygo: fileCfg.Toolchain.TinyGo}, nil
}

// resolveConfigPath returns an explicit path or auto-discovers tinybpf.json.
func resolveConfigPath(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", nil
	}
	found, err := config.Find(wd)
	if err != nil {
		return "", nil
	}
	return found, nil
}

// applyBuildDefaults copies config-file build settings into the pipeline
// config for any field not explicitly set via CLI flags.
func applyBuildDefaults(set map[string]bool, cfg *pipeline.Config, pc *pipeline.Config, fileCfg *config.Config) {
	applyBuildScalars(set, cfg, pc, fileCfg)
	if !set["program"] && len(pc.Programs) > 0 {
		cfg.Programs = pc.Programs
	}
	if !set["section"] && len(pc.Sections) > 0 {
		cfg.Sections = pc.Sections
	}
	if len(pc.CustomPasses) > 0 {
		cfg.CustomPasses = pc.CustomPasses
	}
}

func applyBuildScalars(set map[string]bool, cfg *pipeline.Config, pc *pipeline.Config, fileCfg *config.Config) {
	if !set["output"] && !set["o"] && pc.Output != "" {
		cfg.Output = pc.Output
	}
	if !set["cpu"] && pc.CPU != "" {
		cfg.CPU = pc.CPU
	}
	if !set["opt-profile"] && pc.OptProfile != "" {
		cfg.OptProfile = pc.OptProfile
	}
	if !set["btf"] && fileCfg.Build.BTF != nil {
		cfg.EnableBTF = pc.EnableBTF
	}
	if !set["timeout"] && pc.Timeout > 0 {
		cfg.Timeout = pc.Timeout
	}
}

// flagsSet returns a set of flag names that were explicitly provided by the user.
func flagsSet(fs *flag.FlagSet) map[string]bool {
	m := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { m[f.Name] = true })
	return m
}

// applyToolOverrides applies config-file tool paths for any tool not
// explicitly overridden via CLI flags.
func applyToolOverrides(set map[string]bool, dst *llvm.ToolOverrides, src llvm.ToolOverrides) {
	if !set["llvm-link"] && src.LLVMLink != "" {
		dst.LLVMLink = src.LLVMLink
	}
	if !set["opt"] && src.Opt != "" {
		dst.Opt = src.Opt
	}
	if !set["llc"] && src.LLC != "" {
		dst.LLC = src.LLC
	}
	if !set["llvm-ar"] && src.LLVMAr != "" {
		dst.LLVMAr = src.LLVMAr
	}
	if !set["llvm-objcopy"] && src.Objcopy != "" {
		dst.Objcopy = src.Objcopy
	}
	if !set["pahole"] && src.Pahole != "" {
		dst.Pahole = src.Pahole
	}
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
