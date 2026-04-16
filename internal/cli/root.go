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

	"github.com/kyleseneker/tinybpf"
	"github.com/kyleseneker/tinybpf/config"
	"github.com/kyleseneker/tinybpf/internal/cache"
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
	case "generate":
		return runGenerate(ctx, args[1:], stdout, stderr)
	case "clean-cache":
		return runCleanCache(stdout, stderr)
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
  tinybpf generate <object.bpf.o>  Generate Go loader from BPF ELF
  tinybpf clean-cache               Remove cached build artifacts
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

// registerBuildFlags registers the flags shared by build and link.
func registerBuildFlags(fs *flag.FlagSet, req *tinybpf.Request, programs, sections *multiStringFlag, configPath *string) {
	fs.StringVar(configPath, "config", "", "Path to tinybpf.json project config (default: auto-discovered).")
	fs.StringVar(&req.Output, "output", "bpf.o", "Output eBPF ELF object path.")
	fs.StringVar(&req.Output, "o", "bpf.o", "Output eBPF ELF object path (shorthand).")
	fs.StringVar(&req.CPU, "cpu", "v3", "BPF CPU version passed to llc as -mcpu.")
	fs.BoolVar(&req.KeepTemp, "keep-temp", false, "Keep temporary intermediate files after run.")
	fs.BoolVar(&req.Verbose, "verbose", false, "Enable verbose stage logging.")
	fs.BoolVar(&req.Verbose, "v", false, "Enable verbose stage logging (shorthand).")
	fs.StringVar(&req.PassPipeline, "pass-pipeline", "", "Explicit LLVM opt pass pipeline string.")
	fs.StringVar(&req.OptProfile, "opt-profile", "default", "Optimization profile: conservative, default, aggressive, verifier-safe.")
	fs.DurationVar(&req.Timeout, "timeout", 30*time.Second, "Per-stage command timeout.")
	fs.StringVar(&req.TempDir, "tmpdir", "", "Directory for intermediate artifacts (kept after run).")
	fs.BoolVar(&req.EnableBTF, "btf", false, "Enable BTF injection via pahole.")
	fs.BoolVar(&req.DumpIR, "dump-ir", false, "Write intermediate IR after each transform stage for debugging.")
	fs.BoolVar(&req.Cache, "cache", true, "Enable content-addressed build cache for intermediate artifacts.")
	fs.StringVar(&req.ProgramType, "program-type", "", "BPF program type (e.g. kprobe, xdp, tracepoint). Auto-inferred from --section values when omitted.")
	fs.Var(programs, "program", "Program function name to keep. Repeat for multiple programs. Auto-detected if omitted.")
	fs.Var(sections, "section", "Program-to-section mapping (e.g., handle_connect=tracepoint/syscalls/sys_enter_connect). Repeat for multiple.")
	registerToolFlags(fs, &req.Toolchain)
}

// configResult holds the loaded project config and tinygo path override.
type configResult struct {
	tinygo string
}

// loadProjectConfig discovers and applies tinybpf.json settings that aren't overridden by CLI flags.
func loadProjectConfig(fs *flag.FlagSet, configPath string, req *tinybpf.Request, stderr io.Writer) (*configResult, error) {
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
	fileReq := config.ToRequest(fileCfg)
	applyBuildDefaults(set, req, &fileReq, fileCfg)
	applyToolOverrides(set, &req.Toolchain, fileReq.Toolchain)

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

// applyBuildDefaults copies config-file build settings into the request
// for any field not explicitly set via CLI flags.
func applyBuildDefaults(set map[string]bool, req *tinybpf.Request, fileReq *tinybpf.Request, fileCfg *config.Config) {
	applyBuildScalars(set, req, fileReq, fileCfg)
	if !set["program"] && len(fileReq.Programs) > 0 {
		req.Programs = fileReq.Programs
	}
	if !set["section"] && len(fileReq.Sections) > 0 {
		req.Sections = fileReq.Sections
	}
	if len(fileReq.CustomPasses) > 0 {
		req.CustomPasses = fileReq.CustomPasses
	}
}

// applyBuildScalars copies individual config-file scalar fields unless overridden by CLI flags.
func applyBuildScalars(set map[string]bool, req *tinybpf.Request, fileReq *tinybpf.Request, fileCfg *config.Config) {
	if !set["output"] && !set["o"] && fileReq.Output != "" {
		req.Output = fileReq.Output
	}
	if !set["cpu"] && fileReq.CPU != "" {
		req.CPU = fileReq.CPU
	}
	if !set["opt-profile"] && fileReq.OptProfile != "" {
		req.OptProfile = fileReq.OptProfile
	}
	if !set["btf"] && fileCfg.Build.BTF != nil {
		req.EnableBTF = fileReq.EnableBTF
	}
	if !set["cache"] && fileCfg.Build.Cache != nil {
		req.Cache = fileReq.Cache
	}
	if !set["timeout"] && fileReq.Timeout > 0 {
		req.Timeout = fileReq.Timeout
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
func applyToolOverrides(set map[string]bool, dst *tinybpf.Toolchain, src tinybpf.Toolchain) {
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

// runBuildAndReport runs a build request and prints the result.
func runBuildAndReport(ctx context.Context, req tinybpf.Request, stdout, stderr io.Writer) int {
	req.Stdout = stdout
	req.Stderr = stderr
	result, err := tinybpf.Build(ctx, req)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1
	}
	if req.Verbose || req.KeepTemp || req.TempDir != "" {
		fmt.Fprintf(stdout, "intermediates: %s\n", result.TempDir)
	}
	fmt.Fprintf(stdout, "wrote %s\n", result.Output)
	return 0
}

// registerToolFlags binds the standard LLVM tool path flags to a Toolchain.
func registerToolFlags(fs *flag.FlagSet, tc *tinybpf.Toolchain) {
	fs.StringVar(&tc.LLVMLink, "llvm-link", "", "Path to llvm-link binary.")
	fs.StringVar(&tc.Opt, "opt", "", "Path to opt binary.")
	fs.StringVar(&tc.LLC, "llc", "", "Path to llc binary.")
	fs.StringVar(&tc.LLVMAr, "llvm-ar", "", "Path to llvm-ar binary.")
	fs.StringVar(&tc.Objcopy, "llvm-objcopy", "", "Path to llvm-objcopy binary.")
	fs.StringVar(&tc.Pahole, "pahole", "", "Path to pahole binary (used with --btf).")
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

// runCleanCache removes all cached build artifacts.
func runCleanCache(stdout, stderr io.Writer) int {
	s, err := cache.Open()
	if err != nil {
		return cliErrorf(stderr, "opening cache: %v", err)
	}
	if err := s.Clean(); err != nil {
		return cliErrorf(stderr, "cleaning cache: %v", err)
	}
	fmt.Fprintf(stdout, "cleaned cache: %s\n", s.Dir())
	return 0
}

// parseSectionFlags parses "name=section" flag strings into a map.
func parseSectionFlags(flags []string) (map[string]string, error) {
	if len(flags) == 0 {
		return nil, nil
	}
	m := make(map[string]string, len(flags))
	for _, f := range flags {
		parts := strings.SplitN(f, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid --section %q: expected format name=section", f)
		}
		name := strings.TrimSpace(parts[0])
		section := strings.TrimSpace(parts[1])
		if name == "" || section == "" {
			return nil, fmt.Errorf("invalid --section %q: expected format name=section", f)
		}
		m[name] = section
	}
	return m, nil
}
