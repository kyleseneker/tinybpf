package cli

import (
	"context"
	"io"

	"github.com/kyleseneker/tinybpf"
)

// runBuild compiles Go source to a BPF ELF object in one step.
func runBuild(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	var programs multiStringFlag
	var sectionFlags multiStringFlag
	var configPath string
	var req tinybpf.Request

	fs := newFlagSet(stderr, "tinybpf build [flags] <package>", "Compile Go source to a BPF ELF object in one step.")
	registerBuildFlags(fs, &req, &programs, &sectionFlags, &configPath)
	fs.StringVar(&req.Toolchain.TinyGo, "tinygo", "", "Path to tinygo binary (default: discovered from PATH).")

	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	cfgResult, cfgErr := loadProjectConfig(fs, configPath, &req, stderr)
	if cfgErr != nil {
		return cliErrorf(stderr, "%v", cfgErr)
	}

	if fs.NArg() != 1 {
		return usageErrorf(fs, stderr, "exactly one package argument is required")
	}

	req.Package = fs.Arg(0)

	if req.Toolchain.TinyGo == "" && cfgResult.tinygo != "" {
		req.Toolchain.TinyGo = cfgResult.tinygo
	}

	if len(programs) > 0 {
		req.Programs = programs
	}

	sections, secErr := parseSectionFlags(sectionFlags)
	if secErr != nil {
		return cliErrorf(stderr, "%v", secErr)
	}
	if len(sections) > 0 {
		req.Sections = sections
	}

	return runBuildAndReport(ctx, req, stdout, stderr)
}
