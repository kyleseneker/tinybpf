package cli

import (
	"context"
	"io"

	"github.com/kyleseneker/tinybpf/internal/scaffold"
)

// runInit scaffolds a new BPF project in the current directory.
func runInit(_ context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet(stderr, "tinybpf init <name>", "Scaffold a new BPF project in the current directory.")

	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	if fs.NArg() != 1 {
		return usageErrorf(fs, stderr, "exactly one project name argument is required")
	}

	cfg := scaffold.Config{Dir: ".", Program: fs.Arg(0), Stdout: stdout}
	if err := scaffold.Run(cfg); err != nil {
		return cliErrorf(stderr, "%v", err)
	}
	return 0
}
