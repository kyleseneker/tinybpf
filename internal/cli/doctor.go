package cli

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/kyleseneker/tinybpf/internal/doctor"
)

// runDoctor checks the toolchain installation and version compatibility.
func runDoctor(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	cfg := doctor.Config{
		Stdout: stdout,
		Stderr: stderr,
	}

	fs := newFlagSet(stderr, "tinybpf doctor [flags]", "Check toolchain installation and version compatibility.")
	fs.DurationVar(&cfg.Timeout, "timeout", 10*time.Second, "Timeout for each version check.")
	registerToolFlags(fs, &cfg.Tools)

	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	if err := doctor.Run(ctx, cfg); err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1
	}
	return 0
}
