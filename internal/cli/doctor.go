package cli

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/kyleseneker/tinybpf"
	"github.com/kyleseneker/tinybpf/internal/doctor"
	"github.com/kyleseneker/tinybpf/internal/llvm"
)

// runDoctor checks the toolchain installation and version compatibility.
func runDoctor(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	var toolchain tinybpf.Toolchain
	var timeout time.Duration

	fs := newFlagSet(stderr, "tinybpf doctor [flags]", "Check toolchain installation and version compatibility.")
	fs.DurationVar(&timeout, "timeout", 10*time.Second, "Timeout for each version check.")
	registerToolFlags(fs, &toolchain)

	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	cfg := doctor.Config{
		Tools: llvm.ToolOverrides{
			LLVMLink: toolchain.LLVMLink,
			Opt:      toolchain.Opt,
			LLC:      toolchain.LLC,
			LLVMAr:   toolchain.LLVMAr,
			Objcopy:  toolchain.Objcopy,
			Pahole:   toolchain.Pahole,
		},
		Stdout:  stdout,
		Stderr:  stderr,
		Timeout: timeout,
	}

	if err := doctor.Run(ctx, cfg); err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1
	}
	return 0
}
