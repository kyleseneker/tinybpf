package pipeline

import (
	"context"
	"fmt"
	"strings"

	"github.com/kyleseneker/tinybpf/internal/diag"
	"github.com/kyleseneker/tinybpf/internal/llvm"
)

// injectBTF runs pahole -J on the output object to embed BTF type information.
func injectBTF(ctx context.Context, cfg Config, tools llvm.Tools) error {
	if tools.Pahole == "" {
		return &diag.Error{Stage: diag.StageBTF,
			Err:     fmt.Errorf("pahole not found"),
			Command: "pahole",
			Hint:    "install pahole or pass --pahole when using --btf"}
	}

	res, err := llvm.Run(ctx, cfg.Timeout, tools.Pahole, "-J", cfg.Output)
	if cfg.Verbose && strings.TrimSpace(res.Stderr) != "" {
		fmt.Fprintf(cfg.Stderr, "%s\n", res.Stderr)
	}
	if err != nil {
		return &diag.Error{Stage: diag.StageBTF, Err: err,
			Command: res.Command, Stderr: res.Stderr,
			Hint: "failed to inject BTF data into output object"}
	}
	return nil
}
