package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kyleseneker/tinybpf/internal/codegen"
)

// runGenerate generates Go loader code from a compiled BPF ELF object.
func runGenerate(_ context.Context, args []string, stdout, stderr io.Writer) int {
	var pkg, output string

	fs := newFlagSet(stderr,
		"tinybpf generate [flags] <object.bpf.o>",
		"Generate type-safe Go loader code from a compiled BPF ELF object.")
	fs.StringVar(&pkg, "package", "", "Go package name for generated code (default: directory name of output).")
	fs.StringVar(&output, "output", "", "Output file path (default: <basename>_bpf.go in current directory).")

	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() != 1 {
		return usageErrorf(fs, stderr, "exactly one BPF object argument is required")
	}

	objectPath := fs.Arg(0)

	if output == "" {
		base := filepath.Base(objectPath)
		base = strings.TrimSuffix(base, ".bpf.o")
		base = strings.TrimSuffix(base, ".o")
		output = base + "_bpf.go"
	}

	if pkg == "" {
		absOutput, err := filepath.Abs(output)
		if err != nil {
			return cliErrorf(stderr, "resolve output path: %v", err)
		}
		pkg = filepath.Base(filepath.Dir(absOutput))
	}

	info, err := codegen.ExtractELFInfo(objectPath)
	if err != nil {
		return cliErrorf(stderr, "%v", err)
	}

	embedPath := computeEmbedPath(objectPath, output)
	src, err := codegen.Generate(pkg, info, embedPath)
	if err != nil {
		return cliErrorf(stderr, "%v", err)
	}

	if err := os.WriteFile(output, src, 0o600); err != nil {
		return cliErrorf(stderr, "write %s: %v", output, err)
	}

	fmt.Fprintf(stdout, "wrote %s (%d programs, %d maps)\n", output, len(info.Programs), len(info.Maps))
	return 0
}

// computeEmbedPath returns the relative path from the output file's directory
// to the BPF object, suitable for a //go:embed directive.
func computeEmbedPath(objectPath, outputPath string) string {
	absObj, err := filepath.Abs(objectPath)
	if err != nil {
		return ""
	}
	absOut, err := filepath.Abs(outputPath)
	if err != nil {
		return ""
	}
	outDir := filepath.Dir(absOut)
	rel, err := filepath.Rel(outDir, absObj)
	if err != nil {
		return ""
	}
	if strings.HasPrefix(rel, "..") {
		return ""
	}
	return rel
}
