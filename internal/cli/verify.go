package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/kyleseneker/tinybpf/internal/elfcheck"
)

type elfValidator func(path string) error

// runVerify validates a BPF ELF object offline.
func runVerify(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runVerifyWith(ctx, args, stdout, stderr, elfcheck.Validate)
}

// runVerifyWith is the testable core of runVerify with an injected ELF validator.
func runVerifyWith(_ context.Context, args []string, stdout, stderr io.Writer, validate elfValidator) int {
	var input string

	fs := newFlagSet(stderr, "tinybpf verify --input <file>", "Validate a BPF ELF object offline.")
	fs.StringVar(&input, "input", "", "Path to the BPF ELF object to validate.")
	fs.StringVar(&input, "i", "", "Path to the BPF ELF object to validate (shorthand).")

	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	if input == "" {
		return usageErrorf(fs, stderr, "--input is required")
	}

	if err := validate(input); err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1
	}

	fmt.Fprintf(stdout, "%s: valid BPF ELF object\n", input)
	return 0
}
