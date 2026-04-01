// Package tinybpf compiles Go source or pre-compiled LLVM IR into
// BPF ELF objects suitable for loading with cilium/ebpf or libbpf.
package tinybpf

import (
	"io"
	"time"
)

// Request describes the inputs and options for a BPF compilation.
type Request struct {
	// Package is a Go package path to compile via TinyGo.
	// Mutually exclusive with Inputs.
	Package string

	// Inputs are pre-compiled LLVM IR/bitcode files to link.
	// Supported extensions: .ll, .bc, .o, .a.
	// Mutually exclusive with Package.
	Inputs []string

	// Output is the path for the resulting BPF ELF object.
	// Defaults to "bpf.o" if empty.
	Output string

	// CPU is the BPF CPU version passed to llc (e.g. "v3").
	// Defaults to "v3" if empty.
	CPU string

	// EnableBTF injects BTF type information via pahole.
	EnableBTF bool

	// ProgramType constrains section validation to a specific BPF program
	// type (e.g. "kprobe", "xdp", "tracepoint").
	ProgramType string

	// Programs lists BPF program function names to keep.
	// Auto-detected from IR if omitted.
	Programs []string

	// Sections maps program function names to ELF section names
	// (e.g. "handle_connect" -> "tracepoint/syscalls/sys_enter_connect").
	Sections map[string]string

	// OptProfile selects a named optimization profile:
	// "conservative", "default", "aggressive", or "verifier-safe".
	// Defaults to "default" if empty.
	OptProfile string

	// PassPipeline is an explicit LLVM opt pass pipeline string.
	// Overrides OptProfile when set.
	PassPipeline string

	// CustomPasses are additional LLVM pass names appended to the pipeline.
	CustomPasses []string

	// Timeout is the per-stage command timeout. Defaults to 30s.
	Timeout time.Duration

	// KeepTemp preserves intermediate artifacts after the run.
	KeepTemp bool

	// TempDir specifies a directory for intermediate artifacts.
	// When set, artifacts are kept regardless of KeepTemp.
	TempDir string

	// Cache enables the content-addressed build cache.
	Cache bool

	// DumpIR writes intermediate IR after each transform stage.
	DumpIR bool

	// Verbose enables detailed stage logging to Stdout/Stderr.
	Verbose bool

	// Jobs controls parallel input normalization workers. Defaults to 1.
	Jobs int

	// Toolchain overrides default tool discovery for LLVM and TinyGo binaries.
	Toolchain Toolchain

	// Stdout receives verbose and informational output.
	// Defaults to [io.Discard] if nil.
	Stdout io.Writer

	// Stderr receives warning and error detail output.
	// Defaults to [io.Discard] if nil.
	Stderr io.Writer
}

// Result holds the outputs of a successful [Build].
type Result struct {
	// Output is the path to the final BPF ELF object.
	Output string

	// TempDir is the directory containing intermediate artifacts,
	// populated when KeepTemp is true or TempDir was specified.
	TempDir string

	// Programs lists the BPF program symbol names found in the output ELF.
	Programs []string

	// Maps lists the BPF map symbol names found in the output ELF.
	Maps []string
}

// Toolchain configures explicit paths to LLVM and TinyGo binaries.
type Toolchain struct {
	TinyGo   string
	LLVMLink string
	Opt      string
	LLC      string
	LLVMAr   string
	Objcopy  string
	Pahole   string
}
