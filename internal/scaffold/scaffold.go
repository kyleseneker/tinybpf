// Package scaffold generates the file structure for a new tinybpf project.
package scaffold

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Config holds settings for project scaffolding.
type Config struct {
	Dir     string
	Program string
	Stdout  io.Writer
}

// Run generates a minimal tinybpf project skeleton in cfg.Dir.
func Run(cfg Config) error {
	if cfg.Stdout == nil {
		cfg.Stdout = io.Discard
	}
	if strings.TrimSpace(cfg.Program) == "" {
		return fmt.Errorf("program name is required")
	}

	bpfDir := filepath.Join(cfg.Dir, "bpf")
	if err := os.MkdirAll(bpfDir, 0o755); err != nil {
		return fmt.Errorf("creating bpf directory: %w", err)
	}

	files := []struct {
		path    string
		content string
	}{
		{filepath.Join(bpfDir, cfg.Program+".go"), programGo(cfg.Program)},
		{filepath.Join(bpfDir, cfg.Program+"_stub.go"), programStubGo()},
		{filepath.Join(cfg.Dir, "Makefile"), makefile(cfg.Program)},
	}

	for _, f := range files {
		if _, err := os.Stat(f.path); err == nil {
			return fmt.Errorf("%s already exists; refusing to overwrite", f.path)
		}
		if err := os.WriteFile(f.path, []byte(f.content), 0o600); err != nil {
			return fmt.Errorf("writing %s: %w", f.path, err)
		}
		rel, _ := filepath.Rel(cfg.Dir, f.path)
		if rel == "" {
			rel = f.path
		}
		fmt.Fprintf(cfg.Stdout, "  create %s\n", rel)
	}

	return nil
}

func programGo(programName string) string {
	return `//go:build tinygo

package main

import "unsafe"

// bpfMapDef describes a BPF map. tinybpf rewrites this to BTF-compatible encoding.
// Set Type to the BPF map type constant and fill in the remaining fields for your use case.
// Common types: 1 (HASH), 2 (ARRAY), 6 (PERCPU_HASH), 27 (RINGBUF).
type bpfMapDef struct {
	Type       uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	MapFlags   uint32
}

// Declare BPF helpers with //go:extern. tinybpf rewrites these to kernel helper calls.
// See docs/TINYGO_COMPAT.md for the full list of supported helpers.
//
//go:extern bpf_get_current_pid_tgid
func bpfGetCurrentPidTgid() uint64

// ` + programName + ` is the BPF program entry point.
// Assign it to an ELF section with: tinybpf --section ` + programName + `=<type>/<attach_point>
//
//export ` + programName + `
func ` + programName + `(ctx unsafe.Pointer) int32 {
	return 0
}

func main() {}
`
}

func programStubGo() string {
	return `//go:build !tinygo

package main
`
}

func makefile(programName string) string {
	return `.PHONY: build clean

# Output paths
BUILD_DIR := build
IR_FILE   := $(BUILD_DIR)/` + programName + `.ll
BPF_OBJ   := $(BUILD_DIR)/` + programName + `.bpf.o

# Customize: set the ELF section for your program.
# Examples:
#   tracepoint/syscalls/sys_enter_connect
#   kprobe/__x64_sys_openat
#   xdp
SECTION := ` + programName + `

build: $(BPF_OBJ)

$(IR_FILE): bpf/` + programName + `.go | $(BUILD_DIR)
	tinygo build -gc=none -scheduler=none -panic=trap -opt=1 -o $@ ./bpf

$(BPF_OBJ): $(IR_FILE)
	tinybpf --input $< --output $@ --section ` + programName + `=$(SECTION) --verbose

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)
`
}
