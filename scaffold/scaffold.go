// Package scaffold generates the file structure for a new tinybpf project.
package scaffold

import (
	"encoding/json"
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

type plannedFile struct {
	path    string
	content string
}

// Run generates a minimal tinybpf project skeleton in cfg.Dir.
func Run(cfg Config) error {
	if cfg.Stdout == nil {
		cfg.Stdout = io.Discard
	}
	if err := validateProgramName(cfg.Program); err != nil {
		return err
	}

	bpfDir := filepath.Join(cfg.Dir, "bpf")
	if err := os.MkdirAll(bpfDir, 0o755); err != nil {
		return fmt.Errorf("creating bpf directory: %w", err)
	}

	files := buildPlan(cfg.Dir, bpfDir, cfg.Program)

	if err := checkCollisions(files); err != nil {
		return err
	}
	return writePlannedFiles(cfg.Dir, cfg.Stdout, files)
}

func buildPlan(dir, bpfDir, program string) []plannedFile {
	return []plannedFile{
		{filepath.Join(dir, "tinybpf.json"), projectConfig(program)},
		{filepath.Join(bpfDir, program+".go"), programGo(program)},
		{filepath.Join(bpfDir, program+"_stub.go"), programStubGo()},
		{filepath.Join(dir, "Makefile"), makefile(program)},
	}
}

func checkCollisions(files []plannedFile) error {
	for _, f := range files {
		if _, err := os.Stat(f.path); err == nil {
			return fmt.Errorf("%s already exists; refusing to overwrite", f.path)
		}
	}
	return nil
}

func writePlannedFiles(baseDir string, out io.Writer, files []plannedFile) error {
	for _, f := range files {
		if err := os.WriteFile(f.path, []byte(f.content), 0o600); err != nil {
			return fmt.Errorf("writing %s: %w", f.path, err)
		}
		rel, _ := filepath.Rel(baseDir, f.path)
		if rel == "" {
			rel = f.path
		}
		fmt.Fprintf(out, "  create %s\n", rel)
	}
	return nil
}

func validateProgramName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("program name is required")
	}
	if strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("program name must not contain path separators")
	}
	return nil
}

func programGo(programName string) string {
	return `//go:build tinygo

package main

import "unsafe"

// bpfMapDef describes a BPF map. tinybpf rewrites this to BTF-compatible encoding.
// Set Type to the BPF map type constant and fill in the remaining fields for your use case.
// Common types: 1 (HASH), 2 (ARRAY), 5 (PERCPU_HASH), 27 (RINGBUF).
type bpfMapDef struct {
	Type       uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	MapFlags   uint32
}

// Declare BPF helpers with //go:extern. tinybpf rewrites these to kernel helper calls.
// See docs/writing-go-for-ebpf.md for the full list of supported helpers.
//
//go:extern bpf_get_current_pid_tgid
func bpfGetCurrentPidTgid() uint64

// ` + programName + ` is the BPF program entry point.
// Set the ELF section in tinybpf.json under build.programs.
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

BUILD_DIR := build
BPF_OBJ   := $(BUILD_DIR)/` + programName + `.bpf.o

build: $(BPF_OBJ)

$(BPF_OBJ): bpf/` + programName + `.go tinybpf.json | $(BUILD_DIR)
	tinybpf build --verbose ./bpf

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)
`
}

func projectConfig(programName string) string {
	type build struct {
		Output   string            `json:"output"`
		Programs map[string]string `json:"programs"`
	}
	cfg := struct {
		Build build `json:"build"`
	}{
		Build: build{
			Output:   "build/" + programName + ".bpf.o",
			Programs: map[string]string{programName: programName},
		},
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	return string(data) + "\n"
}
