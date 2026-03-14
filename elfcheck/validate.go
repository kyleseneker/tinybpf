// Package elfcheck validates that an output file is a well-formed eBPF ELF object.
package elfcheck

import (
	"debug/elf"
	"fmt"

	"github.com/kyleseneker/tinybpf/diag"
)

// Validate checks that the ELF at path is a well-formed BPF object.
func Validate(path string) error {
	f, err := elf.Open(path)
	if err != nil {
		return validationErr(err, "output is not a readable ELF object")
	}
	defer func() { _ = f.Close() }()

	if err := validateClassAndMachine(f); err != nil {
		return err
	}
	if err := validateProgramSections(f); err != nil {
		return err
	}
	if err := validateMapsSection(f); err != nil {
		return err
	}
	return validateSymbols(f)
}

// validationErr wraps err as a validation-stage diagnostic with a hint.
func validationErr(err error, hint string) *diag.Error {
	return diag.Wrap(diag.StageValidate, err, hint)
}

// validateClassAndMachine checks for 64-bit class and EM_BPF machine type.
func validateClassAndMachine(f *elf.File) error {
	if f.Class != elf.ELFCLASS64 {
		return validationErr(
			fmt.Errorf("expected ELFCLASS64, got %s", f.Class),
			"use llc with BPF target")
	}
	if f.Machine != elf.EM_BPF {
		return validationErr(
			fmt.Errorf("expected machine %s, got %s", elf.EM_BPF, f.Machine),
			"ensure llc uses -march=bpf")
	}
	return nil
}

// validateProgramSections checks that at least one executable PROGBITS section exists.
func validateProgramSections(f *elf.File) error {
	for _, s := range f.Sections {
		if s.Type == elf.SHT_PROGBITS && (s.Flags&elf.SHF_EXECINSTR) != 0 {
			return nil
		}
	}
	return validationErr(
		fmt.Errorf("missing executable program section"),
		"verify input IR contains at least one BPF program function section")
}

// validateMapsSection rejects a .maps section that is incorrectly marked executable.
func validateMapsSection(f *elf.File) error {
	for _, s := range f.Sections {
		if s.Name == ".maps" && (s.Flags&elf.SHF_EXECINSTR) != 0 {
			return validationErr(
				fmt.Errorf(".maps section has executable flag"),
				"map definitions should be data sections, not executable code")
		}
	}
	return nil
}

// validateSymbols checks that the object contains at least one symbol.
func validateSymbols(f *elf.File) error {
	syms, err := f.Symbols()
	if err == nil && len(syms) == 0 {
		return validationErr(
			fmt.Errorf("object contains no symbols"),
			"expected at least one global function symbol for a BPF program")
	}
	return nil
}
