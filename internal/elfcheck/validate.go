// Package elfcheck validates that an output file is a well-formed eBPF ELF object.
package elfcheck

import (
	"debug/elf"
	"fmt"

	"github.com/kyleseneker/tinybpf/internal/diag"
)

// Validate opens the ELF at path and checks that it meets the minimum
// requirements for a BPF object: 64-bit class, EM_BPF machine, at least
// one executable program section, and at least one symbol.
func Validate(path string) error {
	f, err := elf.Open(path)
	if err != nil {
		return &diag.Error{Stage: diag.StageValidate, Err: err,
			Hint: "output is not a readable ELF object"}
	}
	defer func() { _ = f.Close() }()

	if f.Class != elf.ELFCLASS64 {
		return &diag.Error{Stage: diag.StageValidate,
			Err:  fmt.Errorf("expected ELFCLASS64, got %s", f.Class),
			Hint: "use llc with BPF target"}
	}

	if f.Machine != elf.EM_BPF {
		return &diag.Error{Stage: diag.StageValidate,
			Err:  fmt.Errorf("expected machine %s, got %s", elf.EM_BPF, f.Machine),
			Hint: "ensure llc uses -march=bpf"}
	}

	hasCode := false
	for _, s := range f.Sections {
		if s.Type == elf.SHT_PROGBITS && (s.Flags&elf.SHF_EXECINSTR) != 0 {
			hasCode = true
			break
		}
	}
	if !hasCode {
		return &diag.Error{Stage: diag.StageValidate,
			Err:  fmt.Errorf("missing executable program section"),
			Hint: "verify input IR contains at least one BPF program function section"}
	}

	syms, err := f.Symbols()
	if err == nil && len(syms) == 0 {
		return &diag.Error{Stage: diag.StageValidate,
			Err:  fmt.Errorf("object contains no symbols"),
			Hint: "expected at least one global function symbol for a BPF program"}
	}

	return nil
}
