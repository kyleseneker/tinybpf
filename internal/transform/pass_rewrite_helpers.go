package transform

import (
	"fmt"
	"strings"

	"github.com/kyleseneker/tinybpf/diag"
	"github.com/kyleseneker/tinybpf/internal/ir"
)

// rewriteHelpersModule replaces Go-style BPF helper calls with inttoptr-based kernel helper calls.
func rewriteHelpersModule(m *ir.Module) error {
	var errs []error
	for _, fn := range m.Functions {
		if fn.Removed {
			continue
		}
		ir.EnsureBlocks(fn)
		for _, block := range fn.Blocks {
			for _, inst := range block.Instructions {
				if inst.Kind == ir.InstCall && inst.Call != nil &&
					strings.HasPrefix(inst.Call.Callee, "@main.bpf") {
					if err := rewriteHelperInst(inst, fn); err != nil {
						errs = append(errs, err)
					}
				} else if inst.Kind == ir.InstOther &&
					strings.Contains(inst.Raw, "@main.bpf") &&
					strings.Contains(inst.Raw, "call") {
					// Parser couldn't parse this call — report as error
					errs = append(errs, fmt.Errorf("line references @main.bpf* but does not match expected call pattern: %s",
						strings.TrimSpace(inst.Raw)))
				}
			}
		}
	}
	return diag.WrapErrors(diag.StageTransform, "rewrite-helpers", errs,
		"check that helper names match kernel BPF helpers")
}

// rewriteHelperInst rewrites a single BPF helper call instruction from Go-style to inttoptr-based.
func rewriteHelperInst(inst *ir.Instruction, fn *ir.Function) error {
	callee := inst.Call.Callee
	funcName := strings.TrimPrefix(callee, "@")
	if strings.HasPrefix(funcName, "main.bpfCore") || strings.HasPrefix(funcName, "main.bpfKfunc") {
		return nil
	}
	helperID, ok := helperIDs[funcName]
	if !ok {
		return unknownHelperErr(funcName)
	}
	args := stripTrailingUndef(inst.Call.Args)
	inst.Call.Callee = fmt.Sprintf("inttoptr (i64 %d to ptr)", helperID)
	inst.Call.Args = args
	inst.Modified = true
	fn.Modified = true
	return nil
}

// unknownHelperErr returns an error for an unrecognized BPF helper, with a suggestion if possible.
func unknownHelperErr(name string) error {
	if suggestion := closestHelper(name); suggestion != "" {
		return fmt.Errorf("unknown BPF helper %q (did you mean %q?)", name, suggestion)
	}
	return fmt.Errorf("unknown BPF helper %q", name)
}
