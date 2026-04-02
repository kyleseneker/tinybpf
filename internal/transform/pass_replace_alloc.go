package transform

import (
	"fmt"
	"slices"
	"strings"

	"github.com/kyleseneker/tinybpf/diag"
	"github.com/kyleseneker/tinybpf/internal/ir"
)

// allocSite records the location and parameters of a runtime.alloc call to replace.
type allocSite struct {
	blockIdx int
	instIdx  int
	varName  string
	size     string
}

// replaceAllocModule converts runtime.alloc calls to stack allocas zeroed by memset.
func replaceAllocModule(m *ir.Module) error {
	needMemset := false
	var errs []error

	for _, fn := range m.Functions {
		if fn.Removed {
			continue
		}
		ir.EnsureBlocks(fn)

		sites := collectAllocSites(fn, &errs)
		if len(sites) == 0 {
			continue
		}
		needMemset = true
		fn.Modified = true
		applyAllocReplacements(fn, sites)
	}

	if err := diag.WrapErrors(diag.StageTransform, "replace-alloc", errs,
		"check that @runtime.alloc calls match the expected pattern"); err != nil {
		return err
	}

	if needMemset && !hasMemsetDecl(m) {
		insertMemsetDeclInModule(m)
	}
	return nil
}

// collectAllocSites finds all runtime.alloc call sites in a function and reports
// unparseable references as errors.
func collectAllocSites(fn *ir.Function, errs *[]error) []allocSite {
	var sites []allocSite
	for bi, block := range fn.Blocks {
		for ii, inst := range block.Instructions {
			if site, err := tryParseAllocSite(inst, bi, ii); err != nil {
				*errs = append(*errs, err)
			} else if site != nil {
				sites = append(sites, *site)
			}
		}
	}
	return sites
}

// tryParseAllocSite checks whether inst is a runtime.alloc call and extracts
// the alloc site parameters. Returns (nil, nil) for non-alloc instructions.
func tryParseAllocSite(inst *ir.Instruction, bi, ii int) (*allocSite, error) {
	allocErr := func() error {
		return fmt.Errorf("line references @runtime.alloc but does not match expected call pattern: %s",
			strings.TrimSpace(inst.Raw))
	}
	if inst.Kind == ir.InstOther && strings.Contains(inst.Raw, "@runtime.alloc") {
		return nil, allocErr()
	}
	if inst.Kind != ir.InstCall || inst.Call == nil || inst.Call.Callee != "@runtime.alloc" {
		return nil, nil
	}
	firstArg := firstCommaArg(inst.Call.Args)
	parts := strings.Fields(firstArg)
	if len(parts) < 2 || parts[0] != "i64" || inst.SSAName == "" {
		return nil, allocErr()
	}
	return &allocSite{blockIdx: bi, instIdx: ii, varName: inst.SSAName, size: parts[1]}, nil
}

// applyAllocReplacements rewrites alloc call sites to memset calls and inserts
// alloca instructions at the top of the entry block.
func applyAllocReplacements(fn *ir.Function, sites []allocSite) {
	for _, a := range sites {
		inst := fn.Blocks[a.blockIdx].Instructions[a.instIdx]
		inst.SSAName = ""
		inst.Call.Callee = "@" + memsetIntrinsicName
		inst.Call.RetType = "void"
		inst.Call.Args = fmt.Sprintf("ptr align 4 %s, i8 0, i64 %s, i1 false", a.varName, a.size)
		inst.Modified = true
	}

	entryBlock := fn.Blocks[0]
	newInsts := make([]*ir.Instruction, len(sites))
	for j, a := range sites {
		newInsts[j] = &ir.Instruction{
			SSAName:  a.varName,
			Kind:     ir.InstAlloca,
			Alloca:   &ir.AllocaInst{Type: fmt.Sprintf("[%s x i8]", a.size), Align: 4},
			Raw:      fmt.Sprintf("  %s = alloca [%s x i8], align 4", a.varName, a.size),
			Modified: true,
		}
	}
	entryBlock.Instructions = append(newInsts, entryBlock.Instructions...)
}

// hasMemsetDecl reports whether the module already declares llvm.memset.p0.i64.
func hasMemsetDecl(m *ir.Module) bool {
	for _, d := range m.Declares {
		if d.Name == memsetIntrinsicName && !d.Removed {
			return true
		}
	}
	for _, e := range m.Entries {
		if !e.Removed && strings.Contains(e.Raw, "@"+memsetIntrinsicName) {
			return true
		}
	}
	return false
}

// insertMemsetDeclInModule adds a declare for llvm.memset.p0.i64 if not already present.
func insertMemsetDeclInModule(m *ir.Module) {
	decl := &ir.Declare{
		Name:    memsetIntrinsicName,
		RetType: "void",
		Params:  "ptr, i8, i64, i1",
		Raw:     memsetDecl,
	}
	m.Declares = append(m.Declares, decl)

	insertIdx := findFirstFuncEntry(m)
	entry := ir.TopLevelEntry{Kind: ir.TopDeclare, Raw: memsetDecl, Declare: decl}
	blankEntry := ir.TopLevelEntry{Kind: ir.TopBlank, Raw: ""}

	if insertIdx >= 0 {
		m.Entries = slices.Insert(m.Entries, insertIdx, entry, blankEntry)
	} else {
		m.Entries = append(m.Entries, entry, blankEntry)
	}
}
