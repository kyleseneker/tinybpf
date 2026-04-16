package transform

import (
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/kyleseneker/tinybpf/internal/ir"
)

const (
	bpfStackLimit      = 512
	stackWarnThreshold = 384
)

var allocaSizeRe = regexp.MustCompile(`alloca \[(\d+) x i8\]`)

// finalizeModule adds a GPL license if missing and removes unreferenced definitions.
func finalizeModule(m *ir.Module, w io.Writer) error {
	stripKfuncPrefixModule(m)
	stripAbortCallsModule(m, w)
	if err := addLicenseModule(m); err != nil {
		return err
	}
	return cleanupModule(m)
}

// stripAbortCallsModule removes `call void @abort()` instructions from function
// bodies. TinyGo pairs them with an `unreachable` terminator on panic and
// bounds-check paths; the terminator alone preserves semantics and is
// BPF-compatible, but the BPF llc backend rejects `abort`. A diagnostic is
// emitted when stripping happens so users see their code contains a
// TinyGo-flagged panic path -- if reachable at runtime the kernel verifier
// will reject the program with a clearer message. The now-unused
// `declare void @abort()` is pruned by removeUnreferencedDeclares later.
func stripAbortCallsModule(m *ir.Module, w io.Writer) {
	total := 0
	for _, fn := range m.Functions {
		if fn.Removed {
			continue
		}
		ir.EnsureBlocks(fn)
		count := 0
		for _, block := range fn.Blocks {
			kept := block.Instructions[:0]
			for _, inst := range block.Instructions {
				if inst.Kind == ir.InstCall && inst.Call != nil && inst.Call.Callee == "@abort" {
					count++
					continue
				}
				kept = append(kept, inst)
			}
			block.Instructions = kept
		}
		if count > 0 {
			fn.Modified = true
			total += count
		}
	}
	if total > 0 && w != nil {
		fmt.Fprintf(w, "[transform] stripped %d abort call(s) from TinyGo panic paths; "+
			"if reachable at runtime the BPF verifier will reject the program\n", total)
	}
}

// stripKfuncPrefixModule renames kfunc declarations and call sites from
// @main.bpfKfunc* to @bpfKfunc*, and strips the trailing TinyGo context
// pointer (ptr undef) from kfunc call arguments.
func stripKfuncPrefixModule(m *ir.Module) {
	var renames []mapRename
	for i := range m.Entries {
		e := &m.Entries[i]
		if e.Removed || e.Kind != ir.TopDeclare || e.Declare == nil {
			continue
		}
		if !strings.HasPrefix(e.Declare.Name, "main.bpfKfunc") {
			continue
		}
		oldName := e.Declare.Name
		newName := oldName[len("main."):]
		renames = append(renames, mapRename{
			oldRef: "@" + oldName,
			newRef: "@" + newName,
		})
		e.Declare.Name = newName
		e.Raw = strings.ReplaceAll(e.Raw, "@"+oldName, "@"+newName)
	}
	if len(renames) == 0 {
		return
	}
	for _, fn := range m.Functions {
		if fn.Removed {
			continue
		}
		ir.EnsureBlocks(fn)
		fn.Modified = true
		applyKfuncRenames(fn, renames)
	}
}

// applyKfuncRenames renames kfunc references in a function and strips the
// trailing TinyGo context pointer from their call arguments.
func applyKfuncRenames(fn *ir.Function, renames []mapRename) {
	for _, r := range renames {
		renameInFunction(fn, r.oldRef, r.newRef)
	}
	for _, block := range fn.Blocks {
		for _, inst := range block.Instructions {
			if inst.Kind != ir.InstCall || inst.Call == nil {
				continue
			}
			for _, r := range renames {
				if inst.Call.Callee == r.newRef {
					inst.Call.Args = stripTrailingUndef(inst.Call.Args)
					inst.Modified = true
				}
			}
		}
	}
}

// addLicenseModule inserts a GPL license global if one is not already present.
func addLicenseModule(m *ir.Module) error {
	for _, g := range m.Globals {
		if g.Section == "license" {
			return nil
		}
	}
	for _, e := range m.Entries {
		if e.Global != nil && strings.Contains(e.Raw, `section "license"`) {
			return nil
		}
	}
	newGlobal := &ir.Global{
		Name:        "_license",
		Linkage:     "global",
		Type:        "[4 x i8]",
		Initializer: `c"GPL\00"`,
		Section:     "license",
		Align:       1,
		Modified:    true,
	}
	m.Globals = append(m.Globals, newGlobal)

	insertIdx := findFirstFuncEntry(m)
	entry := ir.TopLevelEntry{
		Kind:   ir.TopGlobal,
		Global: newGlobal,
	}

	if insertIdx >= 0 {
		blankEntry := ir.TopLevelEntry{Kind: ir.TopBlank, Raw: ""}
		m.Entries = append(m.Entries[:insertIdx+2], m.Entries[insertIdx:]...)
		m.Entries[insertIdx] = entry
		m.Entries[insertIdx+1] = blankEntry
	} else {
		m.Entries = append(m.Entries, entry)
	}
	return nil
}

// cleanupModule removes unreferenced declares, globals, and attribute groups, then compacts entries.
func cleanupModule(m *ir.Module) error {
	identRefs := buildModuleIdentRefs(m)
	removeUnreferencedDeclares(m, identRefs)
	removeUnreferencedGlobals(m, identRefs)
	removeUnusedAttrGroups(m)
	markOrphanedAttrCommentsInModule(m)
	compactModuleEntries(m)
	return nil
}

// removeUnreferencedDeclares marks declare entries as removed if no other entry references them.
func removeUnreferencedDeclares(m *ir.Module, identRefs map[string][]int) {
	for i := range m.Entries {
		e := &m.Entries[i]
		if e.Removed {
			continue
		}
		if e.Declare != nil && e.Declare.Removed {
			e.Removed = true
			continue
		}
		if e.Kind == ir.TopDeclare && e.Declare != nil {
			name := "@" + e.Declare.Name
			if !identReferencedElsewhere(identRefs, name, i) {
				e.Removed = true
				if i > 0 && isAttrComment(m.Entries[i-1]) {
					m.Entries[i-1].Removed = true
				}
			}
		}
	}
}

// removeUnreferencedGlobals marks non-section globals as removed if no other entry references them.
func removeUnreferencedGlobals(m *ir.Module, identRefs map[string][]int) {
	for i := range m.Entries {
		e := &m.Entries[i]
		if e.Removed || e.Kind != ir.TopGlobal || e.Global == nil {
			continue
		}
		if e.Global.Section != "" || strings.Contains(e.Raw, " section ") {
			continue
		}
		name := "@" + e.Global.Name
		if !identReferencedElsewhere(identRefs, name, i) {
			e.Removed = true
		}
	}
}

// removeUnusedAttrGroups marks attribute groups as removed if no active entry references their ID.
func removeUnusedAttrGroups(m *ir.Module) {
	usedAttrs := collectUsedAttrIDsFromModule(m)
	for i := range m.Entries {
		e := &m.Entries[i]
		if e.Removed || e.Kind != ir.TopAttrGroup || e.AttrGroup == nil {
			continue
		}
		if !usedAttrs[e.AttrGroup.ID] {
			e.Removed = true
		}
	}
}

// buildModuleIdentRefs scans all entries and builds a map of @-identifier to entry indices.
func buildModuleIdentRefs(m *ir.Module) map[string][]int {
	refs := make(map[string][]int)
	for i, e := range m.Entries {
		if e.Removed {
			continue
		}
		for _, line := range entryTextLines(e) {
			for pos := 0; pos < len(line); pos++ {
				if line[pos] != '@' {
					continue
				}
				j := pos + 1
				for j < len(line) && isIdentCharByte(line[j]) {
					j++
				}
				if j > pos+1 {
					ident := line[pos:j]
					refs[ident] = append(refs[ident], i)
					pos = j - 1
				}
			}
		}
	}
	return refs
}

// identReferencedElsewhere reports whether name appears in any entry other than defIdx.
func identReferencedElsewhere(refs map[string][]int, name string, defIdx int) bool {
	for _, idx := range refs[name] {
		if idx != defIdx {
			return true
		}
	}
	return false
}

// isAttrComment reports whether the entry is a "; Function Attrs:" comment.
func isAttrComment(e ir.TopLevelEntry) bool {
	return !e.Removed && e.Kind == ir.TopComment &&
		strings.Contains(e.Raw, "; Function Attrs:")
}

// collectUsedAttrIDsFromModule returns the set of attribute group IDs (#N) referenced by active entries.
func collectUsedAttrIDsFromModule(m *ir.Module) map[string]bool {
	used := make(map[string]bool)
	for _, e := range m.Entries {
		if e.Removed || e.Kind == ir.TopAttrGroup {
			continue
		}
		for _, line := range entryTextLines(e) {
			for pos := range len(line) {
				if line[pos] != '#' {
					continue
				}
				j := pos + 1
				for j < len(line) && line[j] >= '0' && line[j] <= '9' {
					j++
				}
				if j > pos+1 {
					used[line[pos+1:j]] = true
				}
			}
		}
	}
	return used
}

// markOrphanedAttrCommentsInModule removes "; Function Attrs:" comments not followed by a function or declare.
func markOrphanedAttrCommentsInModule(m *ir.Module) {
	for i := range m.Entries {
		e := &m.Entries[i]
		if e.Removed || !isAttrComment(*e) {
			continue
		}
		hasTarget := false
		for j := i + 1; j < len(m.Entries); j++ {
			if m.Entries[j].Removed {
				continue
			}
			if m.Entries[j].Kind == ir.TopBlank {
				continue
			}
			if m.Entries[j].Kind == ir.TopFunction || m.Entries[j].Kind == ir.TopDeclare {
				hasTarget = true
			}
			break
		}
		if !hasTarget {
			e.Removed = true
		}
	}
}

// compactModuleEntries removes flagged entries and collapses consecutive blank lines.
func compactModuleEntries(m *ir.Module) {
	n := 0
	prevBlank := false
	for _, e := range m.Entries {
		if e.Removed {
			continue
		}
		blank := e.Kind == ir.TopBlank
		if blank && prevBlank {
			continue
		}
		m.Entries[n] = e
		n++
		prevBlank = blank
	}
	m.Entries = m.Entries[:n]
	for len(m.Entries) > 0 && m.Entries[len(m.Entries)-1].Kind == ir.TopBlank {
		m.Entries = m.Entries[:len(m.Entries)-1]
	}
	m.Entries = append(m.Entries, ir.TopLevelEntry{Kind: ir.TopBlank, Raw: ""})
}

// warnStackUsage estimates per-function stack usage from alloca instructions
// and warns when it approaches the 512-byte BPF stack limit.
func warnStackUsage(m *ir.Module, w io.Writer) {
	for _, fn := range m.Functions {
		if fn.Removed {
			continue
		}
		ir.EnsureBlocks(fn)
		var total int64
		for _, block := range fn.Blocks {
			for _, inst := range block.Instructions {
				if inst.Kind != ir.InstAlloca || inst.Alloca == nil {
					continue
				}
				// Extract array size from types like "[16 x i8]"
				if locs := allocaSizeRe.FindStringSubmatch(inst.Raw); locs != nil {
					n, err := strconv.ParseInt(locs[1], 10, 64)
					if err == nil {
						total += n
					}
				}
			}
		}
		if total >= stackWarnThreshold {
			fmt.Fprintf(w, "[transform] %s: estimated stack usage ~%d bytes (BPF limit is %d); consider reducing local variable size or using map storage\n",
				fn.Name, total, bpfStackLimit)
		}
	}
}
