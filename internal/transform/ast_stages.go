package transform

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/kyleseneker/tinybpf/internal/ir"
)

// moduleStage pairs a name with an AST-based transform function.
type moduleStage struct {
	name string
	fn   func(*ir.Module) error
}

// buildModuleStages returns the ordered pipeline of AST-based IR transforms.
func buildModuleStages(opts Options) []moduleStage {
	return []moduleStage{
		{"retarget", retargetModule},
		{"strip-attributes", stripAttributesModule},
		{"extract-programs", func(m *ir.Module) error {
			return extractProgramsModule(m, opts.Programs, opts.Verbose, opts.Stdout)
		}},
		{"replace-alloc", replaceAllocModule},
		{"rewrite-helpers", rewriteHelpersModule},
		{"rewrite-core-access", rewriteCoreAccessModule},
		{"rewrite-core-exists", rewriteCoreExistsModule},
		{"assign-data-sections", assignDataSectionsModule},
		{"assign-program-sections", func(m *ir.Module) error {
			return assignProgramSectionsModule(m, opts.Sections)
		}},
		{"strip-map-prefix", stripMapPrefixModule},
		{"rewrite-map-btf", rewriteMapForBTFModule},
		{"sanitize-btf-names", sanitizeBTFNamesModule},
		{"sanitize-core-fields", sanitizeCoreFieldNamesModule},
		{"add-license", addLicenseModule},
		{"cleanup", cleanupModule},
	}
}

// runLineStage is a fallback that serializes the module, runs a legacy
// line-based stage, and re-parses the result.
func runLineStage(m *ir.Module, fn func([]string) ([]string, error)) (*ir.Module, error) {
	text := ir.Serialize(m)
	lines := strings.Split(text, "\n")
	lines, err := fn(lines)
	if err != nil {
		return nil, err
	}
	return ir.Parse(strings.Join(lines, "\n"))
}

const (
	bpfDatalayoutValue = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
	bpfTripleValue     = "bpf"
)

func retargetModule(m *ir.Module) error {
	m.DataLayout = bpfDatalayoutValue
	m.Triple = bpfTripleValue
	return nil
}

var (
	reAttrTargetCPU      = regexp.MustCompile(`"target-cpu"="[^"]*"`)
	reAttrTargetFeatures = regexp.MustCompile(`"target-features"="[^"]*"`)
	reAttrAllocKind      = regexp.MustCompile(`allockind\("[^"]*"\)`)
	reAttrAllocSize      = regexp.MustCompile(`allocsize\(\d+\)`)
	reAttrAllocFamily    = regexp.MustCompile(`"alloc-family"="[^"]*"`)
	reAttrMultiSpace     = regexp.MustCompile(`  +`)
)

func stripAttributesModule(m *ir.Module) error {
	for _, ag := range m.AttrGroups {
		body := ag.Body
		body = reAttrTargetCPU.ReplaceAllString(body, "")
		body = reAttrTargetFeatures.ReplaceAllString(body, "")
		body = reAttrAllocKind.ReplaceAllString(body, "")
		body = reAttrAllocSize.ReplaceAllString(body, "")
		body = reAttrAllocFamily.ReplaceAllString(body, "")
		body = reAttrMultiSpace.ReplaceAllString(body, " ")
		if body != ag.Body {
			ag.Body = body
			ag.Modified = true
		}
	}
	return nil
}

func extractProgramsModule(m *ir.Module, programNames []string, verbose bool, w io.Writer) error {
	if w == nil {
		w = io.Discard
	}
	programSet := make(map[string]bool)
	if len(programNames) > 0 {
		defined := make(map[string]bool, len(m.Functions))
		for _, fn := range m.Functions {
			defined[fn.Name] = true
		}
		var missing []string
		for _, n := range programNames {
			if !defined[n] {
				missing = append(missing, n)
			}
			programSet[n] = true
		}
		if len(missing) > 0 {
			available := make([]string, len(m.Functions))
			for i, fn := range m.Functions {
				available[i] = fn.Name
			}
			return fmt.Errorf("requested program(s) not found in IR: %v (available: %v)", missing, available)
		}
	} else {
		for _, fn := range m.Functions {
			if !isRuntimeFunc(fn.Name) {
				programSet[fn.Name] = true
			}
		}
	}
	if len(programSet) == 0 {
		names := make([]string, len(m.Functions))
		for i, fn := range m.Functions {
			names[i] = fn.Name
		}
		return fmt.Errorf("no program functions found among: %v", names)
	}
	if verbose {
		for name := range programSet {
			fmt.Fprintf(w, "[transform] keeping program: %s\n", name)
		}
	}
	for _, fn := range m.Functions {
		if !programSet[fn.Name] {
			fn.Removed = true
		}
	}
	for i := range m.Entries {
		entry := &m.Entries[i]
		if entry.Kind == ir.TopFunction && entry.Function != nil && entry.Function.Removed {
			entry.Removed = true
		}
	}
	for _, g := range m.Globals {
		if strings.HasPrefix(g.Name, "runtime.") || g.Name == ".string" ||
			strings.HasPrefix(g.Name, "__bpf_core_") {
			g.Modified = true
			markGlobalRemoved(m, g)
		}
	}
	return nil
}

func markGlobalRemoved(m *ir.Module, g *ir.Global) {
	for i := range m.Entries {
		if m.Entries[i].Global == g {
			m.Entries[i].Removed = true
			break
		}
	}
}

func replaceAllocModule(m *ir.Module, ) error {
	// Fall back to line-based for this complex transform
	result, err := runLineStage(m, replaceAlloc)
	if err != nil {
		return err
	}
	*m = *result
	return nil
}

func rewriteHelpersModule(m *ir.Module) error {
	result, err := runLineStage(m, rewriteHelpers)
	if err != nil {
		return err
	}
	*m = *result
	return nil
}

func rewriteCoreAccessModule(m *ir.Module) error {
	result, err := runLineStage(m, rewriteCoreAccess)
	if err != nil {
		return err
	}
	*m = *result
	return nil
}

func rewriteCoreExistsModule(m *ir.Module) error {
	result, err := runLineStage(m, rewriteCoreExistsChecks)
	if err != nil {
		return err
	}
	*m = *result
	return nil
}

func assignDataSectionsModule(m *ir.Module) error {
	for _, g := range m.Globals {
		if g.Section != "" {
			continue
		}
		if isRuntimeGlobal(g.Name) {
			continue
		}
		raw := g.Raw
		if strings.Contains(raw, "%main.bpfMapDef") {
			continue
		}
		section := classifyGlobalSectionFromAST(g)
		if section != "" {
			g.Section = section
			g.Modified = true
		}
	}
	return nil
}

func classifyGlobalSectionFromAST(g *ir.Global) string {
	if g.Initializer == "zeroinitializer" {
		return ".bss"
	}
	if strings.Contains(g.Linkage, "constant") {
		return ".rodata"
	}
	if strings.Contains(g.Linkage, "global") || g.Initializer != "" {
		return ".data"
	}
	return ""
}

func assignProgramSectionsModule(m *ir.Module, sections map[string]string) error {
	result, err := runLineStage(m, func(lines []string) ([]string, error) {
		return assignProgramSections(lines, sections)
	})
	if err != nil {
		return err
	}
	*m = *result
	return nil
}

func stripMapPrefixModule(m *ir.Module) error {
	result, err := runLineStage(m, stripMapPrefix)
	if err != nil {
		return err
	}
	*m = *result
	return nil
}

func rewriteMapForBTFModule(m *ir.Module) error {
	result, err := runLineStage(m, rewriteMapForBTF)
	if err != nil {
		return err
	}
	*m = *result
	return nil
}

func sanitizeBTFNamesModule(m *ir.Module) error {
	result, err := runLineStage(m, sanitizeBTFNames)
	if err != nil {
		return err
	}
	*m = *result
	return nil
}

func sanitizeCoreFieldNamesModule(m *ir.Module) error {
	result, err := runLineStage(m, sanitizeCoreFieldNames)
	if err != nil {
		return err
	}
	*m = *result
	return nil
}

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

	insertIdx := -1
	for i, e := range m.Entries {
		if e.Kind == ir.TopDeclare || e.Kind == ir.TopFunction {
			insertIdx = i
			break
		}
	}

	entry := ir.TopLevelEntry{
		Kind:    ir.TopGlobal,
		Global:  newGlobal,
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

func cleanupModule(m *ir.Module) error {
	result, err := runLineStage(m, cleanup)
	if err != nil {
		return err
	}
	*m = *result
	return nil
}
