package transform

import (
	"strings"

	"github.com/kyleseneker/tinybpf/internal/ir"
)

// sectionsPassModule assigns ELF sections to globals and program functions in a single pass.
func sectionsPassModule(m *ir.Module, sections map[string]string) error {
	if err := assignDataSectionsModule(m); err != nil {
		return err
	}
	return assignProgramSectionsModule(m, sections)
}

// assignDataSectionsModule assigns .data, .bss, or .rodata sections to globals that lack one.
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

// classifyGlobalSectionFromAST returns the ELF section name for a global based on its linkage.
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

// assignProgramSectionsModule adds ELF section attributes to function definitions and map globals.
func assignProgramSectionsModule(m *ir.Module, sections map[string]string) error {
	for i := range m.Entries {
		e := &m.Entries[i]
		if e.Removed {
			continue
		}
		if e.Kind == ir.TopFunction && e.Function != nil && !e.Function.Removed {
			fn := e.Function
			sec := ""
			if sections != nil {
				sec = sections[fn.Name]
			}
			if sec == "" {
				sec = fn.Name
			}
			if !strings.Contains(fn.Raw, " section ") {
				fn.Raw = insertSection(fn.Raw, sec)
			}
		}
		if e.Kind == ir.TopGlobal && e.Global != nil && strings.Contains(e.Raw, "bpfMapDef") {
			e.Raw = strings.Replace(e.Raw, " internal ", " ", 1)
			if !strings.Contains(e.Raw, " section ") {
				e.Raw = insertSectionAttr(e.Raw, ".maps")
			}
		}
	}
	return nil
}
