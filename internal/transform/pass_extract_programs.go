package transform

import (
	"fmt"
	"io"
	"strings"

	"github.com/kyleseneker/tinybpf/internal/ir"
)

// extractProgramsModule keeps only the specified BPF program functions and removes runtime functions.
func extractProgramsModule(m *ir.Module, programNames []string, verbose bool, w io.Writer) error {
	if w == nil {
		w = io.Discard
	}
	programSet, err := buildProgramSet(m, programNames)
	if err != nil {
		return err
	}
	if verbose {
		for name := range programSet {
			fmt.Fprintf(w, "[transform] keeping program: %s\n", name)
		}
	}
	if len(programNames) == 0 && len(programSet) > 1 {
		names := make([]string, 0, len(programSet))
		for name := range programSet {
			names = append(names, name)
		}
		fmt.Fprintf(w, "[transform] auto-detected %d programs: %v (use --programs to select explicitly)\n",
			len(names), names)
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
	markRuntimeGlobalsRemoved(m)
	return nil
}

// buildProgramSet resolves which functions to keep based on explicit names or auto-detection.
func buildProgramSet(m *ir.Module, programNames []string) (map[string]bool, error) {
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
			return nil, fmt.Errorf("requested program(s) not found in IR: %v (available: %v)", missing, available)
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
		return nil, fmt.Errorf("no program functions found among: %v", names)
	}
	return programSet, nil
}

// markRuntimeGlobalsRemoved flags runtime-internal globals for removal.
func markRuntimeGlobalsRemoved(m *ir.Module) {
	for _, g := range m.Globals {
		if strings.HasPrefix(g.Name, "runtime.") || g.Name == ".string" ||
			strings.HasPrefix(g.Name, "__bpf_core_") {
			g.Modified = true
			markGlobalRemoved(m, g)
		}
	}
}

// markGlobalRemoved flags the module entry associated with the given global as removed.
func markGlobalRemoved(m *ir.Module, g *ir.Global) {
	for i := range m.Entries {
		if m.Entries[i].Global == g {
			m.Entries[i].Removed = true
			break
		}
	}
}
