package transform

import (
	"strings"
)

// assignDataSections adds BPF data section attributes to user-defined global
// variables so they appear in .data, .rodata, or .bss. Globals that already
// have a section assignment (e.g. maps in ".maps") are left unchanged.
func assignDataSections(lines []string) []string {
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		name, ok := parseGlobalName(trimmed)
		if !ok {
			continue
		}
		if strings.Contains(trimmed, " section ") {
			continue
		}
		if isRuntimeGlobal(name) || isMapGlobal(trimmed) {
			continue
		}
		section := classifyGlobalSection(trimmed)
		if section == "" {
			continue
		}
		lines[i] = insertSectionAttr(line, section)
	}
	return lines
}

// classifyGlobalSection determines the BPF data section for a global.
func classifyGlobalSection(trimmed string) string {
	if isZeroInitialized(trimmed) {
		return ".bss"
	}
	if isConstantGlobal(trimmed) {
		return ".rodata"
	}
	if hasInitializer(trimmed) {
		return ".data"
	}
	return ""
}

func isRuntimeGlobal(name string) bool {
	for _, prefix := range []string{"runtime.", "internal/", "reflect.", ".string", "llvm."} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func isMapGlobal(trimmed string) bool {
	return strings.Contains(trimmed, "%main.bpfMapDef")
}

func isZeroInitialized(trimmed string) bool {
	return strings.Contains(trimmed, " zeroinitializer")
}

func isConstantGlobal(trimmed string) bool {
	return strings.Contains(trimmed, " constant ")
}

func hasInitializer(trimmed string) bool {
	for _, tok := range []string{" global ", " addrspace("} {
		if strings.Contains(trimmed, tok) {
			return true
		}
	}
	return false
}

// insertSectionAttr adds `, section ".name"` before the alignment or trailing comma.
func insertSectionAttr(line, section string) string {
	if idx := strings.Index(line, ", align "); idx >= 0 {
		return line[:idx] + `, section "` + section + `"` + line[idx:]
	}
	return strings.TrimRight(line, " \t") + `, section "` + section + `"`
}
