package transform

import (
	"fmt"
	"regexp"
	"strings"
)

// reCoreGEP matches getelementptr instructions on bpfCore-annotated struct types.
var reCoreGEP = regexp.MustCompile(
	`^(\s*(%[\w.]+)\s*=\s*)getelementptr\s+(?:inbounds\s+)?(%main\.bpfCore[\w.]*),\s*ptr\s+(%[\w.]+),\s*i32\s+0,\s*i32\s+(\d+)(.*)$`)

const coreIntrinsicDecl = "declare ptr @llvm.preserve.struct.access.index.p0.p0(ptr, i32 immarg, i32 immarg)"
const coreIntrinsicName = "@llvm.preserve.struct.access.index.p0.p0"

// rewriteCoreAccess replaces getelementptr instructions that access
// bpfCore-prefixed struct fields with llvm.preserve.struct.access.index
// intrinsic calls, enabling CO-RE field offset relocations in the final ELF.
func rewriteCoreAccess(lines []string) []string {
	coreTypes := findCoreTypes(lines)
	if len(coreTypes) == 0 {
		return lines
	}

	typeMeta := findCoreTypeMetadata(lines, coreTypes)

	modified := false
	for i, line := range lines {
		m := reCoreGEP.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		typeName := m[3]
		if _, ok := coreTypes[typeName]; !ok {
			continue
		}
		assign := m[1]
		base := m[4]
		fieldIdx := m[5]
		trailing := m[6]

		repl := fmt.Sprintf("%scall ptr %s(ptr %s, i32 %s, i32 %s)",
			assign, coreIntrinsicName, base, fieldIdx, fieldIdx)
		if metaID, ok := typeMeta[typeName]; ok {
			repl += fmt.Sprintf(", !llvm.preserve.access.index !%d", metaID)
		}
		if dbg := extractDBG(trailing); dbg != "" {
			repl += ", " + dbg
		}
		lines[i] = repl
		modified = true
	}

	if !modified {
		return lines
	}

	return addCoreIntrinsicDecl(lines)
}

// findCoreTypes scans for type definitions matching %main.bpfCore*.
func findCoreTypes(lines []string) map[string]bool {
	types := make(map[string]bool)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, "bpfCore") || !strings.Contains(trimmed, "= type {") {
			continue
		}
		idx := strings.Index(trimmed, " = type {")
		if idx <= 0 {
			continue
		}
		name := trimmed[:idx]
		if strings.HasPrefix(name, "%main.bpfCore") {
			types[name] = true
		}
	}
	return types
}

// findCoreTypeMetadata locates DICompositeType metadata IDs for core-annotated structs.
func findCoreTypeMetadata(lines []string, coreTypes map[string]bool) map[string]int {
	meta := make(map[string]int)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, "DICompositeType") ||
			!strings.Contains(trimmed, "DW_TAG_structure_type") ||
			!strings.Contains(trimmed, "bpfCore") {
			continue
		}
		id := extractMetadataID(trimmed)
		if id < 0 {
			continue
		}
		for typeName := range coreTypes {
			goName := strings.TrimPrefix(typeName, "%")
			if strings.Contains(trimmed, fmt.Sprintf(`name: "%s"`, goName)) {
				meta[typeName] = id
				break
			}
		}
	}
	return meta
}

// extractDBG pulls a !dbg !N reference from trailing GEP text.
func extractDBG(s string) string {
	idx := strings.Index(s, "!dbg ")
	if idx < 0 {
		return ""
	}
	end := idx + 5
	for end < len(s) && (s[end] == '!' || (s[end] >= '0' && s[end] <= '9')) {
		end++
	}
	return s[idx:end]
}

// addCoreIntrinsicDecl adds the llvm.preserve.struct.access.index declaration
// if it isn't already present.
func addCoreIntrinsicDecl(lines []string) []string {
	if hasDeclare(lines, "llvm.preserve.struct.access.index") {
		return lines
	}
	return insertBeforeFunc(lines, coreIntrinsicDecl)
}
