package transform

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// reCoreGEP matches getelementptr instructions on bpfCore-annotated struct types.
var reCoreGEP = regexp.MustCompile(
	`^(\s*(%[\w.]+)\s*=\s*)getelementptr\s+(?:inbounds\s+)?(%main\.bpfCore[\w.]*),\s*ptr\s+(%[\w.]+),\s*i32\s+0,\s*i32\s+(\d+)(.*)$`)

// reCoreExistsCall matches calls to bpfCoreFieldExists or bpfCoreTypeExists.
var reCoreExistsCall = regexp.MustCompile(
	`(call\s+i32\s+)@main\.(bpfCoreFieldExists|bpfCoreTypeExists)\(([^)]*)\)`)

const coreIntrinsicDecl = "declare ptr @llvm.preserve.struct.access.index.p0.p0(ptr, i32 immarg, i32 immarg)"
const coreIntrinsicName = "@llvm.preserve.struct.access.index.p0.p0"

const fieldInfoIntrinsicDecl = "declare i32 @llvm.bpf.preserve.field.info.p0(ptr, i64 immarg)"
const typeInfoIntrinsicDecl = "declare i32 @llvm.bpf.preserve.type.info.p0(ptr, i64 immarg)"

// rewriteCoreAccess replaces getelementptr instructions that access
// bpfCore-prefixed struct fields with llvm.preserve.struct.access.index
// intrinsic calls, enabling CO-RE field offset relocations in the final ELF.
func rewriteCoreAccess(lines []string) ([]string, error) {
	coreTypes, err := findCoreTypes(lines)
	if err != nil {
		return nil, err
	}
	if len(coreTypes) == 0 {
		return lines, nil
	}

	typeMeta, err := findCoreTypeMetadata(lines, coreTypes)
	if err != nil {
		return nil, err
	}

	modified := false
	for i, line := range lines {
		if !strings.Contains(line, "getelementptr") || !strings.Contains(line, "bpfCore") {
			continue
		}
		m := reCoreGEP.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("line %d has getelementptr on bpfCore type but does not match expected GEP pattern: %s",
				i+1, strings.TrimSpace(line))
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
		return lines, nil
	}

	return addCoreIntrinsicDecl(lines), nil
}

// findCoreTypes scans for type definitions matching %main.bpfCore*.
func findCoreTypes(lines []string) (map[string]bool, error) {
	types := make(map[string]bool)
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, "bpfCore") || !strings.Contains(trimmed, "= type {") {
			continue
		}
		idx := strings.Index(trimmed, " = type {")
		if idx <= 0 {
			return nil, fmt.Errorf("line %d contains bpfCore type definition but name could not be parsed: %s",
				i+1, trimmed)
		}
		name := trimmed[:idx]
		if strings.HasPrefix(name, "%main.bpfCore") {
			types[name] = true
		}
	}
	return types, nil
}

// findCoreTypeMetadata locates DICompositeType metadata IDs for core-annotated structs.
func findCoreTypeMetadata(lines []string, coreTypes map[string]bool) (map[string]int, error) {
	meta := make(map[string]int)
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, "DICompositeType") ||
			!strings.Contains(trimmed, "DW_TAG_structure_type") ||
			!strings.Contains(trimmed, "bpfCore") {
			continue
		}
		id := extractMetadataID(trimmed)
		if id < 0 {
			return nil, fmt.Errorf("line %d has bpfCore DICompositeType but metadata ID could not be parsed: %s",
				i+1, trimmed)
		}
		for typeName := range coreTypes {
			goName := strings.TrimPrefix(typeName, "%")
			if strings.Contains(trimmed, fmt.Sprintf(`name: "%s"`, goName)) {
				meta[typeName] = id
				break
			}
		}
	}
	return meta, nil
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

// sanitizeCoreFieldNames converts Go CamelCase field and type names in
// bpfCore struct metadata to kernel-compatible snake_case names so that
// CO-RE relocations can match the running kernel's BTF.
func sanitizeCoreFieldNames(lines []string) ([]string, error) {
	coreMetaIDs, err := findCoreCompositeIDs(lines)
	if err != nil {
		return nil, err
	}
	if len(coreMetaIDs) == 0 {
		return lines, nil
	}
	coreMemberIDs := collectReferencedIDs(lines)

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		id := extractMetadataID(trimmed)
		if id < 0 {
			continue
		}
		if coreMetaIDs[id] {
			lines[i] = renameCoreType(line)
		} else if coreMemberIDs[id] && isMemberMeta(trimmed) {
			lines[i] = renameCoreField(line)
		}
	}
	return lines, nil
}

// findCoreCompositeIDs returns metadata IDs for bpfCore DICompositeType entries.
func findCoreCompositeIDs(lines []string) (map[int]bool, error) {
	ids := make(map[int]bool)
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, "DICompositeType") ||
			!strings.Contains(trimmed, "DW_TAG_structure_type") ||
			!strings.Contains(trimmed, "bpfCore") {
			continue
		}
		id := extractMetadataID(trimmed)
		if id < 0 {
			return nil, fmt.Errorf("line %d has bpfCore DICompositeType but metadata ID could not be parsed: %s",
				i+1, trimmed)
		}
		ids[id] = true
	}
	return ids, nil
}

// collectReferencedIDs extracts all numeric !N references from bpfCore
// DICompositeType lines to identify member metadata IDs.
func collectReferencedIDs(lines []string) map[int]bool {
	ids := make(map[int]bool)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, "DICompositeType") || !strings.Contains(trimmed, "bpfCore") {
			continue
		}
		for _, seg := range strings.Split(trimmed, "!") {
			seg = strings.TrimSpace(seg)
			if n := parseLeadingInt(seg); n >= 0 {
				ids[n] = true
			}
		}
	}
	return ids
}

// parseLeadingInt extracts a leading integer from s if s starts with digits
// followed by non-digits. Returns -1 on failure.
func parseLeadingInt(s string) int {
	if len(s) == 0 {
		return -1
	}
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 || end == len(s) {
		return -1
	}
	n, err := strconv.Atoi(s[:end])
	if err != nil {
		return -1
	}
	return n
}

// isMemberMeta reports whether a trimmed metadata line is a DW_TAG_member DIDerivedType.
func isMemberMeta(trimmed string) bool {
	return strings.Contains(trimmed, "DIDerivedType") && strings.Contains(trimmed, "DW_TAG_member")
}

// renameCoreType converts a bpfCore struct type name to a kernel-style name.
// "main_bpfCoreTaskStruct" -> "task_struct"
func renameCoreType(line string) string {
	const prefix = `name: "`
	idx := strings.Index(line, prefix)
	if idx < 0 {
		return line
	}
	start := idx + len(prefix)
	end := strings.IndexByte(line[start:], '"')
	if end < 0 {
		return line
	}
	end += start
	name := line[start:end]

	stripped := name
	if i := strings.Index(stripped, "bpfCore"); i >= 0 {
		stripped = stripped[i+len("bpfCore"):]
	}
	if stripped == "" {
		return line
	}
	return line[:start] + camelToSnake(stripped) + line[end:]
}

// renameCoreField converts a Go CamelCase field name to snake_case.
// name: "Pid" -> name: "pid", name: "LoginUid" -> name: "login_uid"
func renameCoreField(line string) string {
	const prefix = `name: "`
	idx := strings.Index(line, prefix)
	if idx < 0 {
		return line
	}
	start := idx + len(prefix)
	end := strings.IndexByte(line[start:], '"')
	if end < 0 {
		return line
	}
	end += start
	name := line[start:end]
	return line[:start] + camelToSnake(name) + line[end:]
}

// rewriteCoreExistsChecks rewrites bpfCoreFieldExists/bpfCoreTypeExists
// calls to their corresponding llvm.bpf.preserve intrinsics.
func rewriteCoreExistsChecks(lines []string) ([]string, error) {
	needField := false
	needType := false
	for i, line := range lines {
		if !strings.Contains(line, "@main.bpfCore") {
			continue
		}
		m := reCoreExistsCall.FindStringSubmatchIndex(line)
		if m == nil {
			if strings.Contains(line, "Exists") && strings.Contains(line, "call") {
				return nil, fmt.Errorf("line %d references a bpfCore*Exists function but does not match expected call pattern: %s",
					i+1, strings.TrimSpace(line))
			}
			continue
		}
		callPrefix := line[m[0]:m[3]]
		funcName := line[m[4]:m[5]]
		args := stripTrailingUndef(strings.TrimSpace(line[m[6]:m[7]]))

		var intrinsic string
		switch funcName {
		case "bpfCoreFieldExists":
			intrinsic = "@llvm.bpf.preserve.field.info.p0"
			needField = true
		case "bpfCoreTypeExists":
			intrinsic = "@llvm.bpf.preserve.type.info.p0"
			needType = true
		default:
			continue
		}
		repl := fmt.Sprintf("%s%s(%s, i64 0)", callPrefix, intrinsic, args)
		lines[i] = line[:m[0]] + repl + line[m[1]:]
	}

	if needField {
		lines = addIntrinsicDecl(lines, "llvm.bpf.preserve.field.info", fieldInfoIntrinsicDecl)
	}
	if needType {
		lines = addIntrinsicDecl(lines, "llvm.bpf.preserve.type.info", typeInfoIntrinsicDecl)
	}

	lines = stripCoreExistsDeclarations(lines)
	return lines, nil
}

// stripCoreExistsDeclarations removes the Go-generated declare lines for
// bpfCoreFieldExists/bpfCoreTypeExists (they are replaced by intrinsics).
func stripCoreExistsDeclarations(lines []string) []string {
	result := lines[:0:0]
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "declare") &&
			(strings.Contains(trimmed, "@main.bpfCoreFieldExists") ||
				strings.Contains(trimmed, "@main.bpfCoreTypeExists")) {
			continue
		}
		result = append(result, line)
	}
	if len(result) < len(lines) {
		return result
	}
	return lines
}

// addIntrinsicDecl adds a declare line if one with the given name isn't already present.
func addIntrinsicDecl(lines []string, name, decl string) []string {
	if hasDeclare(lines, name) {
		return lines
	}
	return insertBeforeFunc(lines, decl)
}

// addCoreIntrinsicDecl adds the llvm.preserve.struct.access.index declaration
// if it isn't already present.
func addCoreIntrinsicDecl(lines []string) []string {
	return addIntrinsicDecl(lines, "llvm.preserve.struct.access.index", coreIntrinsicDecl)
}
