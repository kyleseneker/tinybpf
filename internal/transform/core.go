package transform

import (
	"fmt"
	"regexp"
	"strings"
)

// reCoreGEP matches getelementptr instructions on bpfCore-annotated struct types.
var reCoreGEP = regexp.MustCompile(
	`^(\s*(%[\w.]+)\s*=\s*)getelementptr\s+(?:[A-Za-z0-9_().]+\s+)*(%main\.bpfCore[\w.]*),\s*ptr\s+(%[\w.]+),\s*i32\s+0,\s*i32\s+(\d+)(.*)$`)

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

		repl := fmt.Sprintf("%s%s",
			assign, preserveStructAccessCall(base, typeName, fieldIdx, fieldIdx))
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

// preserveStructAccessCall formats a call to llvm.preserve.struct.access.index
// with an explicit elementtype(...) attribute required by LLVM 20+.
func preserveStructAccessCall(base, elementType, gepIndex, diIndex string) string {
	return fmt.Sprintf("call ptr %s(ptr elementtype(%s) %s, i32 %s, i32 %s)",
		coreIntrinsicName, elementType, base, gepIndex, diIndex)
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
