package transform

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// mapFieldInfo pairs a libbpf field name with its Go-source name.
type mapFieldInfo struct {
	goName string
	cName  string
}

// mapFields5 is the standard 5-field bpfMapDef layout.
var mapFields5 = []mapFieldInfo{
	{"Type", "type"},
	{"KeySize", "key_size"},
	{"ValueSize", "value_size"},
	{"MaxEntries", "max_entries"},
	{"MapFlags", "map_flags"},
}

// mapFields6 extends the standard layout with an optional 6th pinning field.
var mapFields6 = []mapFieldInfo{
	{"Type", "type"},
	{"KeySize", "key_size"},
	{"ValueSize", "value_size"},
	{"MaxEntries", "max_entries"},
	{"MapFlags", "map_flags"},
	{"Pinning", "pinning"},
}

var reMapGlobal = regexp.MustCompile(
	`^@([\w.]+)\s*=\s*(global|internal global)\s+%[\w.]*bpfMapDef\s*\{\s*(.*?)\}`)

// reMapGlobalZero matches zeroinitializer map globals (all fields default to 0).
var reMapGlobalZero = regexp.MustCompile(
	`^@([\w.]+)\s*=\s*(global|internal global)\s+%[\w.]*bpfMapDef\s+zeroinitializer`)

type mapDef struct {
	lineIdx int
	name    string
	values  []int
}

// rewriteMapForBTF rewrites bpfMapDef map globals and their debug metadata to use the libbpf-compatible BTF encoding.
// Supports both 5-field (standard) and 6-field (with pinning) bpfMapDef layouts.
func rewriteMapForBTF(lines []string) []string {
	fieldCount := detectMapFieldCount(lines)
	maps := collectMapDefs(lines, fieldCount)
	if len(maps) == 0 {
		return lines
	}

	mapFields := mapFields5
	if fieldCount == 6 {
		mapFields = mapFields6
	}

	maxMeta := findMaxMetadataID(lines)
	for _, md := range maps {
		var nextID int
		lines, nextID = processMapDef(lines, md, mapFields, fieldCount, maxMeta)
		maxMeta = nextID
	}

	return lines
}

// collectMapDefs scans lines for bpfMapDef globals (both initialized and zeroinitializer forms).
func collectMapDefs(lines []string, fieldCount int) []mapDef {
	var maps []mapDef
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if m := reMapGlobal.FindStringSubmatch(trimmed); m != nil {
			vals := parseI32Initializer(m[3])
			if len(vals) != fieldCount {
				continue
			}
			maps = append(maps, mapDef{lineIdx: i, name: m[1], values: vals})
			continue
		}
		if mz := reMapGlobalZero.FindStringSubmatch(trimmed); mz != nil {
			maps = append(maps, mapDef{lineIdx: i, name: mz[1], values: make([]int, fieldCount)})
		}
	}
	return maps
}

// processMapDef rewrites a single map definition's global declaration,
// type definition, and debug metadata for BTF compatibility. Returns
// the updated lines and the next available metadata ID.
func processMapDef(lines []string, md mapDef, mapFields []mapFieldInfo, fieldCount, maxMeta int) ([]string, int) {
	nextID := maxMeta + 1

	intTypeID := nextID
	nextID++
	newMeta := []string{
		fmt.Sprintf("!%d = !DIBasicType(name: \"int\", size: 32, encoding: DW_ATE_signed)", intTypeID),
	}

	fieldPtrIDs := make([]int, fieldCount)
	for fi := range mapFields {
		subrangeID := nextID
		nextID++
		arrayID := nextID
		nextID++
		ptrID := nextID
		nextID++
		fieldPtrIDs[fi] = ptrID

		val := md.values[fi]
		newMeta = append(newMeta,
			fmt.Sprintf("!%d = !DISubrange(count: %d)", subrangeID, val),
			fmt.Sprintf("!%d = !DICompositeType(tag: DW_TAG_array_type, baseType: !%d, elements: !{!%d})",
				arrayID, intTypeID, subrangeID),
			fmt.Sprintf("!%d = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !%d, size: 64)",
				ptrID, arrayID),
		)
	}

	rewriteMemberNodes(lines, mapFields, fieldPtrIDs)
	rewriteStructSize(lines, fieldCount)
	rewriteMapGlobal(lines, md, fieldCount)
	rewriteMapTypeDef(lines, fieldCount)

	lines = appendMetadata(lines, newMeta)
	return lines, nextID
}

// rewriteMemberNodes updates DIDerivedType member nodes to use libbpf
// field names, pointer-sized base types, and 64-bit offsets.
func rewriteMemberNodes(lines []string, mapFields []mapFieldInfo, fieldPtrIDs []int) {
	for i, line := range lines {
		if !strings.Contains(line, "DIDerivedType") || !strings.Contains(line, "DW_TAG_member") {
			continue
		}
		for fi, mf := range mapFields {
			goKey := fmt.Sprintf(`name: "%s"`, mf.goName)
			if !strings.Contains(line, goKey) {
				continue
			}
			newLine := strings.Replace(line, goKey, fmt.Sprintf(`name: "%s"`, mf.cName), 1)
			newLine = reBaseType.ReplaceAllString(newLine,
				fmt.Sprintf("baseType: !%d", fieldPtrIDs[fi]))
			newLine = reMemberSize.ReplaceAllString(newLine, "size: 64")
			newLine = reMemberOffset.ReplaceAllString(newLine,
				fmt.Sprintf("offset: %d", fi*64))
			lines[i] = newLine
			break
		}
	}
}

// rewriteStructSize updates the DICompositeType struct size from the
// original i32-based layout to the pointer-based layout.
func rewriteStructSize(lines []string, fieldCount int) {
	origStructSize := fmt.Sprintf("%d", fieldCount*32)
	newStructSize := fmt.Sprintf("%d", fieldCount*64)
	reOldStructSize := regexp.MustCompile(`size:\s*` + origStructSize)

	typedefTarget := ""
	for _, line := range lines {
		if strings.Contains(line, "DW_TAG_typedef") && strings.Contains(line, "bpfMapDef") {
			if m := reBaseType.FindString(line); m != "" {
				typedefTarget = strings.TrimPrefix(m, "baseType: ")
				break
			}
		}
	}
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		isTarget := typedefTarget != "" && strings.HasPrefix(trimmed, typedefTarget+" ")
		if isTarget || (strings.Contains(line, "DICompositeType") &&
			strings.Contains(line, "DW_TAG_structure_type") &&
			strings.Contains(line, "bpfMapDef")) {
			lines[i] = reOldStructSize.ReplaceAllString(line, "size: "+newStructSize)
		}
	}
}

// rewriteMapGlobal replaces the original map global declaration with a
// pointer-field zeroinitializer form.
func rewriteMapGlobal(lines []string, md mapDef, fieldCount int) {
	ptrFields := strings.TrimSuffix(strings.Repeat("ptr, ", fieldCount), ", ")
	replacement := fmt.Sprintf("@%s = global { %s } zeroinitializer", md.name, ptrFields)

	origLine := lines[md.lineIdx]
	trimmedOrig := strings.TrimSpace(origLine)
	newGlobal := reMapGlobal.ReplaceAllStringFunc(trimmedOrig, func(string) string {
		return replacement
	})
	if newGlobal == trimmedOrig {
		newGlobal = reMapGlobalZero.ReplaceAllStringFunc(trimmedOrig, func(string) string {
			return replacement
		})
	}
	newGlobal = strings.Replace(newGlobal, "align 4", "align 8", 1)
	lines[md.lineIdx] = newGlobal
}

// rewriteMapTypeDef replaces the bpfMapDef type definition fields from
// i32 to ptr.
func rewriteMapTypeDef(lines []string, fieldCount int) {
	ptrFields := strings.TrimSuffix(strings.Repeat("ptr, ", fieldCount), ", ")
	origI32Fields := strings.TrimSuffix(strings.Repeat("i32, ", fieldCount), ", ")
	for i, line := range lines {
		if strings.Contains(line, "bpfMapDef") && strings.Contains(line, "= type {") {
			lines[i] = strings.Replace(line, "{ "+origI32Fields+" }", "{ "+ptrFields+" }", 1)
		}
	}
}

// appendMetadata inserts new metadata lines before any trailing blanks.
func appendMetadata(lines []string, newMeta []string) []string {
	insertIdx := len(lines)
	for insertIdx > 0 && strings.TrimSpace(lines[insertIdx-1]) == "" {
		insertIdx--
	}
	result := make([]string, 0, len(lines)+len(newMeta)+1)
	result = append(result, lines[:insertIdx]...)
	result = append(result, "")
	result = append(result, newMeta...)
	result = append(result, lines[insertIdx:]...)
	return result
}

var (
	reBaseType     = regexp.MustCompile(`baseType:\s*!\d+`)
	reMemberSize   = regexp.MustCompile(`size:\s*\d+`)
	reMemberOffset = regexp.MustCompile(`offset:\s*\d+`)

	reMapDefType = regexp.MustCompile(`%[\w.]*bpfMapDef\s*=\s*type\s*\{([^}]+)\}`)
)

// detectMapFieldCount determines whether the bpfMapDef struct has 5 or 6 fields
// by inspecting the type definition. Returns 5 (standard) or 6 (with pinning).
func detectMapFieldCount(lines []string) int {
	for _, line := range lines {
		m := reMapDefType.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		fields := strings.Split(m[1], ",")
		if len(fields) == 6 {
			return 6
		}
		return 5
	}
	return 5
}

// parseI32Initializer extracts integer values from an LLVM IR struct initializer.
func parseI32Initializer(s string) []int {
	parts := strings.Split(s, ",")
	var vals []int
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.TrimPrefix(p, "i32 ")
		p = strings.TrimSpace(p)
		v, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		vals = append(vals, v)
	}
	return vals
}

// findMaxMetadataID scans for the highest numbered metadata node.
func findMaxMetadataID(lines []string) int {
	max := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) == 0 || trimmed[0] != '!' {
			continue
		}
		i := 1
		for i < len(trimmed) && trimmed[i] >= '0' && trimmed[i] <= '9' {
			i++
		}
		if i == 1 {
			continue
		}
		if i >= len(trimmed) || (trimmed[i] != ' ' && trimmed[i] != '=') {
			continue
		}
		n, err := strconv.Atoi(trimmed[1:i])
		if err != nil {
			continue
		}
		if n > max {
			max = n
		}
	}
	return max
}

// sanitizeBTFNames replaces dots in DWARF type/variable names with underscores.
func sanitizeBTFNames(lines []string) []string {
	var buf strings.Builder
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) == 0 || trimmed[0] != '!' {
			continue
		}
		if !strings.Contains(line, "DI") {
			continue
		}
		if !strings.Contains(line, "DIBasicType") &&
			!strings.Contains(line, "DIDerivedType") &&
			!strings.Contains(line, "DICompositeType") &&
			!strings.Contains(line, "DIGlobalVariable") &&
			!strings.Contains(line, "DISubprogram") {
			continue
		}
		if strings.Contains(line, "DW_TAG_pointer_type") {
			lines[i] = stripPointerName(line)
			continue
		}
		if strings.Contains(line, ".") {
			buf.Reset()
			lines[i] = replaceDotInNameFields(line, &buf)
		}
	}
	return lines
}

// nameFieldPrefixes are the LLVM DI metadata name field prefixes we rewrite.
var nameFieldPrefixes = []string{"linkageName: \"", "linkagename: \"", "name: \"", "Name: \""}

// replaceDotInNameFields replaces dots with underscores inside name: "..."
// fields without using regexp. The caller-owned buf is reused across calls.
func replaceDotInNameFields(line string, buf *strings.Builder) string {
	pos := 0
	modified := false
	for pos < len(line) {
		matched := false
		for _, prefix := range nameFieldPrefixes {
			if !strings.HasPrefix(line[pos:], prefix) {
				continue
			}
			valueStart := pos + len(prefix)
			quoteEnd := strings.IndexByte(line[valueStart:], '"')
			if quoteEnd < 0 {
				break
			}
			quoteEnd += valueStart
			value := line[valueStart:quoteEnd]
			if !strings.Contains(value, ".") {
				break
			}
			if !modified {
				buf.Grow(len(line))
				buf.WriteString(line[:pos])
				modified = true
			}
			buf.WriteString(prefix)
			buf.WriteString(strings.ReplaceAll(value, ".", "_"))
			buf.WriteByte('"')
			pos = quoteEnd + 1
			matched = true
			break
		}
		if !matched {
			if modified {
				buf.WriteByte(line[pos])
			}
			pos++
		}
	}
	if !modified {
		return line
	}
	return buf.String()
}

// stripPointerName removes a name: "..." field from a pointer type metadata
// line without using regexp.
func stripPointerName(line string) string {
	idx := strings.Index(line, `name: "`)
	if idx < 0 {
		return line
	}
	valueStart := idx + len(`name: "`)
	quoteEnd := strings.IndexByte(line[valueStart:], '"')
	if quoteEnd < 0 {
		return line
	}
	quoteEnd += valueStart + 1
	start := idx
	for start > 0 && line[start-1] == ' ' {
		start--
	}
	if start > 0 && line[start-1] == ',' {
		start--
	}
	return line[:start] + line[quoteEnd:]
}
