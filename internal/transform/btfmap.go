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

var mapFields = []mapFieldInfo{
	{"Type", "type"},
	{"KeySize", "key_size"},
	{"ValueSize", "value_size"},
	{"MaxEntries", "max_entries"},
	{"MapFlags", "map_flags"},
}

var reMapGlobal = regexp.MustCompile(
	`^@([\w.]+)\s*=\s*(global|internal global)\s+%[\w.]*bpfMapDef\s*\{\s*(.*?)\}`)

// rewriteMapForBTF rewrites bpfMapDef map globals and their debug metadata to use the libbpf-compatible BTF encoding.
func rewriteMapForBTF(lines []string) []string {
	type mapDef struct {
		lineIdx int
		name    string
		values  []int
	}
	var maps []mapDef

	for i, line := range lines {
		m := reMapGlobal.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		vals := parseI32Initializer(m[3])
		if len(vals) != 5 {
			continue
		}
		maps = append(maps, mapDef{lineIdx: i, name: m[1], values: vals})
	}
	if len(maps) == 0 {
		return lines
	}

	maxMeta := findMaxMetadataID(lines)

	for _, md := range maps {
		nextID := maxMeta + 1

		intTypeID := nextID
		nextID++
		var newMeta []string
		newMeta = append(newMeta,
			fmt.Sprintf("!%d = !DIBasicType(name: \"int\", size: 32, encoding: DW_ATE_signed)", intTypeID))

		fieldPtrIDs := make([]int, 5)
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

		// Rewrite DIDerivedType member nodes to libbpf field names and pointer sizes
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

		// Update struct size from 160 (5×i32) to 320 (5×ptr) via the typedef
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
			isTarget := false
			if typedefTarget != "" && strings.HasPrefix(trimmed, typedefTarget+" ") {
				isTarget = true
			}
			if isTarget || (strings.Contains(line, "DICompositeType") &&
				strings.Contains(line, "DW_TAG_structure_type") &&
				strings.Contains(line, "bpfMapDef")) {
				lines[i] = reStructSize.ReplaceAllString(line, "size: 320")
			}
		}

		origLine := lines[md.lineIdx]
		newGlobal := reMapGlobal.ReplaceAllStringFunc(strings.TrimSpace(origLine), func(s string) string {
			return fmt.Sprintf("@%s = global { ptr, ptr, ptr, ptr, ptr } zeroinitializer", md.name) //nolint:dupword
		})
		newGlobal = strings.Replace(newGlobal, "align 4", "align 8", 1)
		lines[md.lineIdx] = newGlobal

		for i, line := range lines {
			if strings.Contains(line, "bpfMapDef") && strings.Contains(line, "= type {") {
				lines[i] = strings.Replace(line, "{ i32, i32, i32, i32, i32 }", "{ ptr, ptr, ptr, ptr, ptr }", 1) //nolint:dupword
			}
		}

		insertIdx := len(lines)
		for insertIdx > 0 && strings.TrimSpace(lines[insertIdx-1]) == "" {
			insertIdx--
		}
		result := make([]string, 0, len(lines)+len(newMeta)+1)
		result = append(result, lines[:insertIdx]...)
		result = append(result, "")
		result = append(result, newMeta...)
		result = append(result, lines[insertIdx:]...)
		lines = result

		maxMeta = nextID
	}

	return lines
}

var (
	reBaseType     = regexp.MustCompile(`baseType:\s*!\d+`)
	reMemberSize   = regexp.MustCompile(`size:\s*\d+`)
	reMemberOffset = regexp.MustCompile(`offset:\s*\d+`)
	reStructSize   = regexp.MustCompile(`size:\s*160`)
)

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
