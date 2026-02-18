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

var reMetadataID = regexp.MustCompile(`^!(\d+)\s*=`)

// findMaxMetadataID scans for the highest numbered metadata node.
func findMaxMetadataID(lines []string) int {
	max := 0
	for _, line := range lines {
		if m := reMetadataID.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			n, _ := strconv.Atoi(m[1])
			if n > max {
				max = n
			}
		}
	}
	return max
}

var reDINameField = regexp.MustCompile(`((?:linkage)?[Nn]ame):\s*"([^"]*)"`)

// sanitizeBTFNames replaces dots in DWARF type/variable names with underscores.
func sanitizeBTFNames(lines []string) []string {
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "!") {
			continue
		}
		if !strings.Contains(line, "DIBasicType") &&
			!strings.Contains(line, "DIDerivedType") &&
			!strings.Contains(line, "DICompositeType") &&
			!strings.Contains(line, "DIGlobalVariable") &&
			!strings.Contains(line, "DISubprogram") {
			continue
		}
		// Pointer types must not have names in BTF
		if strings.Contains(line, "DW_TAG_pointer_type") {
			lines[i] = rePointerName.ReplaceAllString(line, "")
			continue
		}
		lines[i] = reDINameField.ReplaceAllStringFunc(line, func(m string) string {
			return strings.ReplaceAll(m, ".", "_")
		})
	}
	return lines
}

var rePointerName = regexp.MustCompile(`,?\s*name:\s*"[^"]*"`)
