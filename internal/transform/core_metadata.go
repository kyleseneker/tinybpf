package transform

import (
	"fmt"
	"strconv"
	"strings"
)

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

// discoverCoreFieldOffsets finds bpfCore struct types and their field byte
// offsets from type definitions.
func discoverCoreFieldOffsets(lines []string) (map[string][]int, map[string]int, error) {
	coreTypes, err := findCoreTypes(lines)
	if err != nil {
		return nil, nil, err
	}
	if len(coreTypes) == 0 {
		return discoverCoreFieldOffsetsFromMetadata(lines)
	}

	fieldOffsets := make(map[string][]int, len(coreTypes))
	for typeName := range coreTypes {
		sizes, parseErr := parseCoreFieldSizes(lines, typeName)
		if parseErr != nil {
			return nil, nil, parseErr
		}
		fieldOffsets[typeName] = cumulativeOffsets(sizes)
	}
	typeMeta, metaErr := findCoreTypeMetadata(lines, coreTypes)
	if metaErr != nil {
		return nil, nil, metaErr
	}
	return fieldOffsets, typeMeta, nil
}

// discoverCoreFieldOffsetsFromMetadata derives bpfCore field byte offsets from
// DWARF metadata when LLVM type definitions are unavailable.
func discoverCoreFieldOffsetsFromMetadata(lines []string) (map[string][]int, map[string]int, error) {
	metaByID := buildMetadataLineIndex(lines)
	fieldOffsets := make(map[string][]int)
	typeMeta := make(map[string]int)

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, "DICompositeType") ||
			!strings.Contains(trimmed, "DW_TAG_structure_type") ||
			!strings.Contains(trimmed, "bpfCore") {
			continue
		}

		id := extractMetadataID(trimmed)
		if id < 0 {
			return nil, nil, fmt.Errorf("line %d has bpfCore DICompositeType but metadata ID could not be parsed: %s",
				i+1, trimmed)
		}

		name, ok := extractMetadataName(trimmed)
		if !ok {
			return nil, nil, fmt.Errorf("line %d has bpfCore DICompositeType but name could not be parsed: %s",
				i+1, trimmed)
		}

		memberIDs := resolveCompositeMemberIDs(trimmed, metaByID)
		if len(memberIDs) == 0 {
			continue
		}

		offsets := make([]int, 0, len(memberIDs))
		for _, memberID := range memberIDs {
			memberLine, exists := metaByID[memberID]
			if !exists {
				continue
			}
			if !isMemberMeta(memberLine) {
				continue
			}
			offsetBits, found := extractMemberOffsetBits(memberLine)
			if !found {
				continue
			}
			if offsetBits%8 != 0 {
				return nil, nil, fmt.Errorf("metadata member !%d has non-byte-aligned offset %d", memberID, offsetBits)
			}
			offsets = append(offsets, offsetBits/8)
		}
		if len(offsets) == 0 {
			continue
		}

		typeName := "%" + name
		fieldOffsets[typeName] = offsets
		typeMeta[typeName] = id
	}

	if len(fieldOffsets) == 0 {
		return nil, nil, nil
	}
	return fieldOffsets, typeMeta, nil
}

// buildMetadataLineIndex indexes metadata definition lines by their !N ID.
func buildMetadataLineIndex(lines []string) map[int]string {
	metaByID := make(map[int]string)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "!") || !strings.Contains(trimmed, "=") {
			continue
		}
		id := extractMetadataID(trimmed)
		if id < 0 {
			continue
		}
		metaByID[id] = trimmed
	}
	return metaByID
}

// extractMetadataName returns the quoted value of name: "..." from metadata.
func extractMetadataName(line string) (string, bool) {
	const marker = `name: "`
	idx := strings.Index(line, marker)
	if idx < 0 {
		return "", false
	}
	start := idx + len(marker)
	end := strings.IndexByte(line[start:], '"')
	if end < 0 {
		return "", false
	}
	end += start
	return line[start:end], true
}

// resolveCompositeMemberIDs returns member metadata IDs referenced by a
// DICompositeType's elements field, including via indirection metadata nodes.
func resolveCompositeMemberIDs(compositeLine string, metaByID map[int]string) []int {
	const marker = "elements:"
	idx := strings.Index(compositeLine, marker)
	if idx < 0 {
		return nil
	}
	expr := strings.TrimSpace(compositeLine[idx+len(marker):])
	refs := parseMetadataRefs(expr)
	if len(refs) == 0 {
		return nil
	}

	var out []int
	seen := make(map[int]bool)
	for _, ref := range refs {
		appendResolvedMetadataRefs(ref, metaByID, seen, &out)
	}
	return out
}

// appendResolvedMetadataRefs recursively resolves !{...} indirection nodes to
// the concrete metadata IDs they reference, preserving source order.
func appendResolvedMetadataRefs(id int, metaByID map[int]string, seen map[int]bool, out *[]int) {
	if seen[id] {
		return
	}
	seen[id] = true

	line, ok := metaByID[id]
	if !ok {
		*out = append(*out, id)
		return
	}
	if !strings.Contains(line, "= !{") {
		*out = append(*out, id)
		return
	}
	eq := strings.IndexByte(line, '=')
	if eq < 0 {
		*out = append(*out, id)
		return
	}
	refs := parseMetadataRefs(line[eq+1:])
	if len(refs) == 0 {
		*out = append(*out, id)
		return
	}
	for _, ref := range refs {
		appendResolvedMetadataRefs(ref, metaByID, seen, out)
	}
}

// parseMetadataRefs extracts !N numeric references from metadata expressions.
func parseMetadataRefs(s string) []int {
	var refs []int
	for _, seg := range strings.Split(s, "!") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		n := 0
		digits := 0
		for i := range len(seg) {
			c := seg[i]
			if c < '0' || c > '9' {
				break
			}
			n = n*10 + int(c-'0')
			digits++
		}
		if digits > 0 {
			refs = append(refs, n)
		}
	}
	return refs
}

// extractMemberOffsetBits returns the integer value from "offset: N", where N
// is in bits in DWARF metadata.
func extractMemberOffsetBits(line string) (int, bool) {
	const marker = "offset:"
	idx := strings.Index(line, marker)
	if idx < 0 {
		return 0, false
	}
	s := strings.TrimSpace(line[idx+len(marker):])
	if s == "" {
		return 0, false
	}
	n := 0
	digits := 0
	for i := range len(s) {
		c := s[i]
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
		digits++
	}
	if digits == 0 {
		return 0, false
	}
	return n, true
}

// parseCoreFieldSizes extracts field sizes in bytes from a bpfCore struct
// type definition (e.g. "= type { i32, i64, [16 x i8] }").
func parseCoreFieldSizes(lines []string, typeName string) ([]int, error) {
	prefix := typeName + " = type {"
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, prefix) {
			continue
		}
		bodyStart := strings.IndexByte(trimmed, '{')
		bodyEnd := strings.LastIndexByte(trimmed, '}')
		if bodyStart < 0 || bodyEnd <= bodyStart {
			return nil, fmt.Errorf("malformed type definition for %s: %s", typeName, trimmed)
		}
		body := trimmed[bodyStart+1 : bodyEnd]
		fields := splitStructFields(body)
		sizes := make([]int, len(fields))
		for i, f := range fields {
			s, err := irTypeSize(f)
			if err != nil {
				return nil, fmt.Errorf("type %s field %d: %w", typeName, i, err)
			}
			sizes[i] = s
		}
		return sizes, nil
	}
	return nil, fmt.Errorf("type definition not found for %s", typeName)
}

// splitStructFields splits an IR struct body like "i32, i32, [16 x i8]"
// into individual field type strings, respecting nested brackets.
func splitStructFields(body string) []string {
	var fields []string
	depth := 0
	start := 0
	for i := range len(body) {
		switch body[i] {
		case '[':
			depth++
		case ']':
			depth--
		case ',':
			if depth == 0 {
				fields = append(fields, strings.TrimSpace(body[start:i]))
				start = i + 1
			}
		}
	}
	if f := strings.TrimSpace(body[start:]); f != "" {
		fields = append(fields, f)
	}
	return fields
}

// irTypeSize returns the size in bytes of an LLVM IR type.
func irTypeSize(t string) (int, error) {
	t = strings.TrimSpace(t)
	switch t {
	case "i8":
		return 1, nil
	case "i16":
		return 2, nil
	case "i32":
		return 4, nil
	case "i64":
		return 8, nil
	case "ptr":
		return 8, nil
	}
	if strings.HasPrefix(t, "[") {
		inner := strings.TrimPrefix(t, "[")
		inner = strings.TrimSuffix(inner, "]")
		parts := strings.SplitN(inner, " x ", 2)
		if len(parts) != 2 {
			return 0, fmt.Errorf("unsupported array type: %s", t)
		}
		n, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return 0, fmt.Errorf("unsupported array count in %s: %w", t, err)
		}
		elemSize, err := irTypeSize(parts[1])
		if err != nil {
			return 0, err
		}
		return n * elemSize, nil
	}
	return 0, fmt.Errorf("unsupported IR type: %s", t)
}

// cumulativeOffsets converts field sizes to cumulative byte offsets.
// For sizes [4, 4, 16] the result is [0, 4, 8].
func cumulativeOffsets(sizes []int) []int {
	offsets := make([]int, len(sizes))
	off := 0
	for i, s := range sizes {
		offsets[i] = off
		off += s
	}
	return offsets
}

// fieldIndexFromOffset returns the field index for a byte offset, or -1.
func fieldIndexFromOffset(offsets []int, byteOffset int) int {
	for i, off := range offsets {
		if off == byteOffset {
			return i
		}
	}
	return -1
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
