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

// reMetaRef matches !N metadata references inside a metadata entry.
var reMetaRef = regexp.MustCompile(`!(\d+)`)

type coreComposite struct {
	typeName  string
	metaID    int
	memberIDs []int
}

// discoverCoreTypesFromMetadata finds bpfCore struct types from DWARF debug
// metadata when no explicit type definitions are present.
func discoverCoreTypesFromMetadata(lines []string) (map[string][]int, map[string]int) {
	composites := findCoreComposites(lines)
	if len(composites) == 0 {
		return nil, nil
	}

	memberLines := make(map[int]string)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isMemberMeta(trimmed) {
			if id := extractMetadataID(trimmed); id >= 0 {
				memberLines[id] = trimmed
			}
		}
	}

	fieldOffsets := make(map[string][]int)
	metaIDs := make(map[string]int)
	for _, ci := range composites {
		offsets := make([]int, 0, len(ci.memberIDs))
		for _, mID := range ci.memberIDs {
			if mLine, ok := memberLines[mID]; ok {
				offsets = append(offsets, extractMetaIntField(mLine, "offset")/8)
			}
		}
		if len(offsets) > 0 {
			fieldOffsets[ci.typeName] = offsets
			metaIDs[ci.typeName] = ci.metaID
		}
	}
	return fieldOffsets, metaIDs
}

// findCoreComposites scans for DICompositeType metadata entries that
// describe bpfCore struct types and extracts their member metadata IDs.
func findCoreComposites(lines []string) []coreComposite {
	metaIndex := buildMetadataIndex(lines)
	var result []coreComposite
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, "DICompositeType") ||
			!strings.Contains(trimmed, "DW_TAG_structure_type") ||
			!strings.Contains(trimmed, "bpfCore") {
			continue
		}
		goName := extractMetaStringField(trimmed, "name")
		if goName == "" || !strings.Contains(goName, "bpfCore") {
			continue
		}
		metaID := extractMetadataID(trimmed)
		if metaID < 0 {
			continue
		}
		result = append(result, coreComposite{
			typeName:  "%" + goName,
			metaID:    metaID,
			memberIDs: extractElementIDs(trimmed, metaIndex),
		})
	}
	return result
}

// buildMetadataIndex maps metadata IDs to their trimmed line content
// for resolving indirect metadata references like elements: !N.
func buildMetadataIndex(lines []string) map[int]string {
	idx := make(map[int]string)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) > 0 && trimmed[0] == '!' {
			if id := extractMetadataID(trimmed); id >= 0 {
				idx[id] = trimmed
			}
		}
	}
	return idx
}

// extractElementIDs extracts metadata IDs from an elements field.
func extractElementIDs(line string, metaIndex map[int]string) []int {
	elemIdx := strings.Index(line, "elements:")
	if elemIdx < 0 {
		return nil
	}
	rest := line[elemIdx:]

	if ids := extractMetaIDsFromBraces(rest); ids != nil {
		return ids
	}

	refs := reMetaRef.FindStringSubmatch(rest)
	if refs == nil {
		return nil
	}
	indirectID, _ := strconv.Atoi(refs[1])
	if resolved, ok := metaIndex[indirectID]; ok {
		return extractMetaIDsFromBraces(resolved)
	}
	return nil
}

// extractMetaIDsFromBraces extracts !N references from within { ... }.
func extractMetaIDsFromBraces(s string) []int {
	open := strings.IndexByte(s, '{')
	close := strings.IndexByte(s, '}')
	if open < 0 || close <= open {
		return nil
	}
	var ids []int
	for _, m := range reMetaRef.FindAllStringSubmatch(s[open:close], -1) {
		n, _ := strconv.Atoi(m[1])
		ids = append(ids, n)
	}
	return ids
}

// extractMetaStringField extracts a quoted string value from a metadata field.
func extractMetaStringField(line, field string) string {
	prefix := field + `: "`
	idx := strings.Index(line, prefix)
	if idx < 0 {
		return ""
	}
	start := idx + len(prefix)
	end := strings.IndexByte(line[start:], '"')
	if end < 0 {
		return ""
	}
	return line[start : start+end]
}

// extractMetaIntField extracts an integer value from a metadata field.
// Returns 0 if the field is not found.
func extractMetaIntField(line, field string) int {
	prefix := field + ": "
	idx := strings.Index(line, prefix)
	if idx < 0 {
		return 0
	}
	start := idx + len(prefix)
	end := start
	for end < len(line) && line[end] >= '0' && line[end] <= '9' {
		end++
	}
	if end == start {
		return 0
	}
	n, _ := strconv.Atoi(line[start:end])
	return n
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

// reByteGEP matches byte-level getelementptr instructions that TinyGo emits
// for field address computations like &core.Tgid.
var reByteGEP = regexp.MustCompile(
	`^\s*(%[\w.]+)\s*=\s*getelementptr\s+(?:inbounds\s+)?(?:nuw\s+)?i8,\s*ptr\s+(%[\w.]+),\s*i64\s+(\d+)`)

// rePtrArg extracts an SSA value name from a pointer argument like "ptr nonnull %4".
var rePtrArg = regexp.MustCompile(`ptr\s+(?:nonnull\s+)?(%[\w.]+)`)

const bpfFieldExists = 2

// coreExistsContext holds precomputed data for rewriting bpfCore*Exists calls.
type coreExistsContext struct {
	fieldOffsets map[string][]int
	typeMeta     map[string]int
}

// buildCoreExistsContext precomputes struct layouts and metadata needed for
// rewriting bpfCoreFieldExists calls.
func buildCoreExistsContext(lines []string) (*coreExistsContext, error) {
	fieldOffsets, typeMeta, err := discoverCoreFieldOffsets(lines)
	if err != nil {
		return nil, err
	}
	return &coreExistsContext{
		fieldOffsets: fieldOffsets,
		typeMeta:     typeMeta,
	}, nil
}

// discoverCoreFieldOffsets finds bpfCore struct types and their field byte
// offsets from type definitions.
func discoverCoreFieldOffsets(lines []string) (map[string][]int, map[string]int, error) {
	coreTypes, err := findCoreTypes(lines)
	if err != nil {
		return nil, nil, err
	}

	if len(coreTypes) > 0 {
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

	fieldOffsets, typeMeta := discoverCoreTypesFromMetadata(lines)
	return fieldOffsets, typeMeta, nil
}

// rewriteCoreExistsChecks rewrites bpfCoreFieldExists/bpfCoreTypeExists
// calls to their corresponding llvm.bpf.preserve intrinsics.
func rewriteCoreExistsChecks(lines []string) ([]string, error) {
	ctx, err := buildCoreExistsContext(lines)
	if err != nil {
		return nil, err
	}

	needField := false
	needType := false
	needAccessIndex := false

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

		switch funcName {
		case "bpfCoreFieldExists":
			if err := rewriteFieldExists(lines, i, m, callPrefix, args, ctx); err != nil {
				return nil, err
			}
			needField = true
			needAccessIndex = true
		case "bpfCoreTypeExists":
			repl := fmt.Sprintf("%s%s(%s, i64 0)", callPrefix, "@llvm.bpf.preserve.type.info.p0", args)
			lines[i] = line[:m[0]] + repl + line[m[1]:]
			needType = true
		}
	}

	if needField {
		lines = addIntrinsicDecl(lines, "llvm.bpf.preserve.field.info", fieldInfoIntrinsicDecl)
	}
	if needType {
		lines = addIntrinsicDecl(lines, "llvm.bpf.preserve.type.info", typeInfoIntrinsicDecl)
	}
	if needAccessIndex {
		lines = addCoreIntrinsicDecl(lines)
	}

	lines = stripCoreExistsDeclarations(lines)
	return lines, nil
}

// rewriteFieldExists handles a single bpfCoreFieldExists call: traces back
// to the byte-level GEP, determines the struct type and field index, replaces
// the GEP with preserve_struct_access_index, and emits preserve_field_info
// with BPF_FIELD_EXISTS kind.
func rewriteFieldExists(
	lines []string, callLine int, m []int,
	callPrefix, args string,
	ctx *coreExistsContext,
) error {
	line := lines[callLine]

	ptrArgMatch := rePtrArg.FindStringSubmatch(args)
	if ptrArgMatch == nil {
		return fmt.Errorf("line %d: cannot extract pointer arg from bpfCoreFieldExists args %q",
			callLine+1, args)
	}
	ptrArg := ptrArgMatch[1]

	gepLine := findSSADef(lines, ptrArg, callLine)
	if gepLine >= 0 {
		if gepMatch := reByteGEP.FindStringSubmatch(lines[gepLine]); gepMatch != nil {
			return rewriteFieldExistsGEP(lines, callLine, gepLine, m, callPrefix, args, ptrArg, gepMatch, ctx)
		}
	}

	typeName := ctx.soleType()
	if typeName == "" {
		return fmt.Errorf("line %d: cannot determine bpfCore struct type for field-0 access via %s (found %d types)",
			callLine+1, ptrArg, len(ctx.fieldOffsets))
	}
	accessCall := fmt.Sprintf("call ptr %s(ptr %s, i32 0, i32 0)", coreIntrinsicName, ptrArg)
	if metaID, ok := ctx.typeMeta[typeName]; ok {
		accessCall += fmt.Sprintf(", !llvm.preserve.access.index !%d", metaID)
	}
	repl := fmt.Sprintf("%s@llvm.bpf.preserve.field.info.p0(%s, i64 %d)",
		callPrefix, accessCall, bpfFieldExists)
	lines[callLine] = line[:m[0]] + repl + line[m[1]:]
	return nil
}

// rewriteFieldExistsGEP handles the GEP case: the pointer argument is
// defined by a byte-level GEP, giving us a non-zero field byte offset.
func rewriteFieldExistsGEP(
	lines []string, callLine, gepLine int,
	m []int, callPrefix, args, ptrArg string,
	gepMatch []string,
	ctx *coreExistsContext,
) error {
	line := lines[callLine]
	base := gepMatch[2]
	byteOffset, _ := strconv.Atoi(gepMatch[3])

	typeName, fieldIdx := ctx.resolveField(byteOffset)
	if typeName == "" {
		return fmt.Errorf("line %d: byte offset %d does not match any bpfCore struct field (known types: %v)",
			gepLine+1, byteOffset, ctx.typeNames())
	}

	gepRepl := fmt.Sprintf("  %s = call ptr %s(ptr %s, i32 %d, i32 %d)",
		ptrArg, coreIntrinsicName, base, fieldIdx, fieldIdx)
	if metaID, ok := ctx.typeMeta[typeName]; ok {
		gepRepl += fmt.Sprintf(", !llvm.preserve.access.index !%d", metaID)
	}
	if dbg := extractDBG(lines[gepLine]); dbg != "" {
		gepRepl += ", " + dbg
	}
	lines[gepLine] = gepRepl

	repl := fmt.Sprintf("%s@llvm.bpf.preserve.field.info.p0(%s, i64 %d)",
		callPrefix, args, bpfFieldExists)
	lines[callLine] = line[:m[0]] + repl + line[m[1]:]
	return nil
}

// findSSADef searches backward from startLine for the line that defines
// the given SSA value (e.g., "%4 = ...").
func findSSADef(lines []string, ssaName string, startLine int) int {
	prefix := ssaName + " ="
	limit := startLine - 30
	if limit < 0 {
		limit = 0
	}
	for j := startLine - 1; j >= limit; j-- {
		if strings.Contains(lines[j], prefix) {
			return j
		}
	}
	return -1
}

// soleType returns the single bpfCore type name if exactly one is known.
func (c *coreExistsContext) soleType() string {
	if len(c.fieldOffsets) == 1 {
		for typeName := range c.fieldOffsets {
			return typeName
		}
	}
	return ""
}

// resolveField finds the bpfCore struct type that has a field at byteOffset
// and returns the type name and field index.
func (c *coreExistsContext) resolveField(byteOffset int) (string, int) {
	for typeName, offsets := range c.fieldOffsets {
		if idx := fieldIndexFromOffset(offsets, byteOffset); idx >= 0 {
			return typeName, idx
		}
	}
	return "", -1
}

// typeNames returns a summary of known types and their offsets for diagnostics.
func (c *coreExistsContext) typeNames() string {
	if len(c.fieldOffsets) == 0 {
		return "none"
	}
	var parts []string
	for name, offsets := range c.fieldOffsets {
		parts = append(parts, fmt.Sprintf("%s%v", name, offsets))
	}
	return strings.Join(parts, ", ")
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
