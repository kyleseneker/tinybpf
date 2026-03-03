package transform

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// reCoreExistsCall matches calls to bpfCoreFieldExists or bpfCoreTypeExists.
var reCoreExistsCall = regexp.MustCompile(
	`(call\s+i32\s+)@main\.(bpfCoreFieldExists|bpfCoreTypeExists)\(([^)]*)\)`)

// reByteGEP matches byte-level getelementptr instructions that TinyGo emits
// for field address computations like &core.Tgid.
var reByteGEP = regexp.MustCompile(
	`^\s*(%[\w.]+)\s*=\s*getelementptr\s+(?:[A-Za-z0-9_().]+\s+)*i8,\s*ptr\s+(%[\w.]+),\s*i64\s+(\d+)`)

// reSSAValue extracts an SSA value token such as "%4" from IR operands.
var reSSAValue = regexp.MustCompile(`(%[\w.]+)`)

const bpfFieldExists = 2

// coreExistsContext holds precomputed data for rewriting bpfCore*Exists calls.
type coreExistsContext struct {
	fieldOffsets map[string][]int
	typeMeta     map[string]int
	fallbackIdx  map[int]int
	fallbackType string
	fallbackMeta int
}

// buildCoreExistsContext precomputes struct layouts and metadata needed for
// rewriting bpfCoreFieldExists calls.
func buildCoreExistsContext(lines []string) (*coreExistsContext, error) {
	fieldOffsets, typeMeta, err := discoverCoreFieldOffsets(lines)
	if err != nil {
		return nil, err
	}
	fallbackIdx, fallbackErr := discoverFallbackFieldIndices(lines)
	if fallbackErr != nil {
		return nil, fallbackErr
	}
	return &coreExistsContext{
		fieldOffsets: fieldOffsets,
		typeMeta:     typeMeta,
		fallbackIdx:  fallbackIdx,
	}, nil
}

// discoverFallbackFieldIndices builds a deterministic offset->field-index map
// directly from bpfCoreFieldExists callsites when type metadata is unavailable.
// It assumes lower byte offsets correspond to earlier fields.
func discoverFallbackFieldIndices(lines []string) (map[int]int, error) {
	offsetSet := map[int]bool{0: true}

	for i, line := range lines {
		if !strings.Contains(line, "@main.bpfCoreFieldExists(") {
			continue
		}
		m := reCoreExistsCall.FindStringSubmatchIndex(line)
		if m == nil {
			continue
		}
		args := stripTrailingUndef(strings.TrimSpace(line[m[6]:m[7]]))
		firstArg := strings.TrimSpace(strings.SplitN(args, ",", 2)[0])
		ptrArgMatch := reSSAValue.FindStringSubmatch(firstArg)
		if ptrArgMatch == nil {
			continue
		}
		ptrArg := ptrArgMatch[1]

		gepLine := findSSADef(lines, ptrArg, i)
		if gepLine < 0 {
			continue
		}
		gepMatch := reByteGEP.FindStringSubmatch(lines[gepLine])
		if gepMatch == nil {
			continue
		}
		byteOffset, convErr := strconv.Atoi(gepMatch[3])
		if convErr != nil {
			return nil, fmt.Errorf("line %d: invalid byte offset %q in bpfCoreFieldExists GEP",
				gepLine+1, gepMatch[3])
		}
		offsetSet[byteOffset] = true
	}

	offsets := make([]int, 0, len(offsetSet))
	for off := range offsetSet {
		offsets = append(offsets, off)
	}
	slices.Sort(offsets)

	idxByOffset := make(map[int]int, len(offsets))
	for idx, off := range offsets {
		idxByOffset[off] = idx
	}
	return idxByOffset, nil
}

// rewriteCoreExistsChecks rewrites bpfCoreFieldExists/bpfCoreTypeExists
// calls to their corresponding llvm.bpf.preserve intrinsics.
func rewriteCoreExistsChecks(lines []string) ([]string, error) {
	ctx, err := buildCoreExistsContext(lines)
	if err != nil {
		return nil, err
	}
	lines, err = ensureFallbackCoreArtifacts(lines, ctx)
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
			usedAccessIndex, rwErr := rewriteFieldExists(lines, i, m, callPrefix, args, ctx)
			if rwErr != nil {
				return nil, rwErr
			}
			if usedAccessIndex {
				needAccessIndex = true
			}
			needField = true
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

// ensureFallbackCoreArtifacts injects a synthetic fallback core type and
// matching DI metadata when no discoverable bpfCore type metadata exists.
func ensureFallbackCoreArtifacts(lines []string, ctx *coreExistsContext) ([]string, error) {
	if len(ctx.fieldOffsets) != 0 || len(ctx.fallbackIdx) == 0 {
		return lines, nil
	}

	offsets := make([]int, 0, len(ctx.fallbackIdx))
	for off := range ctx.fallbackIdx {
		offsets = append(offsets, off)
	}
	slices.Sort(offsets)
	if len(offsets) == 0 {
		return lines, nil
	}

	typeName := "%main.__tinybpfCoreFallback"
	typeDef := fmt.Sprintf("%s = type { %s }", typeName, fallbackTypeBody(offsets))
	if !containsLine(lines, typeDef) {
		lines = insertBeforeFunc(lines, typeDef)
	}
	ctx.fallbackType = typeName

	maxID := maxMetadataID(lines)
	baseID := maxID + 1
	memberStart := baseID + 1
	elemsID := memberStart + len(offsets)
	compID := elemsID + 1

	lines = append(lines,
		fmt.Sprintf("!%d = !DIBasicType(name: \"uint8\", size: 8, encoding: DW_ATE_unsigned)", baseID),
	)

	memberRefs := make([]string, len(offsets))
	for i := range offsets {
		memberID := memberStart + i
		memberRefs[i] = fmt.Sprintf("!%d", memberID)
		sizeBytes := fallbackSegmentSize(offsets, i)
		lines = append(lines, fmt.Sprintf("!%d = !DIDerivedType(tag: DW_TAG_member, name: \"f%d\", baseType: !%d, size: %d, offset: %d)",
			memberID, i, baseID, sizeBytes*8, offsets[i]*8))
	}
	lines = append(lines,
		fmt.Sprintf("!%d = !{%s}", elemsID, strings.Join(memberRefs, ", ")),
		fmt.Sprintf("!%d = !DICompositeType(tag: DW_TAG_structure_type, name: \"main.__tinybpfCoreFallback\", size: %d, elements: !%d)",
			compID, fallbackTotalSize(offsets)*8, elemsID),
	)
	ctx.fallbackMeta = compID
	return lines, nil
}

func containsLine(lines []string, want string) bool {
	for _, line := range lines {
		if strings.TrimSpace(line) == strings.TrimSpace(want) {
			return true
		}
	}
	return false
}

func maxMetadataID(lines []string) int {
	maxID := -1
	for _, line := range lines {
		id := extractMetadataID(strings.TrimSpace(line))
		if id > maxID {
			maxID = id
		}
	}
	return maxID
}

func fallbackTypeBody(offsets []int) string {
	fields := make([]string, len(offsets))
	for i := range offsets {
		fields[i] = fmt.Sprintf("[%d x i8]", fallbackSegmentSize(offsets, i))
	}
	return strings.Join(fields, ", ")
}

func fallbackSegmentSize(offsets []int, idx int) int {
	if idx+1 < len(offsets) {
		delta := offsets[idx+1] - offsets[idx]
		if delta > 0 {
			return delta
		}
	}
	return 1
}

func fallbackTotalSize(offsets []int) int {
	last := len(offsets) - 1
	return offsets[last] + fallbackSegmentSize(offsets, last)
}

// rewriteFieldExists handles a single bpfCoreFieldExists call: traces back
// to the byte-level GEP, determines the struct type and field index, replaces
// the GEP with preserve_struct_access_index, and emits preserve_field_info
// with BPF_FIELD_EXISTS kind.
func rewriteFieldExists(
	lines []string, callLine int, m []int,
	callPrefix, args string,
	ctx *coreExistsContext,
) (bool, error) {
	line := lines[callLine]

	firstArg := strings.TrimSpace(strings.SplitN(args, ",", 2)[0])
	ptrArgMatch := reSSAValue.FindStringSubmatch(firstArg)
	if ptrArgMatch == nil {
		return false, fmt.Errorf("line %d: cannot extract pointer arg from bpfCoreFieldExists args %q",
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
		accessCall := preserveStructAccessCall(ptrArg, ctx.fallbackType, strconv.Itoa(ctx.fallbackIdx[0]), strconv.Itoa(ctx.fallbackIdx[0]))
		if ctx.fallbackMeta > 0 {
			accessCall += fmt.Sprintf(", !llvm.preserve.access.index !%d", ctx.fallbackMeta)
		}
		repl := fmt.Sprintf("%s@llvm.bpf.preserve.field.info.p0(%s, i64 %d)",
			callPrefix, accessCall, bpfFieldExists)
		lines[callLine] = line[:m[0]] + repl + line[m[1]:]
		return true, nil
	}
	accessCall := preserveStructAccessCall(ptrArg, typeName, "0", "0")
	if metaID, ok := ctx.typeMeta[typeName]; ok {
		accessCall += fmt.Sprintf(", !llvm.preserve.access.index !%d", metaID)
	}
	repl := fmt.Sprintf("%s@llvm.bpf.preserve.field.info.p0(%s, i64 %d)",
		callPrefix, accessCall, bpfFieldExists)
	lines[callLine] = line[:m[0]] + repl + line[m[1]:]
	return true, nil
}

// rewriteFieldExistsGEP handles the GEP case: the pointer argument is
// defined by a byte-level GEP, giving us a non-zero field byte offset.
func rewriteFieldExistsGEP(
	lines []string, callLine, gepLine int,
	m []int, callPrefix, args, ptrArg string,
	gepMatch []string,
	ctx *coreExistsContext,
) (bool, error) {
	line := lines[callLine]
	base := gepMatch[2]
	byteOffset, _ := strconv.Atoi(gepMatch[3])

	typeName, fieldIdx := ctx.resolveField(byteOffset)
	usedFallback := false
	if typeName == "" {
		if idx, ok := ctx.fallbackIdx[byteOffset]; ok {
			fieldIdx = idx
			usedFallback = true
		} else {
			return false, fmt.Errorf("line %d: byte offset %d does not match any bpfCore struct field (known types: %v)",
				gepLine+1, byteOffset, ctx.typeNames())
		}
	}

	if !usedFallback {
		gepRepl := fmt.Sprintf("  %s = %s",
			ptrArg, preserveStructAccessCall(base, typeName, strconv.Itoa(fieldIdx), strconv.Itoa(fieldIdx)))
		if metaID, ok := ctx.typeMeta[typeName]; ok {
			gepRepl += fmt.Sprintf(", !llvm.preserve.access.index !%d", metaID)
		}
		if dbg := extractDBG(lines[gepLine]); dbg != "" {
			gepRepl += ", " + dbg
		}
		lines[gepLine] = gepRepl
	} else {
		gepRepl := fmt.Sprintf("  %s = %s",
			ptrArg, preserveStructAccessCall(base, ctx.fallbackType, strconv.Itoa(fieldIdx), strconv.Itoa(fieldIdx)))
		if ctx.fallbackMeta > 0 {
			gepRepl += fmt.Sprintf(", !llvm.preserve.access.index !%d", ctx.fallbackMeta)
		}
		if dbg := extractDBG(lines[gepLine]); dbg != "" {
			gepRepl += ", " + dbg
		}
		lines[gepLine] = gepRepl
	}

	repl := fmt.Sprintf("%s@llvm.bpf.preserve.field.info.p0(%s, i64 %d)",
		callPrefix, args, bpfFieldExists)
	lines[callLine] = line[:m[0]] + repl + line[m[1]:]
	return true, nil
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
