package transform

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/kyleseneker/tinybpf/diag"
	"github.com/kyleseneker/tinybpf/internal/ir"
)

// reSSAValue extracts an SSA value token such as "%4" from IR operands.
var reSSAValue = regexp.MustCompile(`(%[\w.]+)`)

const (
	coreIntrinsicDecl      = "declare ptr @llvm.preserve.struct.access.index.p0.p0(ptr, i32 immarg, i32 immarg)"
	coreIntrinsicName      = "@llvm.preserve.struct.access.index.p0.p0"
	fieldInfoIntrinsicDecl = "declare i32 @llvm.bpf.preserve.field.info.p0(ptr, i64 immarg)"
	typeInfoIntrinsicDecl  = "declare i32 @llvm.bpf.preserve.type.info.p0(ptr, i64 immarg)"
	bpfFieldExists         = 2
)

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

// preserveStructAccessCall formats a call to llvm.preserve.struct.access.index with an explicit elementtype attribute.
func preserveStructAccessCall(base, elementType, gepIndex, diIndex string) string {
	return fmt.Sprintf("call ptr %s(ptr elementtype(%s) %s, i32 %s, i32 %s)",
		coreIntrinsicName, elementType, base, gepIndex, diIndex)
}

// FieldLayout holds the computed byte offsets and DWARF metadata ID for a
// bpfCore struct type.
type FieldLayout struct {
	Offsets []int // byte offset of each field
	MetaID  int   // DICompositeType metadata ID, or -1 if unknown
}

// coreExistsContext holds precomputed data for rewriting bpfCore*Exists calls.
type coreExistsContext struct {
	types        map[string]FieldLayout
	fallbackIdx  map[int]int
	fallbackType string
	fallbackMeta int
}

// soleType returns the single bpfCore type name if exactly one is known.
func (c *coreExistsContext) soleType() string {
	if len(c.types) == 1 {
		for typeName := range c.types {
			return typeName
		}
	}
	return ""
}

// resolveField finds the bpfCore struct type with a field at byteOffset and returns the type name and index.
func (c *coreExistsContext) resolveField(byteOffset int) (string, int) {
	for typeName, layout := range c.types {
		if idx := fieldIndexFromOffset(layout.Offsets, byteOffset); idx >= 0 {
			return typeName, idx
		}
	}
	return "", -1
}

// typeNames returns a summary of known types and their offsets for diagnostics.
func (c *coreExistsContext) typeNames() string {
	if len(c.types) == 0 {
		return "none"
	}
	var parts []string
	for name, layout := range c.types {
		parts = append(parts, fmt.Sprintf("%s%v", name, layout.Offsets))
	}
	return strings.Join(parts, ", ")
}

// fallbackTypeBody builds an LLVM struct body from byte offsets for the fallback CO-RE type.
func fallbackTypeBody(offsets []int) string {
	fields := make([]string, len(offsets))
	for i := range offsets {
		fields[i] = fmt.Sprintf("[%d x i8]", fallbackSegmentSize(offsets, i))
	}
	return strings.Join(fields, ", ")
}

// fallbackSegmentSize returns the byte span of the field at idx within a fallback offset list.
func fallbackSegmentSize(offsets []int, idx int) int {
	if idx+1 < len(offsets) {
		delta := offsets[idx+1] - offsets[idx]
		if delta > 0 {
			return delta
		}
	}
	return 1
}

// fallbackTotalSize returns the total byte size of a fallback struct described by offsets.
func fallbackTotalSize(offsets []int) int {
	last := len(offsets) - 1
	return offsets[last] + fallbackSegmentSize(offsets, last)
}

// parseLeadingInt extracts a leading integer from s (digits followed by non-digits), returning -1 on failure.
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

// irTypeAlign returns the natural ABI alignment in bytes for an LLVM IR type
// under the BPF datalayout (e-m:e-p:64:64-i64:64-i128:128-n32:64-S128).
func irTypeAlign(t string) int {
	t = strings.TrimSpace(t)
	switch t {
	case "i8":
		return 1
	case "i16":
		return 2
	case "i32":
		return 4
	case "i64", "ptr":
		return 8
	}
	if strings.HasPrefix(t, "[") {
		inner := strings.TrimPrefix(t, "[")
		inner = strings.TrimSuffix(inner, "]")
		parts := strings.SplitN(inner, " x ", 2)
		if len(parts) == 2 {
			return irTypeAlign(parts[1])
		}
	}
	return 1
}

// alignedFieldOffsets computes byte offsets for struct fields respecting natural
// alignment, matching the BPF datalayout.
func alignedFieldOffsets(fields []string) ([]int, error) {
	offsets := make([]int, len(fields))
	off := 0
	for i, f := range fields {
		size, err := irTypeSize(f)
		if err != nil {
			return nil, err
		}
		align := irTypeAlign(f)
		if align > 1 {
			off = (off + align - 1) &^ (align - 1)
		}
		offsets[i] = off
		off += size
	}
	return offsets, nil
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

// camelToSnake converts "TaskStruct" to "task_struct".
func camelToSnake(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 4)
	for i, c := range s {
		if c >= 'A' && c <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(c + 'a' - 'A')
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// renameCoreType converts a bpfCore struct type name to a kernel-style snake_case name.
func renameCoreType(line string) string {
	name, start, end, ok := extractQuotedName(line)
	if !ok {
		return line
	}
	if i := strings.Index(name, "bpfCore"); i >= 0 {
		name = name[i+len("bpfCore"):]
	}
	if name == "" {
		return line
	}
	return line[:start] + camelToSnake(name) + line[end:]
}

// renameCoreField converts a Go CamelCase field name to kernel-style snake_case.
func renameCoreField(line string) string {
	name, start, end, ok := extractQuotedName(line)
	if !ok {
		return line
	}
	return line[:start] + camelToSnake(name) + line[end:]
}

// --- Core pass entry point ---

// corePassModule runs all CO-RE transforms: struct access rewriting, exists intrinsics, and field name sanitization.
func corePassModule(m *ir.Module) error {
	if err := rewriteCoreAccessModule(m); err != nil {
		return err
	}
	if err := rewriteCoreExistsModule(m); err != nil {
		return err
	}
	return sanitizeCoreFieldNamesModule(m)
}

// rewriteCoreAccessModule converts bpfCore GEP instructions to
// llvm.preserve.struct.access.index calls.
func rewriteCoreAccessModule(m *ir.Module) error {
	coreTypes := make(map[string]bool)
	for _, td := range m.TypeDefs {
		if strings.Contains(td.Name, "bpfCore") && len(td.Fields) > 0 {
			coreTypes[td.Name] = true
		}
	}
	if len(coreTypes) == 0 {
		return nil
	}

	typeMeta := findCoreTypeMetaFromAST(m, coreTypes)

	var errs []error
	modified := false
	for _, fn := range m.Functions {
		if fn.Removed {
			continue
		}
		ir.EnsureBlocks(fn)
		for _, block := range fn.Blocks {
			for _, inst := range block.Instructions {
				ok, err := rewriteCoreGEPInst(inst, fn, coreTypes, typeMeta)
				if err != nil {
					errs = append(errs, err)
				}
				if ok {
					modified = true
				}
			}
		}
	}

	if err := diag.WrapErrors(diag.StageTransform, "core-access", errs,
		"check that bpfCore GEP instructions match the expected pattern"); err != nil {
		return err
	}

	if !modified {
		return nil
	}

	addIntrinsicDeclToModule(m, "llvm.preserve.struct.access.index", coreIntrinsicDecl)
	return nil
}

// rewriteCoreGEPInst rewrites a single bpfCore GEP instruction to a preserve_struct_access_index call.
func rewriteCoreGEPInst(inst *ir.Instruction, fn *ir.Function, coreTypes map[string]bool, typeMeta map[string]int) (bool, error) {
	if inst.Kind != ir.InstGEP || inst.GEP == nil {
		// Check for unparsed GEPs on bpfCore types
		if inst.Kind == ir.InstOther &&
			strings.Contains(inst.Raw, "getelementptr") &&
			strings.Contains(inst.Raw, "bpfCore") {
			return false, fmt.Errorf("getelementptr on bpfCore type does not match expected GEP pattern: %s",
				strings.TrimSpace(inst.Raw))
		}
		return false, nil
	}

	if !strings.Contains(inst.GEP.BaseType, "bpfCore") {
		return false, nil
	}
	typeName := inst.GEP.BaseType
	if !coreTypes[typeName] {
		return false, nil
	}

	// Extract the field index from the last GEP index (e.g. "i32 1" -> "1")
	if len(inst.GEP.Indices) < 2 {
		return false, fmt.Errorf("getelementptr on bpfCore type has too few indices: %s",
			strings.TrimSpace(inst.Raw))
	}
	lastIdx := inst.GEP.Indices[len(inst.GEP.Indices)-1]
	idxParts := strings.Fields(lastIdx)
	gepIndex := idxParts[len(idxParts)-1]

	base := inst.GEP.Base

	// Convert GEP to a call instruction
	inst.Kind = ir.InstCall
	inst.Call = &ir.CallInst{
		RetType: "ptr",
		Callee:  coreIntrinsicName,
		Args:    fmt.Sprintf("ptr elementtype(%s) %s, i32 %s, i32 %s", typeName, base, gepIndex, gepIndex),
	}
	inst.GEP = nil
	if metaID, ok := typeMeta[typeName]; ok {
		inst.Metadata = append(inst.Metadata, ir.MetaAttach{
			Key: "llvm.preserve.access.index", Value: fmt.Sprintf("!%d", metaID),
		})
	}
	// Preserve existing !dbg metadata
	inst.Modified = true
	fn.Modified = true
	return true, nil
}

// rewriteCoreExistsModule converts bpfCoreFieldExists/bpfCoreTypeExists calls
// to BPF CO-RE intrinsics.
func rewriteCoreExistsModule(m *ir.Module) error {
	ctx, err := buildCoreExistsCtxFromAST(m)
	if err != nil {
		return err
	}
	ensureFallbackArtifactsInModule(m, ctx)

	needField, needType, needAccessIdx := false, false, false
	var errs []error

	for _, fn := range m.Functions {
		if fn.Removed {
			continue
		}
		ir.EnsureBlocks(fn)
		f, ty, acc := rewriteCoreExistsInFunc(fn, ctx, &errs)
		if f {
			needField = true
		}
		if ty {
			needType = true
		}
		if acc {
			needAccessIdx = true
		}
	}

	if err := diag.WrapErrors(diag.StageTransform, "core-exists", errs,
		"check bpfCore*Exists calls match the expected pattern"); err != nil {
		return err
	}

	addCoreExistsIntrinsics(m, needField, needType, needAccessIdx)
	stripCoreExistsDeclsFromModule(m)
	return nil
}

// rewriteCoreExistsInFunc processes a single function for CO-RE exists rewrites,
// returning whether field, type, and access-index intrinsics are needed.
func rewriteCoreExistsInFunc(fn *ir.Function, ctx *coreExistsContext, errs *[]error) (needField, needType, needAccessIdx bool) {
	for bi, block := range fn.Blocks {
		for ii, inst := range block.Instructions {
			if inst.Kind == ir.InstCall && inst.Call != nil &&
				strings.HasPrefix(inst.Call.Callee, "@main.bpfCore") &&
				strings.HasSuffix(inst.Call.Callee, "Exists") {
				funcName := strings.TrimPrefix(inst.Call.Callee, "@main.")
				args := stripTrailingUndef(inst.Call.Args)

				switch funcName {
				case "bpfCoreFieldExists":
					usedAccess, rwErr := rewriteFieldExistsInst(fn, inst, bi, ii, args, ctx)
					if rwErr != nil {
						*errs = append(*errs, rwErr)
						continue
					}
					if usedAccess {
						needAccessIdx = true
					}
					needField = true
				case "bpfCoreTypeExists":
					inst.Call.Callee = "@llvm.bpf.preserve.type.info.p0"
					inst.Call.Args = args + ", i64 0"
					inst.Modified = true
					fn.Modified = true
					needType = true
				}
			} else if inst.Kind == ir.InstOther &&
				strings.Contains(inst.Raw, "@main.bpfCore") &&
				strings.Contains(inst.Raw, "Exists") &&
				strings.Contains(inst.Raw, "call") {
				*errs = append(*errs, fmt.Errorf("bpfCore*Exists call does not match expected pattern: %s",
					strings.TrimSpace(inst.Raw)))
			}
		}
	}
	return
}

// addCoreExistsIntrinsics adds LLVM intrinsic declarations required by CO-RE exists rewrites.
func addCoreExistsIntrinsics(m *ir.Module, needField, needType, needAccessIdx bool) {
	if needField {
		addIntrinsicDeclToModule(m, "llvm.bpf.preserve.field.info", fieldInfoIntrinsicDecl)
	}
	if needType {
		addIntrinsicDeclToModule(m, "llvm.bpf.preserve.type.info", typeInfoIntrinsicDecl)
	}
	if needAccessIdx {
		addIntrinsicDeclToModule(m, "llvm.preserve.struct.access.index", coreIntrinsicDecl)
	}
}

// buildCoreExistsCtxFromAST gathers bpfCore type offsets and metadata needed
// for CO-RE exists rewrites.
func buildCoreExistsCtxFromAST(m *ir.Module) (*coreExistsContext, error) {
	coreTypes := make(map[string]bool)
	for _, td := range m.TypeDefs {
		if strings.HasPrefix(td.Name, "%main.bpfCore") && len(td.Fields) > 0 {
			coreTypes[td.Name] = true
		}
	}

	types, err := discoverCoreFieldLayouts(m, coreTypes)
	if err != nil {
		return nil, err
	}

	fallbackIdx, err := discoverFallbackIdxFromAST(m)
	if err != nil {
		return nil, err
	}

	return &coreExistsContext{
		types:       types,
		fallbackIdx: fallbackIdx,
	}, nil
}

// discoverCoreFieldLayouts computes field layouts for bpfCore types using two
// strategies tried in order:
//  1. IR type definitions — when coreTypes is non-empty, alignedFieldOffsets
//     computes offsets from parsed typedef fields.
//  2. DWARF debug metadata — when no typedef exists, discoverFieldLayoutsFromMeta
//     reads DW_TAG_member offset attributes from metadata nodes.
func discoverCoreFieldLayouts(m *ir.Module, coreTypes map[string]bool) (map[string]FieldLayout, error) {
	if len(coreTypes) > 0 {
		typeMeta := findCoreTypeMetaFromAST(m, coreTypes)
		layouts := make(map[string]FieldLayout, len(coreTypes))
		for _, td := range m.TypeDefs {
			if !coreTypes[td.Name] {
				continue
			}
			offsets, err := alignedFieldOffsets(td.Fields)
			if err != nil {
				return nil, fmt.Errorf("type %s: %w", td.Name, err)
			}
			metaID := -1
			if id, ok := typeMeta[td.Name]; ok {
				metaID = id
			}
			layouts[td.Name] = FieldLayout{Offsets: offsets, MetaID: metaID}
		}
		return layouts, nil
	}
	return discoverFieldLayoutsFromMeta(m), nil
}

// findCoreTypeMetaFromAST maps bpfCore type names to their DICompositeType metadata IDs.
func findCoreTypeMetaFromAST(m *ir.Module, coreTypes map[string]bool) map[string]int {
	meta := make(map[string]int)
	for _, mn := range m.MetadataNodes {
		if mn.Kind != "DICompositeType" {
			continue
		}
		tag := mn.Fields["tag"]
		if tag != "DW_TAG_structure_type" {
			continue
		}
		name := mn.Fields["name"]
		if !strings.Contains(name, "bpfCore") {
			continue
		}
		for typeName := range coreTypes {
			if name == strings.TrimPrefix(typeName, "%") {
				meta[typeName] = mn.ID
				break
			}
		}
	}
	return meta
}

// discoverFieldLayoutsFromMeta derives bpfCore field layouts from DW_TAG_member metadata when no typedef exists.
func discoverFieldLayoutsFromMeta(m *ir.Module) map[string]FieldLayout {
	metaByID := make(map[int]*ir.MetadataNode, len(m.MetadataNodes))
	for _, mn := range m.MetadataNodes {
		metaByID[mn.ID] = mn
	}
	layouts := make(map[string]FieldLayout)

	for _, mn := range m.MetadataNodes {
		if mn.Kind != "DICompositeType" {
			continue
		}
		if mn.Fields["tag"] != "DW_TAG_structure_type" {
			continue
		}
		name := mn.Fields["name"]
		if !strings.Contains(name, "bpfCore") {
			continue
		}

		elementsRef := mn.Fields["elements"]
		if elementsRef == "" {
			continue
		}
		memberIDs := resolveMetaRefsFromAST(elementsRef, metaByID)
		if len(memberIDs) == 0 {
			continue
		}

		var offsets []int
		for _, mid := range memberIDs {
			memberNode, ok := metaByID[mid]
			if !ok || memberNode.Kind != "DIDerivedType" {
				continue
			}
			if memberNode.Fields["tag"] != "DW_TAG_member" {
				continue
			}
			offsetStr := memberNode.Fields["offset"]
			if offsetStr == "" {
				continue
			}
			offsetBits, err := strconv.Atoi(offsetStr)
			if err != nil {
				continue
			}
			offsets = append(offsets, offsetBits/8)
		}
		if len(offsets) == 0 {
			continue
		}
		typeName := "%" + name
		layouts[typeName] = FieldLayout{Offsets: offsets, MetaID: mn.ID}
	}
	return layouts
}

// resolveMetaRefsFromAST follows a metadata elements reference to collect the contained member IDs.
func resolveMetaRefsFromAST(elementsRef string, metaByID map[int]*ir.MetadataNode) []int {
	elemID := parseMetaID(elementsRef)
	if elemID < 0 {
		return nil
	}
	node, ok := metaByID[elemID]
	if !ok {
		return nil
	}
	if len(node.Tuple) == 0 {
		return nil
	}
	var result []int
	seen := make(map[int]bool)
	for _, ref := range node.Tuple {
		id := parseMetaID(ref)
		if id < 0 || seen[id] {
			continue
		}
		seen[id] = true
		if inner, ok := metaByID[id]; ok && inner.Kind == "" && len(inner.Tuple) > 0 {
			for _, innerRef := range inner.Tuple {
				iid := parseMetaID(innerRef)
				if iid >= 0 && !seen[iid] {
					seen[iid] = true
					result = append(result, iid)
				}
			}
		} else {
			result = append(result, id)
		}
	}
	return result
}

// discoverFallbackIdxFromAST collects byte offsets used in bpfCoreFieldExists GEPs for fallback indexing.
func discoverFallbackIdxFromAST(m *ir.Module) (map[int]int, error) {
	offsetSet := map[int]bool{0: true}

	for _, fn := range m.Functions {
		if fn.Removed {
			continue
		}
		ir.EnsureBlocks(fn)
		if err := collectFieldExistsOffsets(fn, offsetSet); err != nil {
			return nil, err
		}
	}

	return buildFallbackIdxMap(offsetSet), nil
}

// collectFieldExistsOffsets scans a function for bpfCoreFieldExists calls and
// records the byte offsets of their GEP pointer arguments.
func collectFieldExistsOffsets(fn *ir.Function, offsetSet map[int]bool) error {
	for bi, block := range fn.Blocks {
		for ii, inst := range block.Instructions {
			if inst.Kind != ir.InstCall || inst.Call == nil ||
				inst.Call.Callee != "@main.bpfCoreFieldExists" {
				continue
			}
			args := stripTrailingUndef(inst.Call.Args)
			ptrArgMatch := reSSAValue.FindStringSubmatch(firstCommaArg(args))
			if ptrArgMatch == nil {
				continue
			}
			gepInst, _ := findSSADefInBlocks(fn.Blocks, ptrArgMatch[1], bi, ii)
			if gepInst == nil || gepInst.Kind != ir.InstGEP || gepInst.GEP == nil {
				continue
			}
			if gepInst.GEP.BaseType != "i8" || len(gepInst.GEP.Indices) == 0 {
				continue
			}
			lastIdx := gepInst.GEP.Indices[len(gepInst.GEP.Indices)-1]
			idxParts := strings.Fields(lastIdx)
			byteOffset, err := strconv.Atoi(idxParts[len(idxParts)-1])
			if err != nil {
				continue
			}
			offsetSet[byteOffset] = true
		}
	}
	return nil
}

// buildFallbackIdxMap converts an offset set into a sorted offset-to-index map.
func buildFallbackIdxMap(offsetSet map[int]bool) map[int]int {
	offsets := make([]int, 0, len(offsetSet))
	for off := range offsetSet {
		offsets = append(offsets, off)
	}
	slices.Sort(offsets)

	idxByOffset := make(map[int]int, len(offsets))
	for idx, off := range offsets {
		idxByOffset[off] = idx
	}
	return idxByOffset
}

// ensureFallbackArtifactsInModule creates a synthetic fallback type and metadata when no bpfCore typedef exists.
func ensureFallbackArtifactsInModule(m *ir.Module, ctx *coreExistsContext) {
	if len(ctx.types) != 0 || len(ctx.fallbackIdx) == 0 {
		return
	}

	offsets := make([]int, 0, len(ctx.fallbackIdx))
	for off := range ctx.fallbackIdx {
		offsets = append(offsets, off)
	}
	slices.Sort(offsets)
	if len(offsets) == 0 {
		return
	}

	typeName := "%main.__tinybpfCoreFallback"
	typeDefRaw := fmt.Sprintf("%s = type { %s }", typeName, fallbackTypeBody(offsets))
	ctx.fallbackType = typeName

	alreadyHas := false
	for _, e := range m.Entries {
		if !e.Removed && strings.Contains(e.Raw, "__tinybpfCoreFallback") {
			alreadyHas = true
			break
		}
	}
	if !alreadyHas {
		insertIdx := findFirstFuncEntry(m)
		entry := ir.TopLevelEntry{Kind: ir.TopTypeDef, Raw: typeDefRaw}
		if insertIdx >= 0 {
			m.Entries = append(m.Entries[:insertIdx+1], m.Entries[insertIdx:]...)
			m.Entries[insertIdx] = entry
		} else {
			m.Entries = append(m.Entries, entry)
		}
	}

	maxID := findMaxMetaIDFromModule(m)
	baseID := maxID + 1
	memberStart := baseID + 1
	elemsID := memberStart + len(offsets)
	compID := elemsID + 1

	appendMetaEntryToModule(m,
		fmt.Sprintf("!%d = !DIBasicType(name: \"uint8\", size: 8, encoding: DW_ATE_unsigned)", baseID))

	memberRefs := make([]string, len(offsets))
	for i := range offsets {
		memberID := memberStart + i
		memberRefs[i] = fmt.Sprintf("!%d", memberID)
		sizeBytes := fallbackSegmentSize(offsets, i)
		appendMetaEntryToModule(m,
			fmt.Sprintf("!%d = !DIDerivedType(tag: DW_TAG_member, name: \"f%d\", baseType: !%d, size: %d, offset: %d)",
				memberID, i, baseID, sizeBytes*8, offsets[i]*8))
	}
	appendMetaEntryToModule(m,
		fmt.Sprintf("!%d = !{%s}", elemsID, strings.Join(memberRefs, ", ")))
	appendMetaEntryToModule(m,
		fmt.Sprintf("!%d = !DICompositeType(tag: DW_TAG_structure_type, name: \"main.__tinybpfCoreFallback\", size: %d, elements: !%d)",
			compID, fallbackTotalSize(offsets)*8, elemsID))

	ctx.fallbackMeta = compID
}

// findMaxMetaIDFromModule returns the highest metadata ID used in the module.
func findMaxMetaIDFromModule(m *ir.Module) int {
	maxID := -1
	for _, mn := range m.MetadataNodes {
		if mn.ID > maxID {
			maxID = mn.ID
		}
	}
	for _, e := range m.Entries {
		if e.Removed || e.Kind != ir.TopMetadata {
			continue
		}
		id := parseMetaID(strings.TrimSpace(e.Raw))
		if id > maxID {
			maxID = id
		}
	}
	return maxID
}

// appendMetaEntryToModule appends a raw metadata entry to the module's entry list.
func appendMetaEntryToModule(m *ir.Module, raw string) {
	m.Entries = append(m.Entries, ir.TopLevelEntry{Kind: ir.TopMetadata, Raw: raw})
}

// rewriteFieldExistsInst rewrites a single bpfCoreFieldExists call instruction to a preserve.field.info intrinsic.
func rewriteFieldExistsInst(
	fn *ir.Function, inst *ir.Instruction,
	blockIdx, instIdx int,
	args string, ctx *coreExistsContext,
) (bool, error) {
	ptrArgMatch := reSSAValue.FindStringSubmatch(firstCommaArg(args))
	if ptrArgMatch == nil {
		return false, fmt.Errorf("cannot extract pointer arg from bpfCoreFieldExists args %q", args)
	}
	ptrArg := ptrArgMatch[1]

	// Search backward for the GEP instruction that defines the pointer argument
	gepInst, _ := findSSADefInBlocks(fn.Blocks, ptrArg, blockIdx, instIdx)
	if gepInst != nil && gepInst.Kind == ir.InstGEP && gepInst.GEP != nil &&
		gepInst.GEP.BaseType == "i8" && len(gepInst.GEP.Indices) > 0 {
		return rewriteFieldExistsGEPInst(fn, inst, gepInst, ptrArg, args, ctx)
	}

	typeName := ctx.soleType()
	accessCallArgs, accessMeta := buildFieldExistsAccessCall(ptrArg, typeName, 0, ctx)

	inst.Call.Callee = "@llvm.bpf.preserve.field.info.p0"
	inst.Call.Args = fmt.Sprintf("%s, i64 %d", accessCallArgs, bpfFieldExists)
	inst.Metadata = append(inst.Metadata, accessMeta...)
	inst.Modified = true
	fn.Modified = true
	return true, nil
}

// buildFieldExistsAccessCall constructs the inner preserve_struct_access_index call arguments
// and metadata for a field exists rewrite.
func buildFieldExistsAccessCall(ptrArg, typeName string, fieldIdx int, ctx *coreExistsContext) (string, []ir.MetaAttach) {
	var meta []ir.MetaAttach
	useType := typeName
	useIdx := strconv.Itoa(fieldIdx)

	if typeName == "" {
		useType = ctx.fallbackType
		useIdx = strconv.Itoa(ctx.fallbackIdx[0])
	}

	callText := preserveStructAccessCall(ptrArg, useType, useIdx, useIdx)

	if typeName == "" && ctx.fallbackMeta > 0 {
		callText += fmt.Sprintf(", !llvm.preserve.access.index !%d", ctx.fallbackMeta)
	} else if typeName != "" {
		if layout, ok := ctx.types[typeName]; ok && layout.MetaID >= 0 {
			callText += fmt.Sprintf(", !llvm.preserve.access.index !%d", layout.MetaID)
		}
	}

	return callText, meta
}

// rewriteFieldExistsGEPInst rewrites a bpfCoreFieldExists call whose pointer comes from a byte GEP instruction.
func rewriteFieldExistsGEPInst(
	fn *ir.Function, callInst, gepInst *ir.Instruction,
	ptrArg, args string, ctx *coreExistsContext,
) (bool, error) {
	lastIdx := gepInst.GEP.Indices[len(gepInst.GEP.Indices)-1]
	idxParts := strings.Fields(lastIdx)
	byteOffset, _ := strconv.Atoi(idxParts[len(idxParts)-1])
	base := gepInst.GEP.Base

	typeName, fieldIdx := ctx.resolveField(byteOffset)
	usedFallback := false
	if typeName == "" {
		if idx, ok := ctx.fallbackIdx[byteOffset]; ok {
			fieldIdx = idx
			usedFallback = true
		} else {
			return false, fmt.Errorf("byte offset %d does not match any bpfCore struct field (known types: %v)",
				byteOffset, ctx.typeNames())
		}
	}

	resolvedType := typeName
	if usedFallback {
		resolvedType = ctx.fallbackType
	}
	gepInst.Kind = ir.InstCall
	gepInst.Call = &ir.CallInst{
		RetType: "ptr",
		Callee:  coreIntrinsicName,
		Args:    fmt.Sprintf("ptr elementtype(%s) %s, i32 %s, i32 %s", resolvedType, base, strconv.Itoa(fieldIdx), strconv.Itoa(fieldIdx)),
	}
	gepInst.GEP = nil
	if !usedFallback {
		if layout, ok := ctx.types[typeName]; ok && layout.MetaID >= 0 {
			gepInst.Metadata = append(gepInst.Metadata, ir.MetaAttach{
				Key: "llvm.preserve.access.index", Value: fmt.Sprintf("!%d", layout.MetaID),
			})
		}
	} else if ctx.fallbackMeta > 0 {
		gepInst.Metadata = append(gepInst.Metadata, ir.MetaAttach{
			Key: "llvm.preserve.access.index", Value: fmt.Sprintf("!%d", ctx.fallbackMeta),
		})
	}
	gepInst.Modified = true

	callInst.Call.Callee = "@llvm.bpf.preserve.field.info.p0"
	callInst.Call.Args = fmt.Sprintf("%s, i64 %d", args, bpfFieldExists)
	callInst.Modified = true
	fn.Modified = true
	return true, nil
}

// stripCoreExistsDeclsFromModule removes declarations for the now-rewritten bpfCore*Exists functions.
func stripCoreExistsDeclsFromModule(m *ir.Module) {
	for i := range m.Entries {
		e := &m.Entries[i]
		if e.Removed || e.Kind != ir.TopDeclare || e.Declare == nil {
			continue
		}
		if e.Declare.Name == "main.bpfCoreFieldExists" || e.Declare.Name == "main.bpfCoreTypeExists" {
			e.Removed = true
		}
	}
}

// addIntrinsicDeclToModule adds a declare for an LLVM intrinsic if one does not already exist.
func addIntrinsicDeclToModule(m *ir.Module, name, decl string) {
	for _, d := range m.Declares {
		if !d.Removed && strings.Contains(d.Name, name) {
			return
		}
	}
	for _, e := range m.Entries {
		if !e.Removed && strings.Contains(e.Raw, name) {
			return
		}
	}

	newDecl := &ir.Declare{Name: name, Raw: decl}
	m.Declares = append(m.Declares, newDecl)

	insertIdx := findFirstFuncEntry(m)
	entry := ir.TopLevelEntry{Kind: ir.TopDeclare, Raw: decl, Declare: newDecl}
	if insertIdx >= 0 {
		m.Entries = append(m.Entries[:insertIdx+1], m.Entries[insertIdx:]...)
		m.Entries[insertIdx] = entry
	} else {
		m.Entries = append(m.Entries, entry)
	}
}

// sanitizeCoreFieldNamesModule converts bpfCore type and field names from CamelCase to snake_case.
func sanitizeCoreFieldNamesModule(m *ir.Module) error {
	coreMetaIDs := collectCoreStructMetaIDs(m)
	if len(coreMetaIDs) == 0 {
		return nil
	}
	coreMemberIDs := collectCoreMemberIDs(m)

	for i := range m.Entries {
		e := &m.Entries[i]
		if e.Removed || e.Kind != ir.TopMetadata {
			continue
		}
		trimmed := strings.TrimSpace(e.Raw)
		id := parseMetaID(trimmed)
		if id < 0 {
			continue
		}
		if coreMetaIDs[id] {
			e.Raw = renameCoreType(e.Raw)
		} else if coreMemberIDs[id] && isMemberMeta(trimmed) {
			e.Raw = renameCoreField(e.Raw)
		}
	}
	return nil
}

// collectCoreStructMetaIDs returns the metadata IDs of bpfCore struct type entries.
func collectCoreStructMetaIDs(m *ir.Module) map[int]bool {
	ids := make(map[int]bool)
	for _, e := range m.Entries {
		if e.Removed || e.Kind != ir.TopMetadata {
			continue
		}
		trimmed := strings.TrimSpace(e.Raw)
		if isBpfCoreStructMeta(trimmed) {
			if id := parseMetaID(trimmed); id >= 0 {
				ids[id] = true
			}
		}
	}
	return ids
}

// collectCoreMemberIDs returns the metadata IDs referenced by bpfCore struct type entries.
func collectCoreMemberIDs(m *ir.Module) map[int]bool {
	ids := make(map[int]bool)
	for _, e := range m.Entries {
		if e.Removed || e.Kind != ir.TopMetadata {
			continue
		}
		trimmed := strings.TrimSpace(e.Raw)
		if !isBpfCoreStructMeta(trimmed) {
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
