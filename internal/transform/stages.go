package transform

import (
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/kyleseneker/tinybpf/internal/ir"
)

// moduleStage pairs a name with an AST-based transform function.
type moduleStage struct {
	name string
	fn   func(*ir.Module) error
}

// buildModuleStages returns the ordered pipeline of AST-based IR transforms.
func buildModuleStages(opts Options) []moduleStage {
	return []moduleStage{
		{"module-rewrite", moduleRewriteModule},
		{"extract-programs", func(m *ir.Module) error {
			return extractProgramsModule(m, opts.Programs, opts.Verbose, opts.Stdout)
		}},
		{"replace-alloc", replaceAllocModule},
		{"rewrite-helpers", rewriteHelpersModule},
		{"core", corePassModule},
		{"sections", func(m *ir.Module) error {
			return sectionsPassModule(m, opts.Sections)
		}},
		{"map-btf", mapBTFPassModule},
		{"finalize", finalizeModule},
	}
}

const (
	bpfDatalayoutValue = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
	bpfTripleValue     = "bpf"
)

// moduleRewriteModule sets BPF target properties and strips invalid attributes in a single pass.
func moduleRewriteModule(m *ir.Module) error {
	if err := retargetModule(m); err != nil {
		return err
	}
	return stripAttributesModule(m)
}

// retargetModule sets the module's data layout and triple to BPF targets.
func retargetModule(m *ir.Module) error {
	m.DataLayout = bpfDatalayoutValue
	m.Triple = bpfTripleValue
	return nil
}

var (
	reAttrTargetCPU      = regexp.MustCompile(`"target-cpu"="[^"]*"`)
	reAttrTargetFeatures = regexp.MustCompile(`"target-features"="[^"]*"`)
	reAttrAllocKind      = regexp.MustCompile(`allockind\("[^"]*"\)`)
	reAttrAllocSize      = regexp.MustCompile(`allocsize\(\d+\)`)
	reAttrAllocFamily    = regexp.MustCompile(`"alloc-family"="[^"]*"`)
	reAttrMultiSpace     = regexp.MustCompile(`  +`)
)

// stripAttributesModule removes target-specific attribute group entries that are invalid for BPF.
func stripAttributesModule(m *ir.Module) error {
	for _, ag := range m.AttrGroups {
		body := ag.Body
		body = reAttrTargetCPU.ReplaceAllString(body, "")
		body = reAttrTargetFeatures.ReplaceAllString(body, "")
		body = reAttrAllocKind.ReplaceAllString(body, "")
		body = reAttrAllocSize.ReplaceAllString(body, "")
		body = reAttrAllocFamily.ReplaceAllString(body, "")
		body = reAttrMultiSpace.ReplaceAllString(body, " ")
		if body != ag.Body {
			ag.Body = body
			ag.Modified = true
		}
	}
	return nil
}

// extractProgramsModule keeps only the specified BPF program functions and removes runtime functions.
func extractProgramsModule(m *ir.Module, programNames []string, verbose bool, w io.Writer) error {
	if w == nil {
		w = io.Discard
	}
	programSet, err := buildProgramSet(m, programNames)
	if err != nil {
		return err
	}
	if verbose {
		for name := range programSet {
			fmt.Fprintf(w, "[transform] keeping program: %s\n", name)
		}
	}
	for _, fn := range m.Functions {
		if !programSet[fn.Name] {
			fn.Removed = true
		}
	}
	for i := range m.Entries {
		entry := &m.Entries[i]
		if entry.Kind == ir.TopFunction && entry.Function != nil && entry.Function.Removed {
			entry.Removed = true
		}
	}
	markRuntimeGlobalsRemoved(m)
	return nil
}

// buildProgramSet resolves which functions to keep based on explicit names or auto-detection.
func buildProgramSet(m *ir.Module, programNames []string) (map[string]bool, error) {
	programSet := make(map[string]bool)
	if len(programNames) > 0 {
		defined := make(map[string]bool, len(m.Functions))
		for _, fn := range m.Functions {
			defined[fn.Name] = true
		}
		var missing []string
		for _, n := range programNames {
			if !defined[n] {
				missing = append(missing, n)
			}
			programSet[n] = true
		}
		if len(missing) > 0 {
			available := make([]string, len(m.Functions))
			for i, fn := range m.Functions {
				available[i] = fn.Name
			}
			return nil, fmt.Errorf("requested program(s) not found in IR: %v (available: %v)", missing, available)
		}
	} else {
		for _, fn := range m.Functions {
			if !isRuntimeFunc(fn.Name) {
				programSet[fn.Name] = true
			}
		}
	}
	if len(programSet) == 0 {
		names := make([]string, len(m.Functions))
		for i, fn := range m.Functions {
			names[i] = fn.Name
		}
		return nil, fmt.Errorf("no program functions found among: %v", names)
	}
	return programSet, nil
}

// markRuntimeGlobalsRemoved flags runtime-internal globals for removal.
func markRuntimeGlobalsRemoved(m *ir.Module) {
	for _, g := range m.Globals {
		if strings.HasPrefix(g.Name, "runtime.") || g.Name == ".string" ||
			strings.HasPrefix(g.Name, "__bpf_core_") {
			g.Modified = true
			markGlobalRemoved(m, g)
		}
	}
}

// markGlobalRemoved flags the module entry associated with the given global as removed.
func markGlobalRemoved(m *ir.Module, g *ir.Global) {
	for i := range m.Entries {
		if m.Entries[i].Global == g {
			m.Entries[i].Removed = true
			break
		}
	}
}

// replaceAllocModule converts runtime.alloc calls to stack allocas zeroed by memset.
func replaceAllocModule(m *ir.Module) error {
	needMemset := false

	for _, fn := range m.Functions {
		if fn.Removed {
			continue
		}
		type allocSite struct {
			bodyIdx int
			varName string
			size    string
			indent  string
		}
		var sites []allocSite
		entryIdx := -1

		for i, bline := range fn.BodyRaw {
			trimmed := strings.TrimSpace(bline)
			if trimmed == "entry:" && entryIdx < 0 {
				entryIdx = i
			}
			if !strings.Contains(bline, "@runtime.alloc") {
				continue
			}
			match := reAllocCall.FindStringSubmatch(bline)
			if match == nil {
				return fmt.Errorf("line references @runtime.alloc but does not match expected call pattern: %s", trimmed)
			}
			sites = append(sites, allocSite{
				bodyIdx: i,
				varName: match[2],
				size:    match[3],
				indent:  match[1],
			})
		}

		if len(sites) == 0 {
			continue
		}
		needMemset = true

		for _, a := range sites {
			fn.BodyRaw[a.bodyIdx] = fmt.Sprintf(
				"%scall void @%s(ptr align 4 %s, i8 0, i64 %s, i1 false)",
				a.indent, memsetIntrinsicName, a.varName, a.size)
		}

		insertAt := 0
		if entryIdx >= 0 {
			insertAt = entryIdx + 1
		}
		allocas := make([]string, len(sites))
		for j, a := range sites {
			allocas[j] = fmt.Sprintf("  %s = alloca [%s x i8], align 4", a.varName, a.size)
		}

		newBody := make([]string, 0, len(fn.BodyRaw)+len(allocas))
		newBody = append(newBody, fn.BodyRaw[:insertAt]...)
		newBody = append(newBody, allocas...)
		newBody = append(newBody, fn.BodyRaw[insertAt:]...)
		fn.BodyRaw = newBody
	}

	if needMemset && !hasMemsetDecl(m) {
		insertMemsetDeclInModule(m)
	}
	return nil
}

// hasMemsetDecl reports whether the module already declares llvm.memset.p0.i64.
func hasMemsetDecl(m *ir.Module) bool {
	for _, d := range m.Declares {
		if d.Name == memsetIntrinsicName && !d.Removed {
			return true
		}
	}
	for _, e := range m.Entries {
		if !e.Removed && strings.Contains(e.Raw, "@"+memsetIntrinsicName) {
			return true
		}
	}
	return false
}

// insertMemsetDeclInModule adds a declare for llvm.memset.p0.i64 if not already present.
func insertMemsetDeclInModule(m *ir.Module) {
	decl := &ir.Declare{
		Name:    memsetIntrinsicName,
		RetType: "void",
		Params:  "ptr, i8, i64, i1",
		Raw:     memsetDecl,
	}
	m.Declares = append(m.Declares, decl)

	insertIdx := findFirstFuncEntry(m)
	entry := ir.TopLevelEntry{Kind: ir.TopDeclare, Raw: memsetDecl, Declare: decl}
	blankEntry := ir.TopLevelEntry{Kind: ir.TopBlank, Raw: ""}

	if insertIdx >= 0 {
		m.Entries = slices.Insert(m.Entries, insertIdx, entry, blankEntry)
	} else {
		m.Entries = append(m.Entries, entry, blankEntry)
	}
}

// rewriteHelpersModule replaces Go-style BPF helper calls with inttoptr-based kernel helper calls.
func rewriteHelpersModule(m *ir.Module) error {
	for _, fn := range m.Functions {
		if fn.Removed {
			continue
		}
		for i, bline := range fn.BodyRaw {
			if !strings.Contains(bline, "@main.bpf") {
				continue
			}
			loc := helperCallRe.FindStringSubmatchIndex(bline)
			if loc == nil {
				if strings.Contains(bline, "call") {
					return fmt.Errorf("line references @main.bpf* but does not match expected call pattern: %s",
						strings.TrimSpace(bline))
				}
				continue
			}
			retType := bline[loc[2]:loc[3]]
			funcName := bline[loc[4]:loc[5]]
			if strings.HasPrefix(funcName, "main.bpfCore") {
				continue
			}
			helperID, ok := helperIDs[funcName]
			if !ok {
				return fmt.Errorf("unknown BPF helper %q", funcName)
			}
			args := stripTrailingUndef(strings.TrimSpace(bline[loc[6]:loc[7]]))
			replacement := fmt.Sprintf("call %s inttoptr (i64 %d to ptr)(%s)", retType, helperID, args)
			fn.BodyRaw[i] = bline[:loc[0]] + replacement + bline[loc[1]:]
		}
	}
	return nil
}

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

// rewriteCoreAccessModule converts bpfCore GEP instructions to llvm.preserve.struct.access.index calls.
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

	modified := false
	for _, fn := range m.Functions {
		if fn.Removed {
			continue
		}
		for i, bline := range fn.BodyRaw {
			if !strings.Contains(bline, "getelementptr") || !strings.Contains(bline, "bpfCore") {
				continue
			}
			match := reCoreGEP.FindStringSubmatch(bline)
			if match == nil {
				return fmt.Errorf("getelementptr on bpfCore type does not match expected GEP pattern: %s",
					strings.TrimSpace(bline))
			}
			typeName := match[3]
			if !coreTypes[typeName] {
				continue
			}
			assign := match[1]
			base := match[4]
			fieldIdx := match[5]
			trailing := match[6]

			repl := fmt.Sprintf("%s%s", assign, preserveStructAccessCall(base, typeName, fieldIdx, fieldIdx))
			if metaID, ok := typeMeta[typeName]; ok {
				repl += fmt.Sprintf(", !llvm.preserve.access.index !%d", metaID)
			}
			if dbg := extractDBG(trailing); dbg != "" {
				repl += ", " + dbg
			}
			fn.BodyRaw[i] = repl
			modified = true
		}
	}

	if !modified {
		return nil
	}

	addIntrinsicDeclToModule(m, "llvm.preserve.struct.access.index", coreIntrinsicDecl)
	return nil
}

// rewriteCoreExistsModule converts bpfCoreFieldExists/bpfCoreTypeExists calls to BPF CO-RE intrinsics.
func rewriteCoreExistsModule(m *ir.Module) error {
	ctx, err := buildCoreExistsCtxFromAST(m)
	if err != nil {
		return err
	}
	ensureFallbackArtifactsInModule(m, ctx)

	needField, needType, needAccessIdx := false, false, false

	for _, fn := range m.Functions {
		if fn.Removed {
			continue
		}
		for i, bline := range fn.BodyRaw {
			if !strings.Contains(bline, "@main.bpfCore") {
				continue
			}
			match := reCoreExistsCall.FindStringSubmatchIndex(bline)
			if match == nil {
				if strings.Contains(bline, "Exists") && strings.Contains(bline, "call") {
					return fmt.Errorf("bpfCore*Exists call does not match expected pattern: %s",
						strings.TrimSpace(bline))
				}
				continue
			}
			callPrefix := bline[match[0]:match[3]]
			funcName := bline[match[4]:match[5]]
			args := stripTrailingUndef(strings.TrimSpace(bline[match[6]:match[7]]))

			switch funcName {
			case "bpfCoreFieldExists":
				usedAccess, rwErr := rewriteFieldExistsInBody(fn.BodyRaw, i, match, callPrefix, args, ctx)
				if rwErr != nil {
					return rwErr
				}
				if usedAccess {
					needAccessIdx = true
				}
				needField = true
			case "bpfCoreTypeExists":
				repl := fmt.Sprintf("%s@llvm.bpf.preserve.type.info.p0(%s, i64 0)", callPrefix, args)
				fn.BodyRaw[i] = bline[:match[0]] + repl + bline[match[1]:]
				needType = true
			}
		}
	}

	addCoreExistsIntrinsics(m, needField, needType, needAccessIdx)
	stripCoreExistsDeclsFromModule(m)
	return nil
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

// buildCoreExistsCtxFromAST gathers bpfCore type offsets and metadata needed for CO-RE exists rewrites.
func buildCoreExistsCtxFromAST(m *ir.Module) (*coreExistsContext, error) {
	coreTypes := make(map[string]bool)
	for _, td := range m.TypeDefs {
		if strings.HasPrefix(td.Name, "%main.bpfCore") && len(td.Fields) > 0 {
			coreTypes[td.Name] = true
		}
	}

	var fieldOffsets map[string][]int
	var typeMeta map[string]int

	if len(coreTypes) > 0 {
		fieldOffsets = make(map[string][]int, len(coreTypes))
		for _, td := range m.TypeDefs {
			if !coreTypes[td.Name] {
				continue
			}
			sizes := make([]int, len(td.Fields))
			for i, f := range td.Fields {
				s, err := irTypeSize(f)
				if err != nil {
					return nil, fmt.Errorf("type %s field %d: %w", td.Name, i, err)
				}
				sizes[i] = s
			}
			fieldOffsets[td.Name] = cumulativeOffsets(sizes)
		}
		typeMeta = findCoreTypeMetaFromAST(m, coreTypes)
	} else {
		fieldOffsets, typeMeta = discoverFieldOffsetsFromMeta(m)
	}

	fallbackIdx, err := discoverFallbackIdxFromAST(m)
	if err != nil {
		return nil, err
	}

	return &coreExistsContext{
		fieldOffsets: fieldOffsets,
		typeMeta:     typeMeta,
		fallbackIdx:  fallbackIdx,
	}, nil
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

// discoverFieldOffsetsFromMeta derives bpfCore field offsets from DW_TAG_member metadata when no typedef exists.
func discoverFieldOffsetsFromMeta(m *ir.Module) (map[string][]int, map[string]int) {
	metaByID := make(map[int]*ir.MetadataNode, len(m.MetadataNodes))
	for _, mn := range m.MetadataNodes {
		metaByID[mn.ID] = mn
	}
	fieldOffsets := make(map[string][]int)
	typeMeta := make(map[string]int)

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
		fieldOffsets[typeName] = offsets
		typeMeta[typeName] = mn.ID
	}
	return fieldOffsets, typeMeta
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
		for i, bline := range fn.BodyRaw {
			if !strings.Contains(bline, "@main.bpfCoreFieldExists(") {
				continue
			}
			match := reCoreExistsCall.FindStringSubmatchIndex(bline)
			if match == nil {
				continue
			}
			args := stripTrailingUndef(strings.TrimSpace(bline[match[6]:match[7]]))
			ptrArgMatch := reSSAValue.FindStringSubmatch(firstCommaArg(args))
			if ptrArgMatch == nil {
				continue
			}
			gepIdx := findSSADefInBody(fn.BodyRaw, ptrArgMatch[1], i)
			if gepIdx < 0 {
				continue
			}
			gepMatch := reByteGEP.FindStringSubmatch(fn.BodyRaw[gepIdx])
			if gepMatch == nil {
				continue
			}
			byteOffset, err := strconv.Atoi(gepMatch[3])
			if err != nil {
				return nil, err
			}
			offsetSet[byteOffset] = true
		}
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

// ensureFallbackArtifactsInModule creates a synthetic fallback type and metadata when no bpfCore typedef exists.
func ensureFallbackArtifactsInModule(m *ir.Module, ctx *coreExistsContext) {
	if len(ctx.fieldOffsets) != 0 || len(ctx.fallbackIdx) == 0 {
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

// rewriteFieldExistsInBody rewrites a single bpfCoreFieldExists call to a preserve.field.info intrinsic.
func rewriteFieldExistsInBody(
	bodyRaw []string, callIdx int, match []int,
	callPrefix, args string, ctx *coreExistsContext,
) (bool, error) {
	line := bodyRaw[callIdx]

	ptrArgMatch := reSSAValue.FindStringSubmatch(firstCommaArg(args))
	if ptrArgMatch == nil {
		return false, fmt.Errorf("cannot extract pointer arg from bpfCoreFieldExists args %q", args)
	}
	ptrArg := ptrArgMatch[1]

	gepIdx := findSSADefInBody(bodyRaw, ptrArg, callIdx)
	if gepIdx >= 0 {
		if gepMatch := reByteGEP.FindStringSubmatch(bodyRaw[gepIdx]); gepMatch != nil {
			return rewriteFieldExistsGEPInBody(bodyRaw, callIdx, gepIdx, match, callPrefix, args, ptrArg, gepMatch, ctx)
		}
	}

	typeName := ctx.soleType()
	if typeName == "" {
		accessCall := preserveStructAccessCall(ptrArg, ctx.fallbackType, strconv.Itoa(ctx.fallbackIdx[0]), strconv.Itoa(ctx.fallbackIdx[0]))
		if ctx.fallbackMeta > 0 {
			accessCall += fmt.Sprintf(", !llvm.preserve.access.index !%d", ctx.fallbackMeta)
		}
		repl := fmt.Sprintf("%s@llvm.bpf.preserve.field.info.p0(%s, i64 %d)", callPrefix, accessCall, bpfFieldExists)
		bodyRaw[callIdx] = line[:match[0]] + repl + line[match[1]:]
		return true, nil
	}
	accessCall := preserveStructAccessCall(ptrArg, typeName, "0", "0")
	if metaID, ok := ctx.typeMeta[typeName]; ok {
		accessCall += fmt.Sprintf(", !llvm.preserve.access.index !%d", metaID)
	}
	repl := fmt.Sprintf("%s@llvm.bpf.preserve.field.info.p0(%s, i64 %d)", callPrefix, accessCall, bpfFieldExists)
	bodyRaw[callIdx] = line[:match[0]] + repl + line[match[1]:]
	return true, nil
}

// rewriteFieldExistsGEPInBody rewrites a bpfCoreFieldExists call whose pointer comes from a byte GEP.
func rewriteFieldExistsGEPInBody(
	bodyRaw []string, callIdx, gepIdx int,
	match []int, callPrefix, args, ptrArg string,
	gepMatch []string, ctx *coreExistsContext,
) (bool, error) {
	line := bodyRaw[callIdx]
	base := gepMatch[2]
	byteOffset, _ := strconv.Atoi(gepMatch[3])

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

	if !usedFallback {
		gepRepl := fmt.Sprintf("  %s = %s", ptrArg,
			preserveStructAccessCall(base, typeName, strconv.Itoa(fieldIdx), strconv.Itoa(fieldIdx)))
		if metaID, ok := ctx.typeMeta[typeName]; ok {
			gepRepl += fmt.Sprintf(", !llvm.preserve.access.index !%d", metaID)
		}
		if dbg := extractDBG(bodyRaw[gepIdx]); dbg != "" {
			gepRepl += ", " + dbg
		}
		bodyRaw[gepIdx] = gepRepl
	} else {
		gepRepl := fmt.Sprintf("  %s = %s", ptrArg,
			preserveStructAccessCall(base, ctx.fallbackType, strconv.Itoa(fieldIdx), strconv.Itoa(fieldIdx)))
		if ctx.fallbackMeta > 0 {
			gepRepl += fmt.Sprintf(", !llvm.preserve.access.index !%d", ctx.fallbackMeta)
		}
		if dbg := extractDBG(bodyRaw[gepIdx]); dbg != "" {
			gepRepl += ", " + dbg
		}
		bodyRaw[gepIdx] = gepRepl
	}

	repl := fmt.Sprintf("%s@llvm.bpf.preserve.field.info.p0(%s, i64 %d)", callPrefix, args, bpfFieldExists)
	bodyRaw[callIdx] = line[:match[0]] + repl + line[match[1]:]
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

// sectionsPassModule assigns ELF sections to globals and program functions in a single pass.
func sectionsPassModule(m *ir.Module, sections map[string]string) error {
	if err := assignDataSectionsModule(m); err != nil {
		return err
	}
	return assignProgramSectionsModule(m, sections)
}

// assignDataSectionsModule assigns .data, .bss, or .rodata sections to globals that lack one.
func assignDataSectionsModule(m *ir.Module) error {
	for _, g := range m.Globals {
		if g.Section != "" {
			continue
		}
		if isRuntimeGlobal(g.Name) {
			continue
		}
		raw := g.Raw
		if strings.Contains(raw, "%main.bpfMapDef") {
			continue
		}
		section := classifyGlobalSectionFromAST(g)
		if section != "" {
			g.Section = section
			g.Modified = true
		}
	}
	return nil
}

// classifyGlobalSectionFromAST returns the ELF section name for a global based on its linkage.
func classifyGlobalSectionFromAST(g *ir.Global) string {
	if g.Initializer == "zeroinitializer" {
		return ".bss"
	}
	if strings.Contains(g.Linkage, "constant") {
		return ".rodata"
	}
	if strings.Contains(g.Linkage, "global") || g.Initializer != "" {
		return ".data"
	}
	return ""
}

// assignProgramSectionsModule adds ELF section attributes to function definitions and map globals.
func assignProgramSectionsModule(m *ir.Module, sections map[string]string) error {
	for i := range m.Entries {
		e := &m.Entries[i]
		if e.Removed {
			continue
		}
		if e.Kind == ir.TopFunction && e.Function != nil && !e.Function.Removed {
			fn := e.Function
			sec := ""
			if sections != nil {
				sec = sections[fn.Name]
			}
			if sec == "" {
				sec = fn.Name
			}
			if !strings.Contains(fn.Raw, " section ") {
				fn.Raw = insertSection(fn.Raw, sec)
			}
		}
		if e.Kind == ir.TopGlobal && e.Global != nil && strings.Contains(e.Raw, "bpfMapDef") {
			e.Raw = strings.Replace(e.Raw, " internal ", " ", 1)
			if !strings.Contains(e.Raw, " section ") {
				e.Raw = insertSectionAttr(e.Raw, ".maps")
			}
		}
	}
	return nil
}

// mapBTFPassModule strips map name prefixes, rewrites map definitions for BTF, and sanitizes DI names.
func mapBTFPassModule(m *ir.Module) error {
	if err := stripMapPrefixModule(m); err != nil {
		return err
	}
	if err := rewriteMapForBTFModule(m); err != nil {
		return err
	}
	return sanitizeBTFNamesModule(m)
}

// stripMapPrefixModule removes the "main." prefix from map global names and updates all references.
func stripMapPrefixModule(m *ir.Module) error {
	renames := collectMapRenames(m)
	if len(renames) == 0 {
		return nil
	}
	applyRenames(m, renames)
	return nil
}

type mapRename struct {
	oldRef string
	newRef string
}

// collectMapRenames builds rename pairs for map globals that have a package prefix.
func collectMapRenames(m *ir.Module) []mapRename {
	var renames []mapRename
	for _, e := range m.Entries {
		if e.Removed || e.Kind != ir.TopGlobal || e.Global == nil {
			continue
		}
		if !strings.Contains(e.Raw, `section ".maps"`) {
			continue
		}
		name := e.Global.Name
		dot := strings.IndexByte(name, '.')
		if dot < 0 {
			continue
		}
		stripped := name[dot+1:]
		if stripped == "" {
			continue
		}
		renames = append(renames, mapRename{
			oldRef: "@" + name,
			newRef: "@" + stripped,
		})
	}
	return renames
}

// applyRenames replaces all occurrences of old references with new ones across all entries.
func applyRenames(m *ir.Module, renames []mapRename) {
	for i := range m.Entries {
		e := &m.Entries[i]
		if e.Removed {
			continue
		}
		for _, r := range renames {
			if strings.Contains(e.Raw, r.oldRef) {
				e.Raw = strings.ReplaceAll(e.Raw, r.oldRef, r.newRef)
			}
		}
		if e.Kind == ir.TopFunction && e.Function != nil {
			applyRenamesToFunction(e.Function, renames)
		}
	}
}

// applyRenamesToFunction replaces old references with new ones in a function's raw lines.
func applyRenamesToFunction(fn *ir.Function, renames []mapRename) {
	for _, r := range renames {
		if strings.Contains(fn.Raw, r.oldRef) {
			fn.Raw = strings.ReplaceAll(fn.Raw, r.oldRef, r.newRef)
		}
	}
	for j, bline := range fn.BodyRaw {
		for _, r := range renames {
			if strings.Contains(bline, r.oldRef) {
				fn.BodyRaw[j] = strings.ReplaceAll(fn.BodyRaw[j], r.oldRef, r.newRef)
			}
		}
	}
}

// rewriteMapForBTFModule converts bpfMapDef globals from i32 fields to pointer-based BTF map definitions.
func rewriteMapForBTFModule(m *ir.Module) error {
	fieldCount, err := detectMapFieldCount(m)
	if err != nil {
		return err
	}

	maps, err := collectMapDefs(m, fieldCount)
	if err != nil {
		return err
	}
	if len(maps) == 0 {
		return nil
	}

	fields := mapFields[:fieldCount]
	maxMeta := findMaxMetaIDFromModule(m)

	for _, md := range maps {
		nextID := maxMeta + 1
		intTypeID := nextID
		nextID++

		appendMetaEntryToModule(m,
			fmt.Sprintf("!%d = !DIBasicType(name: \"int\", size: 32, encoding: DW_ATE_signed)", intTypeID))

		fieldPtrIDs := make([]int, fieldCount)
		for fi := range fields {
			subrangeID := nextID
			nextID++
			arrayID := nextID
			nextID++
			ptrID := nextID
			nextID++
			fieldPtrIDs[fi] = ptrID
			appendMetaEntryToModule(m,
				fmt.Sprintf("!%d = !DISubrange(count: %d)", subrangeID, md.values[fi]))
			appendMetaEntryToModule(m,
				fmt.Sprintf("!%d = !DICompositeType(tag: DW_TAG_array_type, baseType: !%d, elements: !{!%d})",
					arrayID, intTypeID, subrangeID))
			appendMetaEntryToModule(m,
				fmt.Sprintf("!%d = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !%d, size: 64)",
					ptrID, arrayID))
		}
		maxMeta = nextID - 1

		ptrFields := strings.TrimSuffix(strings.Repeat("ptr, ", fieldCount), ", ")

		rewriteMemberNodesInModule(m, fields, fieldPtrIDs)
		rewriteStructSizeInModule(m, fieldCount)
		rewriteMapGlobalInModule(m, md.entryIdx, md.name, ptrFields)
		rewriteMapTypeDefInModule(m, ptrFields, fieldCount)
	}

	return nil
}

// detectMapFieldCount returns the field count from a bpfMapDef type, defaulting to 5.
func detectMapFieldCount(m *ir.Module) (int, error) {
	for _, td := range m.TypeDefs {
		if strings.Contains(td.Name, "bpfMapDef") {
			fc := len(td.Fields)
			if fc < 5 || fc > 7 {
				return 0, fmt.Errorf("bpfMapDef type has %d fields (expected 5-7): %s", fc, td.Raw)
			}
			return fc, nil
		}
	}
	return 5, nil
}

type astMapDef struct {
	entryIdx int
	name     string
	values   []int
}

// collectMapDefs scans module entries for bpfMapDef globals and parses their initializers.
func collectMapDefs(m *ir.Module, fieldCount int) ([]astMapDef, error) {
	var maps []astMapDef
	for i, e := range m.Entries {
		if e.Removed || e.Kind != ir.TopGlobal || e.Global == nil {
			continue
		}
		trimmed := strings.TrimSpace(e.Raw)
		if mat := reMapGlobal.FindStringSubmatch(trimmed); mat != nil {
			vals := parseI32Initializer(mat[3])
			if vals == nil {
				return nil, fmt.Errorf("bpfMapDef global %q initializer could not be parsed: %s", mat[1], trimmed)
			}
			if len(vals) != fieldCount {
				return nil, fmt.Errorf("bpfMapDef global %q has %d fields but type has %d", mat[1], len(vals), fieldCount)
			}
			maps = append(maps, astMapDef{entryIdx: i, name: mat[1], values: vals})
			continue
		}
		if mz := reMapGlobalZero.FindStringSubmatch(trimmed); mz != nil {
			maps = append(maps, astMapDef{entryIdx: i, name: mz[1], values: make([]int, fieldCount)})
		}
	}
	return maps, nil
}

// rewriteMemberNodesInModule updates DW_TAG_member metadata to use pointer base types and C field names.
func rewriteMemberNodesInModule(m *ir.Module, fields []mapFieldInfo, fieldPtrIDs []int) {
	for i := range m.Entries {
		e := &m.Entries[i]
		if e.Removed || e.Kind != ir.TopMetadata {
			continue
		}
		line := e.Raw
		if !isMemberMeta(line) {
			continue
		}
		for fi, mf := range fields {
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
			e.Raw = newLine
			break
		}
	}
}

// rewriteStructSizeInModule updates the DICompositeType size for bpfMapDef from i32-based to ptr-based.
func rewriteStructSizeInModule(m *ir.Module, fieldCount int) {
	origStructSize := fmt.Sprintf("%d", fieldCount*32)
	newStructSize := fmt.Sprintf("%d", fieldCount*64)
	reOldStructSize := regexp.MustCompile(`size:\s*` + origStructSize)

	typedefTarget := ""
	for _, e := range m.Entries {
		if e.Removed || e.Kind != ir.TopMetadata {
			continue
		}
		if strings.Contains(e.Raw, "DW_TAG_typedef") && strings.Contains(e.Raw, "bpfMapDef") {
			if mat := reBaseType.FindString(e.Raw); mat != "" {
				typedefTarget = strings.TrimPrefix(mat, "baseType: ")
				break
			}
		}
	}

	for i := range m.Entries {
		e := &m.Entries[i]
		if e.Removed || e.Kind != ir.TopMetadata {
			continue
		}
		trimmed := strings.TrimSpace(e.Raw)
		isTarget := typedefTarget != "" && strings.HasPrefix(trimmed, typedefTarget+" ")
		if isTarget || (strings.Contains(e.Raw, "DICompositeType") &&
			strings.Contains(e.Raw, "DW_TAG_structure_type") &&
			strings.Contains(e.Raw, "bpfMapDef")) {
			e.Raw = reOldStructSize.ReplaceAllString(e.Raw, "size: "+newStructSize)
		}
	}
}

// rewriteMapGlobalInModule replaces a bpfMapDef global initializer with a zeroinitializer of pointer fields.
func rewriteMapGlobalInModule(m *ir.Module, entryIdx int, name, ptrFields string) {
	e := &m.Entries[entryIdx]
	replacement := fmt.Sprintf("@%s = global { %s } zeroinitializer", name, ptrFields)

	trimmed := strings.TrimSpace(e.Raw)
	newGlobal := reMapGlobal.ReplaceAllStringFunc(trimmed, func(string) string { return replacement })
	if newGlobal == trimmed {
		newGlobal = reMapGlobalZero.ReplaceAllStringFunc(trimmed, func(string) string { return replacement })
	}
	newGlobal = strings.Replace(newGlobal, "align 4", "align 8", 1)
	e.Raw = newGlobal
}

// rewriteMapTypeDefInModule replaces i32 fields with ptr fields in the bpfMapDef type definition.
func rewriteMapTypeDefInModule(m *ir.Module, ptrFields string, fieldCount int) {
	origI32Fields := strings.TrimSuffix(strings.Repeat("i32, ", fieldCount), ", ")
	for i := range m.Entries {
		e := &m.Entries[i]
		if e.Removed || e.Kind != ir.TopTypeDef {
			continue
		}
		if strings.Contains(e.Raw, "bpfMapDef") && strings.Contains(e.Raw, "= type {") {
			e.Raw = strings.Replace(e.Raw, "{ "+origI32Fields+" }", "{ "+ptrFields+" }", 1)
		}
	}
}

// sanitizeBTFNamesModule replaces dots with underscores in DI metadata names and strips pointer names.
func sanitizeBTFNamesModule(m *ir.Module) error {
	var buf strings.Builder
	for i := range m.Entries {
		e := &m.Entries[i]
		if e.Removed || e.Kind != ir.TopMetadata {
			continue
		}
		line := e.Raw
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
			e.Raw = stripPointerName(line)
			continue
		}
		if strings.Contains(line, ".") {
			buf.Reset()
			e.Raw = replaceDotInNameFields(line, &buf)
		}
	}
	return nil
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

// finalizeModule adds a GPL license if missing and removes unreferenced definitions.
func finalizeModule(m *ir.Module) error {
	if err := addLicenseModule(m); err != nil {
		return err
	}
	return cleanupModule(m)
}

// addLicenseModule inserts a GPL license global if one is not already present.
func addLicenseModule(m *ir.Module) error {
	for _, g := range m.Globals {
		if g.Section == "license" {
			return nil
		}
	}
	for _, e := range m.Entries {
		if e.Global != nil && strings.Contains(e.Raw, `section "license"`) {
			return nil
		}
	}
	newGlobal := &ir.Global{
		Name:        "_license",
		Linkage:     "global",
		Type:        "[4 x i8]",
		Initializer: `c"GPL\00"`,
		Section:     "license",
		Align:       1,
		Modified:    true,
	}
	m.Globals = append(m.Globals, newGlobal)

	insertIdx := findFirstFuncEntry(m)
	entry := ir.TopLevelEntry{
		Kind:   ir.TopGlobal,
		Global: newGlobal,
	}

	if insertIdx >= 0 {
		blankEntry := ir.TopLevelEntry{Kind: ir.TopBlank, Raw: ""}
		m.Entries = append(m.Entries[:insertIdx+2], m.Entries[insertIdx:]...)
		m.Entries[insertIdx] = entry
		m.Entries[insertIdx+1] = blankEntry
	} else {
		m.Entries = append(m.Entries, entry)
	}
	return nil
}

// cleanupModule removes unreferenced declares, globals, and attribute groups, then compacts entries.
func cleanupModule(m *ir.Module) error {
	identRefs := buildModuleIdentRefs(m)
	removeUnreferencedDeclares(m, identRefs)
	removeUnreferencedGlobals(m, identRefs)
	removeUnusedAttrGroups(m)
	markOrphanedAttrCommentsInModule(m)
	compactModuleEntries(m)
	return nil
}

// removeUnreferencedDeclares marks declare entries as removed if no other entry references them.
func removeUnreferencedDeclares(m *ir.Module, identRefs map[string][]int) {
	for i := range m.Entries {
		e := &m.Entries[i]
		if e.Removed {
			continue
		}
		if e.Declare != nil && e.Declare.Removed {
			e.Removed = true
			continue
		}
		if e.Kind == ir.TopDeclare && e.Declare != nil {
			name := "@" + e.Declare.Name
			if !identReferencedElsewhere(identRefs, name, i) {
				e.Removed = true
				if i > 0 && isAttrComment(m.Entries[i-1]) {
					m.Entries[i-1].Removed = true
				}
			}
		}
	}
}

// removeUnreferencedGlobals marks non-section globals as removed if no other entry references them.
func removeUnreferencedGlobals(m *ir.Module, identRefs map[string][]int) {
	for i := range m.Entries {
		e := &m.Entries[i]
		if e.Removed || e.Kind != ir.TopGlobal || e.Global == nil {
			continue
		}
		if e.Global.Section != "" || strings.Contains(e.Raw, " section ") {
			continue
		}
		name := "@" + e.Global.Name
		if !identReferencedElsewhere(identRefs, name, i) {
			e.Removed = true
		}
	}
}

// removeUnusedAttrGroups marks attribute groups as removed if no active entry references their ID.
func removeUnusedAttrGroups(m *ir.Module) {
	usedAttrs := collectUsedAttrIDsFromModule(m)
	for i := range m.Entries {
		e := &m.Entries[i]
		if e.Removed || e.Kind != ir.TopAttrGroup || e.AttrGroup == nil {
			continue
		}
		if !usedAttrs[e.AttrGroup.ID] {
			e.Removed = true
		}
	}
}

// buildModuleIdentRefs scans all entries and builds a map of @-identifier to entry indices.
func buildModuleIdentRefs(m *ir.Module) map[string][]int {
	refs := make(map[string][]int)
	for i, e := range m.Entries {
		if e.Removed {
			continue
		}
		for _, line := range entryTextLines(e) {
			for pos := 0; pos < len(line); pos++ {
				if line[pos] != '@' {
					continue
				}
				j := pos + 1
				for j < len(line) && isIdentCharByte(line[j]) {
					j++
				}
				if j > pos+1 {
					ident := line[pos:j]
					refs[ident] = append(refs[ident], i)
					pos = j - 1
				}
			}
		}
	}
	return refs
}

// identReferencedElsewhere reports whether name appears in any entry other than defIdx.
func identReferencedElsewhere(refs map[string][]int, name string, defIdx int) bool {
	for _, idx := range refs[name] {
		if idx != defIdx {
			return true
		}
	}
	return false
}

// isAttrComment reports whether the entry is a "; Function Attrs:" comment.
func isAttrComment(e ir.TopLevelEntry) bool {
	return !e.Removed && e.Kind == ir.TopComment &&
		strings.Contains(e.Raw, "; Function Attrs:")
}

// collectUsedAttrIDsFromModule returns the set of attribute group IDs (#N) referenced by active entries.
func collectUsedAttrIDsFromModule(m *ir.Module) map[string]bool {
	used := make(map[string]bool)
	for _, e := range m.Entries {
		if e.Removed || e.Kind == ir.TopAttrGroup {
			continue
		}
		for _, line := range entryTextLines(e) {
			for pos := range len(line) {
				if line[pos] != '#' {
					continue
				}
				j := pos + 1
				for j < len(line) && line[j] >= '0' && line[j] <= '9' {
					j++
				}
				if j > pos+1 {
					used[line[pos+1:j]] = true
				}
			}
		}
	}
	return used
}

// markOrphanedAttrCommentsInModule removes "; Function Attrs:" comments not followed by a function or declare.
func markOrphanedAttrCommentsInModule(m *ir.Module) {
	for i := range m.Entries {
		e := &m.Entries[i]
		if e.Removed || !isAttrComment(*e) {
			continue
		}
		hasTarget := false
		for j := i + 1; j < len(m.Entries); j++ {
			if m.Entries[j].Removed {
				continue
			}
			if m.Entries[j].Kind == ir.TopBlank {
				continue
			}
			if m.Entries[j].Kind == ir.TopFunction || m.Entries[j].Kind == ir.TopDeclare {
				hasTarget = true
			}
			break
		}
		if !hasTarget {
			e.Removed = true
		}
	}
}

// compactModuleEntries removes flagged entries and collapses consecutive blank lines.
func compactModuleEntries(m *ir.Module) {
	n := 0
	prevBlank := false
	for _, e := range m.Entries {
		if e.Removed {
			continue
		}
		blank := e.Kind == ir.TopBlank
		if blank && prevBlank {
			continue
		}
		m.Entries[n] = e
		n++
		prevBlank = blank
	}
	m.Entries = m.Entries[:n]
	for len(m.Entries) > 0 && m.Entries[len(m.Entries)-1].Kind == ir.TopBlank {
		m.Entries = m.Entries[:len(m.Entries)-1]
	}
	m.Entries = append(m.Entries, ir.TopLevelEntry{Kind: ir.TopBlank, Raw: ""})
}
