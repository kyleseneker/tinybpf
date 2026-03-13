package transform

import (
	"fmt"
	"io"
	"regexp"
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
		{"retarget", retargetModule},
		{"strip-attributes", stripAttributesModule},
		{"extract-programs", func(m *ir.Module) error {
			return extractProgramsModule(m, opts.Programs, opts.Verbose, opts.Stdout)
		}},
		{"replace-alloc", replaceAllocModule},
		{"rewrite-helpers", rewriteHelpersModule},
		{"rewrite-core-access", rewriteCoreAccessModule},
		{"rewrite-core-exists", rewriteCoreExistsModule},
		{"assign-data-sections", assignDataSectionsModule},
		{"assign-program-sections", func(m *ir.Module) error {
			return assignProgramSectionsModule(m, opts.Sections)
		}},
		{"strip-map-prefix", stripMapPrefixModule},
		{"rewrite-map-btf", rewriteMapForBTFModule},
		{"sanitize-btf-names", sanitizeBTFNamesModule},
		{"sanitize-core-fields", sanitizeCoreFieldNamesModule},
		{"add-license", addLicenseModule},
		{"cleanup", cleanupModule},
	}
}

// runLineStage is a fallback that serializes the module, runs a legacy
// line-based stage, and re-parses the result.
func runLineStage(m *ir.Module, fn func([]string) ([]string, error)) (*ir.Module, error) {
	text := ir.Serialize(m)
	lines := strings.Split(text, "\n")
	lines, err := fn(lines)
	if err != nil {
		return nil, err
	}
	return ir.Parse(strings.Join(lines, "\n"))
}

const (
	bpfDatalayoutValue = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
	bpfTripleValue     = "bpf"
)

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

func extractProgramsModule(m *ir.Module, programNames []string, verbose bool, w io.Writer) error {
	if w == nil {
		w = io.Discard
	}
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
			return fmt.Errorf("requested program(s) not found in IR: %v (available: %v)", missing, available)
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
		return fmt.Errorf("no program functions found among: %v", names)
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
	for _, g := range m.Globals {
		if strings.HasPrefix(g.Name, "runtime.") || g.Name == ".string" ||
			strings.HasPrefix(g.Name, "__bpf_core_") {
			g.Modified = true
			markGlobalRemoved(m, g)
		}
	}
	return nil
}

func markGlobalRemoved(m *ir.Module, g *ir.Global) {
	for i := range m.Entries {
		if m.Entries[i].Global == g {
			m.Entries[i].Removed = true
			break
		}
	}
}

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
				if strings.Contains(bline, "@runtime.alloc") {
					return fmt.Errorf("line references @runtime.alloc but does not match expected call pattern: %s", trimmed)
				}
				continue
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
				"%scall void @llvm.memset.p0.i64(ptr align 4 %s, i8 0, i64 %s, i1 false)",
				a.indent, a.varName, a.size)
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

	if needMemset {
		hasMemset := false
		for _, d := range m.Declares {
			if d.Name == "llvm.memset.p0.i64" && !d.Removed {
				hasMemset = true
				break
			}
		}
		if !hasMemset {
			for _, e := range m.Entries {
				if !e.Removed && strings.Contains(e.Raw, "@llvm.memset.p0.i64") {
					hasMemset = true
					break
				}
			}
		}
		if !hasMemset {
			insertMemsetDeclInModule(m)
		}
	}
	return nil
}

func insertMemsetDeclInModule(m *ir.Module) {
	decl := &ir.Declare{
		Name:    "llvm.memset.p0.i64",
		RetType: "void",
		Params:  "ptr, i8, i64, i1",
		Raw:     memsetDecl,
	}
	m.Declares = append(m.Declares, decl)

	insertIdx := -1
	for i, e := range m.Entries {
		if !e.Removed && (e.Kind == ir.TopDeclare || e.Kind == ir.TopFunction) {
			insertIdx = i
			break
		}
	}

	entry := ir.TopLevelEntry{Kind: ir.TopDeclare, Raw: memsetDecl, Declare: decl}
	blankEntry := ir.TopLevelEntry{Kind: ir.TopBlank, Raw: ""}

	if insertIdx >= 0 {
		m.Entries = append(m.Entries[:insertIdx+2], m.Entries[insertIdx:]...)
		m.Entries[insertIdx] = entry
		m.Entries[insertIdx+1] = blankEntry
	} else {
		m.Entries = append(m.Entries, entry, blankEntry)
	}
}

func rewriteHelpersModule(m *ir.Module) error {
	for _, fn := range m.Functions {
		if fn.Removed {
			continue
		}
		for i, bline := range fn.BodyRaw {
			if !strings.Contains(bline, "@main.bpf") {
				continue
			}
			loc := reHelperCall.FindStringSubmatchIndex(bline)
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
			helperID, ok := knownHelpers[funcName]
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
		for typeName := range coreTypes {
			goName := strings.TrimPrefix(typeName, "%")
			if name == goName {
				typeMeta[typeName] = mn.ID
				break
			}
		}
	}

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

func rewriteCoreExistsModule(m *ir.Module) error {
	result, err := runLineStage(m, rewriteCoreExistsChecks)
	if err != nil {
		return err
	}
	*m = *result
	return nil
}

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

	insertIdx := -1
	for i, e := range m.Entries {
		if !e.Removed && (e.Kind == ir.TopDeclare || e.Kind == ir.TopFunction) {
			insertIdx = i
			break
		}
	}

	entry := ir.TopLevelEntry{Kind: ir.TopDeclare, Raw: decl, Declare: newDecl}
	if insertIdx >= 0 {
		m.Entries = append(m.Entries[:insertIdx+1], m.Entries[insertIdx:]...)
		m.Entries[insertIdx] = entry
	} else {
		m.Entries = append(m.Entries, entry)
	}
}

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
			if strings.Contains(e.Raw, " internal ") {
				e.Raw = strings.Replace(e.Raw, " internal ", " ", 1)
			}
			if !strings.Contains(e.Raw, " section ") {
				e.Raw = insertSectionAttr(e.Raw, ".maps")
			}
		}
	}
	return nil
}

func stripMapPrefixModule(m *ir.Module) error {
	type rename struct {
		oldRef string
		newRef string
	}
	var renames []rename

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
		renames = append(renames, rename{
			oldRef: "@" + name,
			newRef: "@" + stripped,
		})
	}
	if len(renames) == 0 {
		return nil
	}

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
			fn := e.Function
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
	}
	return nil
}

func rewriteMapForBTFModule(m *ir.Module) error {
	result, err := runLineStage(m, rewriteMapForBTF)
	if err != nil {
		return err
	}
	*m = *result
	return nil
}

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

func sanitizeCoreFieldNamesModule(m *ir.Module) error {
	coreMetaIDs := make(map[int]bool)
	for _, e := range m.Entries {
		if e.Removed || e.Kind != ir.TopMetadata {
			continue
		}
		line := e.Raw
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "DICompositeType") &&
			strings.Contains(trimmed, "DW_TAG_structure_type") &&
			strings.Contains(trimmed, "bpfCore") {
			id := extractMetadataIDFromLine(trimmed)
			if id >= 0 {
				coreMetaIDs[id] = true
			}
		}
	}
	if len(coreMetaIDs) == 0 {
		return nil
	}

	coreMemberIDs := make(map[int]bool)
	for _, e := range m.Entries {
		if e.Removed || e.Kind != ir.TopMetadata {
			continue
		}
		trimmed := strings.TrimSpace(e.Raw)
		if !strings.Contains(trimmed, "DICompositeType") || !strings.Contains(trimmed, "bpfCore") {
			continue
		}
		for _, seg := range strings.Split(trimmed, "!") {
			seg = strings.TrimSpace(seg)
			if n := parseLeadingInt(seg); n >= 0 {
				coreMemberIDs[n] = true
			}
		}
	}

	for i := range m.Entries {
		e := &m.Entries[i]
		if e.Removed || e.Kind != ir.TopMetadata {
			continue
		}
		trimmed := strings.TrimSpace(e.Raw)
		id := extractMetadataIDFromLine(trimmed)
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

func extractMetadataIDFromLine(line string) int {
	if len(line) < 2 || line[0] != '!' || line[1] < '0' || line[1] > '9' {
		return -1
	}
	n := int(line[1] - '0')
	for i := 2; i < len(line) && line[i] >= '0' && line[i] <= '9'; i++ {
		n = n*10 + int(line[i]-'0')
	}
	return n
}

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

	insertIdx := -1
	for i, e := range m.Entries {
		if e.Kind == ir.TopDeclare || e.Kind == ir.TopFunction {
			insertIdx = i
			break
		}
	}

	entry := ir.TopLevelEntry{
		Kind:    ir.TopGlobal,
		Global:  newGlobal,
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

func cleanupModule(m *ir.Module) error {
	identRefs := buildModuleIdentRefs(m)

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

	markOrphanedAttrCommentsInModule(m)
	compactModuleEntries(m)

	return nil
}

func buildModuleIdentRefs(m *ir.Module) map[string][]int {
	refs := make(map[string][]int)
	for i, e := range m.Entries {
		if e.Removed {
			continue
		}
		var lines []string
		switch {
		case e.Kind == ir.TopFunction && e.Function != nil:
			lines = append(lines, e.Function.Raw)
			lines = append(lines, e.Function.BodyRaw...)
		default:
			lines = []string{e.Raw}
		}
		for _, line := range lines {
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

func isIdentCharByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '_' || c == '.'
}

func identReferencedElsewhere(refs map[string][]int, name string, defIdx int) bool {
	for _, idx := range refs[name] {
		if idx != defIdx {
			return true
		}
	}
	return false
}

func isAttrComment(e ir.TopLevelEntry) bool {
	return !e.Removed && e.Kind == ir.TopComment &&
		strings.Contains(e.Raw, "; Function Attrs:")
}

func collectUsedAttrIDsFromModule(m *ir.Module) map[string]bool {
	used := make(map[string]bool)
	for _, e := range m.Entries {
		if e.Removed {
			continue
		}
		if e.Kind == ir.TopAttrGroup {
			continue
		}
		var lines []string
		switch {
		case e.Kind == ir.TopFunction && e.Function != nil:
			lines = append(lines, e.Function.Raw)
			lines = append(lines, e.Function.BodyRaw...)
		default:
			lines = []string{e.Raw}
		}
		for _, line := range lines {
			for pos := 0; pos < len(line); pos++ {
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
