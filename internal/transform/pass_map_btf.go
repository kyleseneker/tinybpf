package transform

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/kyleseneker/tinybpf/diag"
	"github.com/kyleseneker/tinybpf/internal/ir"
)

// --- BTF map field metadata (formerly btfmap.go) ---

// mapFieldInfo pairs a libbpf field name with its Go-source name.
type mapFieldInfo struct {
	goName string
	cName  string
}

// mapFields lists all bpfMapDef fields in order.
var mapFields = []mapFieldInfo{
	{"Type", "type"},
	{"KeySize", "key_size"},
	{"ValueSize", "value_size"},
	{"MaxEntries", "max_entries"},
	{"MapFlags", "map_flags"},
	{"Pinning", "pinning"},
	{"InnerMapFd", "inner_map_fd"},
}

// reMapGlobal matches bpfMapDef global definitions with inline initializers.
var reMapGlobal = regexp.MustCompile(
	`^@([\w.]+)\s*=\s*(global|internal global)\s+%[\w.]*bpfMapDef\s*\{\s*(.*?)\}`)

// reMapGlobalZero matches zeroinitializer map globals (all fields default to 0).
var reMapGlobalZero = regexp.MustCompile(
	`^@([\w.]+)\s*=\s*(global|internal global)\s+%[\w.]*bpfMapDef\s+zeroinitializer`)

var (
	reBaseType     = regexp.MustCompile(`baseType:\s*!\d+`)
	reMemberSize   = regexp.MustCompile(`size:\s*\d+`)
	reMemberOffset = regexp.MustCompile(`offset:\s*\d+`)
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

// nameFieldPrefixes are the LLVM DI metadata name field prefixes we rewrite.
var nameFieldPrefixes = []string{"linkageName: \"", "linkagename: \"", "name: \"", "Name: \""}

// replaceDotInNameFields replaces dots with underscores inside name: "..." metadata fields.
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

// stripPointerName removes the name: "..." field from a pointer type metadata line.
func stripPointerName(line string) string {
	_, start, end, ok := extractQuotedName(line)
	if !ok {
		return line
	}
	fieldStart := start - len(`name: "`)
	fieldEnd := end + 1 // include closing quote
	for fieldStart > 0 && line[fieldStart-1] == ' ' {
		fieldStart--
	}
	if fieldStart > 0 && line[fieldStart-1] == ',' {
		fieldStart--
	}
	return line[:fieldStart] + line[fieldEnd:]
}

// --- Map BTF pass ---

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

// applyRenamesToFunction replaces old references with new ones in a function's instructions.
func applyRenamesToFunction(fn *ir.Function, renames []mapRename) {
	ir.EnsureBlocks(fn)
	fn.Modified = true
	for _, r := range renames {
		renameInFunction(fn, r.oldRef, r.newRef)
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
	var errs []error
	for i, e := range m.Entries {
		if e.Removed || e.Kind != ir.TopGlobal || e.Global == nil {
			continue
		}
		trimmed := strings.TrimSpace(e.Raw)
		if mat := reMapGlobal.FindStringSubmatch(trimmed); mat != nil {
			vals := parseI32Initializer(mat[3])
			if vals == nil {
				errs = append(errs, fmt.Errorf("bpfMapDef global %q initializer could not be parsed: %s", mat[1], trimmed))
				continue
			}
			if len(vals) != fieldCount {
				errs = append(errs, fmt.Errorf("bpfMapDef global %q has %d fields but type has %d", mat[1], len(vals), fieldCount))
				continue
			}
			maps = append(maps, astMapDef{entryIdx: i, name: mat[1], values: vals})
			continue
		}
		if mz := reMapGlobalZero.FindStringSubmatch(trimmed); mz != nil {
			maps = append(maps, astMapDef{entryIdx: i, name: mz[1], values: make([]int, fieldCount)})
		}
	}
	if err := diag.WrapErrors(diag.StageTransform, "map-btf", errs,
		"check that bpfMapDef globals have valid initializers"); err != nil {
		return nil, err
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
