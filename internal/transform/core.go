package transform

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// reCoreGEP matches getelementptr instructions on bpfCore-annotated struct types.
var reCoreGEP = regexp.MustCompile(
	`^(\s*(%[\w.]+)\s*=\s*)getelementptr\s+(?:[A-Za-z0-9_().]+\s+)*(%main\.bpfCore[\w.]*),\s*ptr\s+(%[\w.]+),\s*i32\s+0,\s*i32\s+(\d+)(.*)$`)

// reCoreExistsCall matches calls to bpfCoreFieldExists or bpfCoreTypeExists.
var reCoreExistsCall = regexp.MustCompile(
	`(call\s+i32\s+)@main\.(bpfCoreFieldExists|bpfCoreTypeExists)\(([^)]*)\)`)

// reByteGEP matches byte-level getelementptr instructions emitted by TinyGo for field addresses.
var reByteGEP = regexp.MustCompile(
	`^\s*(%[\w.]+)\s*=\s*getelementptr\s+(?:[A-Za-z0-9_().]+\s+)*i8,\s*ptr\s+(%[\w.]+),\s*i64\s+(\d+)`)

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

// coreExistsContext holds precomputed data for rewriting bpfCore*Exists calls.
type coreExistsContext struct {
	fieldOffsets map[string][]int
	typeMeta     map[string]int
	fallbackIdx  map[int]int
	fallbackType string
	fallbackMeta int
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

// resolveField finds the bpfCore struct type with a field at byteOffset and returns the type name and index.
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

// cumulativeOffsets converts field sizes to cumulative byte offsets (e.g. [4,4,16] -> [0,4,8]).
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
