package transform

import (
	"regexp"
	"strconv"
	"strings"
)

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
