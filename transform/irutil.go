package transform

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/kyleseneker/tinybpf/ir"
)

// isRuntimeFunc reports whether name belongs to TinyGo's runtime.
func isRuntimeFunc(name string) bool {
	if name == "main" || name == "__dynamic_loader" {
		return true
	}
	for _, prefix := range []string{"tinygo_", "runtime.", "internal/"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// isRuntimeGlobal reports whether a global name belongs to the TinyGo runtime or standard library.
func isRuntimeGlobal(name string) bool {
	for _, prefix := range []string{"runtime.", "internal/", "reflect.", ".string", "llvm."} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// insertSectionAttr adds `, section ".name"` before the alignment or trailing comma.
func insertSectionAttr(line, section string) string {
	if idx := strings.Index(line, ", align "); idx >= 0 {
		return line[:idx] + `, section "` + section + `"` + line[idx:]
	}
	return strings.TrimRight(line, " \t") + `, section "` + section + `"`
}

// insertSection inserts a section attribute into a define line before any metadata attachments.
func insertSection(line, sec string) string {
	attr := fmt.Sprintf(` section "%s"`, sec)

	braceIdx := strings.LastIndex(line, "{")
	if braceIdx < 0 {
		return line + attr
	}

	insertPos := braceIdx
	prefix := strings.TrimRight(line[:insertPos], " \t")
	for strings.HasSuffix(prefix, ")") || reMetaAttach.MatchString(prefix) {
		loc := reTrailingMeta.FindStringIndex(prefix)
		if loc == nil {
			break
		}
		prefix = strings.TrimRight(prefix[:loc[0]], " \t")
	}

	return prefix + attr + " " + line[len(prefix):braceIdx] + line[braceIdx:]
}

var (
	reMetaAttach   = regexp.MustCompile(`!\w+\s*!\d+\s*$`)
	reTrailingMeta = regexp.MustCompile(`\s*!\w+\s*!\d+\s*$`)
)

var reAllocCall = regexp.MustCompile(
	`(\s*)(%\w+)\s*=\s*call\s+.*@runtime\.alloc\(i64\s+(\d+)`,
)

const (
	memsetIntrinsicName = "llvm.memset.p0.i64"
	memsetDecl          = "declare void @llvm.memset.p0.i64(ptr, i8, i64, i1)"
)

// parseMetaID extracts the numeric ID from a metadata reference like "!42" or a full definition line, returning -1 on failure.
func parseMetaID(s string) int {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != '!' || s[1] < '0' || s[1] > '9' {
		return -1
	}
	n := int(s[1] - '0')
	for i := 2; i < len(s) && s[i] >= '0' && s[i] <= '9'; i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}

// isBpfCoreStructMeta reports whether a line defines a DICompositeType for a bpfCore struct.
func isBpfCoreStructMeta(line string) bool {
	return strings.Contains(line, "DICompositeType") &&
		strings.Contains(line, "DW_TAG_structure_type") &&
		strings.Contains(line, "bpfCore")
}

// isIdentCharByte reports whether c is valid in an LLVM identifier.
func isIdentCharByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '_' || c == '.'
}

// firstCommaArg returns the first comma-delimited argument, trimmed.
func firstCommaArg(args string) string {
	return strings.TrimSpace(strings.SplitN(args, ",", 2)[0])
}

// findSSADefInBody searches backward from startIdx for an SSA definition of ssaName within a 30-line window.
func findSSADefInBody(bodyRaw []string, ssaName string, startIdx int) int {
	prefix := ssaName + " ="
	limit := startIdx - 30
	if limit < 0 {
		limit = 0
	}
	for j := startIdx - 1; j >= limit; j-- {
		if strings.Contains(bodyRaw[j], prefix) {
			return j
		}
	}
	return -1
}

// findFirstFuncEntry returns the index of the first non-removed declare or function entry, or -1.
func findFirstFuncEntry(m *ir.Module) int {
	for i, e := range m.Entries {
		if !e.Removed && (e.Kind == ir.TopDeclare || e.Kind == ir.TopFunction) {
			return i
		}
	}
	return -1
}

// entryTextLines returns the raw text lines that should be scanned for references in the given entry.
func entryTextLines(e ir.TopLevelEntry) []string {
	if e.Kind == ir.TopFunction && e.Function != nil {
		lines := make([]string, 0, 1+len(e.Function.BodyRaw))
		lines = append(lines, e.Function.Raw)
		lines = append(lines, e.Function.BodyRaw...)
		return lines
	}
	return []string{e.Raw}
}

// extractQuotedName finds `name: "VALUE"` in line and returns VALUE with its byte offsets, or ok=false.
func extractQuotedName(line string) (name string, start, end int, ok bool) {
	const prefix = `name: "`
	idx := strings.Index(line, prefix)
	if idx < 0 {
		return "", 0, 0, false
	}
	start = idx + len(prefix)
	quoteEnd := strings.IndexByte(line[start:], '"')
	if quoteEnd < 0 {
		return "", 0, 0, false
	}
	end = start + quoteEnd
	return line[start:end], start, end, true
}
