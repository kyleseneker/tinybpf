package transform

import (
	"fmt"
	"strings"
)

// isIdentChar checks if a byte is a valid identifier character.
func isIdentChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '_' || c == '.'
}

// parseFuncName extracts the function name from a trimmed line starting with
// prefix ("define " or "declare ") followed by ... @name(. The noLeadingDot
// flag rejects identifiers starting with '.', which is invalid for defines.
func parseFuncName(trimmed, prefix string, noLeadingDot bool) (string, bool) {
	if !strings.HasPrefix(trimmed, prefix) {
		return "", false
	}
	atIdx := strings.IndexByte(trimmed, '@')
	if atIdx < 0 {
		return "", false
	}
	start := atIdx + 1
	if start >= len(trimmed) || !isIdentChar(trimmed[start]) || (noLeadingDot && trimmed[start] == '.') {
		return "", false
	}
	end := start + 1
	for end < len(trimmed) && isIdentChar(trimmed[end]) {
		end++
	}
	if end >= len(trimmed) || trimmed[end] != '(' {
		return "", false
	}
	return trimmed[start:end], true
}

func parseDefineName(trimmed string) (string, bool) {
	return parseFuncName(trimmed, "define ", true)
}

func parseDeclareName(trimmed string) (string, bool) {
	return parseFuncName(trimmed, "declare ", false)
}

// parseGlobalName extracts the global name from a trimmed "@name = ..." line.
func parseGlobalName(trimmed string) (string, bool) {
	if len(trimmed) < 3 || trimmed[0] != '@' || !isIdentChar(trimmed[1]) {
		return "", false
	}
	i := 2
	for i < len(trimmed) && isIdentChar(trimmed[i]) {
		i++
	}
	nameEnd := i
	for i < len(trimmed) && (trimmed[i] == ' ' || trimmed[i] == '\t') {
		i++
	}
	if i >= len(trimmed) || trimmed[i] != '=' {
		return "", false
	}
	return trimmed[1:nameEnd], true
}

// extractMetadataID parses "!N = ..." and returns N, or -1 on failure.
func extractMetadataID(line string) int {
	if len(line) < 2 || line[0] != '!' || line[1] < '0' || line[1] > '9' {
		return -1
	}
	n := int(line[1] - '0')
	for i := 2; i < len(line) && line[i] >= '0' && line[i] <= '9'; i++ {
		n = n*10 + int(line[i]-'0')
	}
	return n
}

// irSnippet returns up to radius lines before and after index center for error context.
func irSnippet(lines []string, center, radius int) string {
	start := center - radius
	if start < 0 {
		start = 0
	}
	end := center + radius + 1
	if end > len(lines) {
		end = len(lines)
	}
	var b strings.Builder
	for i := start; i < end; i++ {
		marker := "  "
		if i == center {
			marker = "> "
		}
		fmt.Fprintf(&b, "%s%d: %s\n", marker, i+1, lines[i])
	}
	return b.String()
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

// hasDeclare reports whether any declare line contains substr.
func hasDeclare(lines []string, substr string) bool {
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "declare") && strings.Contains(trimmed, substr) {
			return true
		}
	}
	return false
}

// insertBeforeFunc splices toInsert lines before the first declare or define
// statement. Falls back to appending if no function statement is found.
func insertBeforeFunc(lines []string, toInsert ...string) []string {
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "declare ") || strings.HasPrefix(trimmed, "define ") {
			result := make([]string, 0, len(lines)+len(toInsert))
			result = append(result, lines[:i]...)
			result = append(result, toInsert...)
			result = append(result, lines[i:]...)
			return result
		}
	}
	return append(lines, toInsert...)
}
