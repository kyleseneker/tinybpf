package transform

import "strings"

// addLicense injects a "license" section with "GPL" if one is not already present.
func addLicense(lines []string) []string {
	for _, line := range lines {
		if strings.Contains(line, `section "license"`) {
			return lines
		}
	}
	decl := `@_license = global [4 x i8] c"GPL\00", section "license", align 1`
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "define ") {
			newLines := make([]string, 0, len(lines)+2)
			newLines = append(newLines, lines[:i]...)
			newLines = append(newLines, decl, "")
			newLines = append(newLines, lines[i:]...)
			return newLines
		}
	}
	return append(lines, decl)
}
