package transform

import "strings"

// addLicense injects a "license" section with "GPL" if one is not already present.
func addLicense(lines []string) []string {
	for _, line := range lines {
		if strings.Contains(line, `section "license"`) {
			return lines
		}
	}
	return insertBeforeFunc(lines,
		`@_license = global [4 x i8] c"GPL\00", section "license", align 1`, "")
}
