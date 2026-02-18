package transform

import "regexp"

var (
	reAttrLine       = regexp.MustCompile(`^attributes #\d+`)
	reTargetCPU      = regexp.MustCompile(`"target-cpu"="[^"]*"`)
	reTargetFeatures = regexp.MustCompile(`"target-features"="[^"]*"`)
	reAllocKind      = regexp.MustCompile(`allockind\("[^"]*"\)`)
	reAllocSize      = regexp.MustCompile(`allocsize\(\d+\)`)
	reAllocFamily    = regexp.MustCompile(`"alloc-family"="[^"]*"`)
	reMultiSpace     = regexp.MustCompile(`  +`)
)

// stripAttributes removes host-specific entries from attribute groups.
func stripAttributes(lines []string) []string {
	for i, line := range lines {
		if !reAttrLine.MatchString(line) {
			continue
		}
		line = reTargetCPU.ReplaceAllString(line, "")
		line = reTargetFeatures.ReplaceAllString(line, "")
		line = reAllocKind.ReplaceAllString(line, "")
		line = reAllocSize.ReplaceAllString(line, "")
		line = reAllocFamily.ReplaceAllString(line, "")
		line = reMultiSpace.ReplaceAllString(line, " ")
		lines[i] = line
	}
	return lines
}
