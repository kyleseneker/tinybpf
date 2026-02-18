package transform

import "strings"

// stripMapPrefix renames Go package-qualified map globals in the ".maps" section to unqualified names.
func stripMapPrefix(lines []string) []string {
	type rename struct {
		oldRef string
		newRef string
	}
	var renames []rename

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(line, `section ".maps"`) {
			continue
		}
		m := reGlobal.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}
		name := m[1]
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
		return lines
	}

	for i, line := range lines {
		for _, r := range renames {
			if strings.Contains(line, r.oldRef) {
				lines[i] = strings.ReplaceAll(lines[i], r.oldRef, r.newRef)
				line = lines[i]
			}
		}
	}
	return lines
}
