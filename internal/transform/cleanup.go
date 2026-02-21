package transform

import "strings"

// cleanup removes orphaned declares, globals, attribute groups, and stale "; Function Attrs:" comments, then condenses blank lines.
func cleanup(lines []string) []string {
	remove := make([]bool, len(lines))

	type ref struct {
		name string
		idx  int
	}

	identLines := make(map[string][]int)
	for i, line := range lines {
		for pos := 0; pos < len(line); pos++ {
			if line[pos] != '@' {
				continue
			}
			j := pos + 1
			for j < len(line) && isIdentChar(line[j]) {
				j++
			}
			if j > pos+1 {
				identLines[line[pos:j]] = append(identLines[line[pos:j]], i)
				pos = j - 1
			}
		}
	}

	referencedElsewhere := func(name string, defIdx int) bool {
		for _, idx := range identLines["@"+name] {
			if idx != defIdx {
				return true
			}
		}
		return false
	}

	var decls []ref
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if name, ok := parseDeclareName(trimmed); ok {
			decls = append(decls, ref{name: name, idx: i})
		}
	}
	for _, d := range decls {
		if !referencedElsewhere(d.name, d.idx) {
			remove[d.idx] = true
			if d.idx > 0 && strings.HasPrefix(strings.TrimSpace(lines[d.idx-1]), ";") {
				remove[d.idx-1] = true
			}
		}
	}

	var globals []ref
	for i, line := range lines {
		if remove[i] {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if name, ok := parseGlobalName(trimmed); ok {
			globals = append(globals, ref{name: name, idx: i})
		}
	}
	for _, g := range globals {
		if strings.Contains(lines[g.idx], " section ") {
			continue
		}
		if !referencedElsewhere(g.name, g.idx) {
			remove[g.idx] = true
		}
	}

	used := make(map[string]bool)
	for i, line := range lines {
		if remove[i] {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "attributes #") {
			continue
		}
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
	for i, line := range lines {
		if remove[i] {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if id, ok := parseAttrDef(trimmed); ok {
			if !used[id] {
				remove[i] = true
			}
		}
	}

	for i, line := range lines {
		if remove[i] {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "; Function Attrs:") {
			continue
		}
		hasTarget := false
		for j := i + 1; j < len(lines); j++ {
			if remove[j] {
				continue
			}
			next := strings.TrimSpace(lines[j])
			if next == "" {
				continue
			}
			if strings.HasPrefix(next, "define ") || strings.HasPrefix(next, "declare ") {
				hasTarget = true
			}
			break
		}
		if !hasTarget {
			remove[i] = true
		}
	}

	n := 0
	prevBlank := false
	for i, line := range lines {
		if remove[i] {
			continue
		}
		blank := strings.TrimSpace(line) == ""
		if blank && prevBlank {
			continue
		}
		lines[n] = line
		n++
		prevBlank = blank
	}
	lines = lines[:n]
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	return append(lines, "")
}

// isIdentChar checks if a byte is a valid identifier character.
func isIdentChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '_' || c == '.'
}

// parseAttrDef parses an attribute definition from a trimmed string.
func parseAttrDef(trimmed string) (string, bool) {
	const prefix = "attributes #"
	if !strings.HasPrefix(trimmed, prefix) {
		return "", false
	}
	rest := trimmed[len(prefix):]
	i := 0
	for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
		i++
	}
	if i == 0 {
		return "", false
	}
	return rest[:i], true
}
