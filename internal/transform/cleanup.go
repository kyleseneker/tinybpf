package transform

import "strings"

type identRef struct {
	name string
	idx  int
}

// cleanup removes orphaned declares, globals, attribute groups, and stale "; Function Attrs:" comments, then condenses blank lines.
func cleanup(lines []string) ([]string, error) {
	remove := make([]bool, len(lines))
	identLines := buildIdentIndex(lines)

	markUnrefDeclares(lines, remove, identLines)
	markUnrefGlobals(lines, remove, identLines)
	markUnusedAttrs(lines, remove)
	markOrphanedAttrComments(lines, remove)

	return compactLines(lines, remove), nil
}

// buildIdentIndex scans all lines for @-prefixed identifiers and records
// which line numbers each identifier appears on.
func buildIdentIndex(lines []string) map[string][]int {
	index := make(map[string][]int)
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
				ident := line[pos:j]
				index[ident] = append(index[ident], i)
				pos = j - 1
			}
		}
	}
	return index
}

// referencedElsewhere returns true if @name appears on any line other than defIdx.
func referencedElsewhere(name string, defIdx int, identLines map[string][]int) bool {
	for _, idx := range identLines["@"+name] {
		if idx != defIdx {
			return true
		}
	}
	return false
}

// markUnrefDeclares marks unreferenced declare statements (and their
// preceding comment lines) for removal.
func markUnrefDeclares(lines []string, remove []bool, identLines map[string][]int) {
	var decls []identRef
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if name, ok := parseDeclareName(trimmed); ok {
			decls = append(decls, identRef{name: name, idx: i})
		}
	}
	for _, d := range decls {
		if !referencedElsewhere(d.name, d.idx, identLines) {
			remove[d.idx] = true
			if d.idx > 0 && strings.HasPrefix(strings.TrimSpace(lines[d.idx-1]), ";") {
				remove[d.idx-1] = true
			}
		}
	}
}

// markUnrefGlobals marks unreferenced global definitions for removal,
// skipping globals that have an explicit section assignment.
func markUnrefGlobals(lines []string, remove []bool, identLines map[string][]int) {
	var globals []identRef
	for i, line := range lines {
		if remove[i] {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if name, ok := parseGlobalName(trimmed); ok {
			globals = append(globals, identRef{name: name, idx: i})
		}
	}
	for _, g := range globals {
		if strings.Contains(lines[g.idx], " section ") {
			continue
		}
		if !referencedElsewhere(g.name, g.idx, identLines) {
			remove[g.idx] = true
		}
	}
}

// markUnusedAttrs marks attribute group definitions that are never
// referenced by any non-removed line.
func markUnusedAttrs(lines []string, remove []bool) {
	used := collectUsedAttrIDs(lines, remove)
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
}

// collectUsedAttrIDs scans non-removed, non-definition lines for #N
// attribute references and returns the set of referenced IDs.
func collectUsedAttrIDs(lines []string, remove []bool) map[string]bool {
	used := make(map[string]bool)
	for i, line := range lines {
		if remove[i] {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "attributes #") {
			continue
		}
		for pos := range len(line) {
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
	return used
}

// markOrphanedAttrComments marks "; Function Attrs:" comments whose
// next non-blank, non-removed line is not a define or declare.
func markOrphanedAttrComments(lines []string, remove []bool) {
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
}

// compactLines filters out removed lines, collapses consecutive blank
// lines, and ensures the output ends with a single blank line.
func compactLines(lines []string, remove []bool) []string {
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
