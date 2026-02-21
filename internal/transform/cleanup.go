package transform

import (
	"regexp"
	"strings"
)

var (
	reAttrRef = regexp.MustCompile(`#(\d+)`)
	reAttrDef = regexp.MustCompile(`^attributes #(\d+)`)
	reAtIdent = regexp.MustCompile(`@[\w.]+`)
)

// cleanup removes orphaned declares, globals, attribute groups, and stale "; Function Attrs:" comments, then condenses blank lines.
func cleanup(lines []string) []string {
	remove := make([]bool, len(lines))

	type ref struct {
		name string
		idx  int
	}

	identLines := make(map[string][]int)
	for i, line := range lines {
		for _, m := range reAtIdent.FindAllString(line, -1) {
			identLines[m] = append(identLines[m], i)
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
		if m := reDeclare.FindStringSubmatch(trimmed); m != nil {
			decls = append(decls, ref{name: m[1], idx: i})
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
		if m := reGlobal.FindStringSubmatch(trimmed); m != nil {
			globals = append(globals, ref{name: m[1], idx: i})
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
		if reAttrDef.MatchString(trimmed) {
			continue
		}
		for _, m := range reAttrRef.FindAllStringSubmatch(line, -1) {
			used[m[1]] = true
		}
	}
	for i, line := range lines {
		if remove[i] {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if m := reAttrDef.FindStringSubmatch(trimmed); m != nil {
			if !used[m[1]] {
				remove[i] = true
			}
		}
	}

	// Remove orphaned "; Function Attrs:" comments
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

	var result []string
	prevBlank := false
	for i, line := range lines {
		if remove[i] {
			continue
		}
		blank := strings.TrimSpace(line) == ""
		if blank && prevBlank {
			continue
		}
		result = append(result, line)
		prevBlank = blank
	}

	for len(result) > 0 && strings.TrimSpace(result[len(result)-1]) == "" {
		result = result[:len(result)-1]
	}
	result = append(result, "")
	return result
}
