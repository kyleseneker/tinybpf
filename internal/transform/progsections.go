package transform

import (
	"fmt"
	"regexp"
	"strings"
)

// assignProgramSections adds BPF program section attributes to function definitions
// and ".maps" section attributes to map globals that don't already have one.
func assignProgramSections(lines []string, sections map[string]string) []string {
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		if name, ok := parseDefineName(trimmed); ok {
			sec := ""
			if sections != nil {
				sec = sections[name]
			}
			if sec == "" {
				sec = name
			}
			if !strings.Contains(line, " section ") {
				lines[i] = insertSection(line, sec)
			}
		}

		if isGlobalLine(trimmed) && strings.Contains(line, "bpfMapDef") {
			if strings.Contains(line, " internal ") {
				lines[i] = strings.Replace(lines[i], " internal ", " ", 1)
				line = lines[i]
			}
			if !strings.Contains(line, " section ") {
				if idx := strings.Index(line, ", align"); idx >= 0 {
					lines[i] = line[:idx] + `, section ".maps"` + line[idx:]
				} else {
					lines[i] = strings.TrimRight(line, " \t") + `, section ".maps"`
				}
			}
		}
	}
	return lines
}

// insertSection inserts a section attribute into a define line before any metadata attachments.
func insertSection(line, sec string) string {
	attr := fmt.Sprintf(` section "%s"`, sec)

	braceIdx := strings.LastIndex(line, "{")
	if braceIdx < 0 {
		return line + attr
	}

	// Walk backward past metadata attachments
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
