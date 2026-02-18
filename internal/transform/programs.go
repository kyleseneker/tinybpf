package transform

import (
	"fmt"
	"io"
	"strings"
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

// extractPrograms removes non-program define blocks and runtime globals.
func extractPrograms(lines []string, programNames []string, verbose bool, w io.Writer) ([]string, error) {
	type defineBlock struct {
		name      string
		startLine int
		endLine   int
	}
	var blocks []defineBlock
	inDef := false
	depth := 0
	var cur defineBlock

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !inDef {
			if m := reDefine.FindStringSubmatch(trimmed); m != nil {
				inDef = true
				cur = defineBlock{name: m[1], startLine: i}
				depth = strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
				if depth <= 0 {
					cur.endLine = i
					blocks = append(blocks, cur)
					inDef = false
				}
			}
			continue
		}
		depth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
		if depth <= 0 {
			cur.endLine = i
			blocks = append(blocks, cur)
			inDef = false
		}
	}

	programSet := make(map[string]bool)
	if len(programNames) > 0 {
		for _, n := range programNames {
			programSet[n] = true
		}
	} else {
		for _, b := range blocks {
			if !isRuntimeFunc(b.name) {
				programSet[b.name] = true
			}
		}
	}
	if len(programSet) == 0 {
		names := make([]string, len(blocks))
		for i, b := range blocks {
			names[i] = b.name
		}
		return nil, fmt.Errorf("transform: no program functions found among: %v", names)
	}
	if verbose {
		for name := range programSet {
			fmt.Fprintf(w, "[transform] keeping program: %s\n", name)
		}
	}

	remove := make(map[int]bool)

	for _, b := range blocks {
		if !programSet[b.name] {
			for j := b.startLine; j <= b.endLine; j++ {
				remove[j] = true
			}
		}
	}

	for i, line := range lines {
		if remove[i] {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if m := reGlobal.FindStringSubmatch(trimmed); m != nil {
			name := m[1]
			if strings.HasPrefix(name, "runtime.") || name == ".string" {
				remove[i] = true
			}
		}
	}

	result := make([]string, 0, len(lines)/2)
	for i, line := range lines {
		if !remove[i] {
			result = append(result, line)
		}
	}
	return result, nil
}
