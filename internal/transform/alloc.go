package transform

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var reAllocCall = regexp.MustCompile(
	`(\s*)(%\w+)\s*=\s*call\s+.*@runtime\.alloc\(i64\s+(\d+)`,
)

type allocInfo struct {
	lineIdx int
	varName string
	size    int
	indent  string
}

type allocFuncInfo struct {
	startIdx int
	entryIdx int
	allocs   []allocInfo
}

// scanAllocSites scans lines for define blocks containing runtime.alloc
// calls and returns per-function allocation metadata.
func scanAllocSites(lines []string) ([]allocFuncInfo, error) {
	var funcs []allocFuncInfo
	var cur *allocFuncInfo
	inDef := false
	depth := 0

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !inDef {
			if _, ok := parseDefineName(trimmed); ok {
				inDef = true
				depth = strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
				funcs = append(funcs, allocFuncInfo{startIdx: i, entryIdx: -1})
				cur = &funcs[len(funcs)-1]
				if depth <= 0 {
					inDef = false
					cur = nil
				}
			}
			continue
		}
		depth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
		if trimmed == "entry:" && cur != nil && cur.entryIdx < 0 {
			cur.entryIdx = i
		}
		if strings.Contains(line, "@runtime.alloc") && reAllocCall.FindStringSubmatch(line) == nil {
			return nil, fmt.Errorf("line %d references @runtime.alloc but does not match expected call pattern: %s",
				i+1, trimmed)
		}
		if m := reAllocCall.FindStringSubmatch(line); m != nil && cur != nil {
			size, err := strconv.Atoi(m[3])
			if err != nil {
				return nil, fmt.Errorf("parse alloc size: %w", err)
			}
			cur.allocs = append(cur.allocs, allocInfo{
				lineIdx: i,
				varName: m[2],
				size:    size,
				indent:  m[1],
			})
		}
		if depth <= 0 {
			inDef = false
			cur = nil
		}
	}
	return funcs, nil
}

// replaceAlloc converts runtime.alloc heap calls into entry-block stack allocas paired with memset zero-fills at the original call site.
func replaceAlloc(lines []string) ([]string, error) {
	funcs, err := scanAllocSites(lines)
	if err != nil {
		return nil, err
	}

	needMemset := false
	for fi := len(funcs) - 1; fi >= 0; fi-- {
		f := funcs[fi]
		if len(f.allocs) == 0 {
			continue
		}
		needMemset = true

		insertIdx := f.startIdx + 1
		if f.entryIdx >= 0 {
			insertIdx = f.entryIdx + 1
		}

		for _, a := range f.allocs {
			lines[a.lineIdx] = fmt.Sprintf(
				"%scall void @llvm.memset.p0.i64(ptr align 4 %s, i8 0, i64 %d, i1 false)",
				a.indent, a.varName, a.size)
		}

		allocas := make([]string, len(f.allocs))
		for j, a := range f.allocs {
			allocas[j] = fmt.Sprintf("  %s = alloca [%d x i8], align 4", a.varName, a.size)
		}

		newLines := make([]string, 0, len(lines)+len(allocas))
		newLines = append(newLines, lines[:insertIdx]...)
		newLines = append(newLines, allocas...)
		newLines = append(newLines, lines[insertIdx:]...)
		lines = newLines
	}

	if needMemset && !hasDeclare(lines, "@llvm.memset.p0.i64") {
		lines = insertMemsetDecl(lines)
	}

	return lines, nil
}

const memsetDecl = "declare void @llvm.memset.p0.i64(ptr, i8, i64, i1)"

func insertMemsetDecl(lines []string) []string {
	return insertBeforeFunc(lines, memsetDecl, "")
}
