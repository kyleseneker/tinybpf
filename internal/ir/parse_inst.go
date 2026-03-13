package ir

import (
	"strconv"
	"strings"
)

// parseInstruction classifies a single IR instruction line and extracts
// structured fields for call, getelementptr, and alloca instructions.
// All other instructions are preserved as InstOther with only SSAName and Raw.
func parseInstruction(line, trimmed string) *Instruction {
	inst := &Instruction{Raw: line}
	inst.Metadata = extractMetaAttachments(line)

	ssaName, afterAssign := extractSSAAssign(trimmed)
	inst.SSAName = ssaName

	work := afterAssign
	if work == "" {
		work = trimmed
	}

	switch {
	case containsCallKeyword(work):
		if ci := tryParseCall(work); ci != nil {
			inst.Kind = InstCall
			inst.Call = ci
			return inst
		}
	case strings.Contains(work, "getelementptr"):
		if gi := tryParseGEP(work); gi != nil {
			inst.Kind = InstGEP
			inst.GEP = gi
			return inst
		}
	case strings.Contains(work, "alloca "):
		if ai := tryParseAlloca(work); ai != nil {
			inst.Kind = InstAlloca
			inst.Alloca = ai
			return inst
		}
	}

	inst.Kind = InstOther
	return inst
}

func extractSSAAssign(trimmed string) (string, string) {
	if len(trimmed) < 2 || trimmed[0] != '%' {
		if len(trimmed) > 2 && trimmed[0] == ' ' && trimmed[1] == ' ' {
			inner := strings.TrimSpace(trimmed)
			if len(inner) > 0 && inner[0] == '%' {
				return extractSSAAssign(inner)
			}
		}
		return "", ""
	}
	eqIdx := strings.Index(trimmed, " = ")
	if eqIdx < 0 {
		return "", ""
	}
	name := strings.TrimSpace(trimmed[:eqIdx])
	if !strings.HasPrefix(name, "%") {
		return "", ""
	}
	for _, c := range name[1:] {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '.') {
			return "", ""
		}
	}
	return name, strings.TrimSpace(trimmed[eqIdx+3:])
}

func containsCallKeyword(s string) bool {
	return strings.Contains(s, "call ") || strings.HasPrefix(strings.TrimSpace(s), "call ")
}

func tryParseCall(work string) *CallInst {
	callIdx := strings.Index(work, "call ")
	if callIdx < 0 {
		return nil
	}

	ci := &CallInst{}
	ci.Tail = strings.TrimSpace(work[:callIdx])

	afterCall := work[callIdx+5:]

	atIdx := strings.IndexByte(afterCall, '@')
	intIdx := strings.Index(afterCall, "inttoptr")
	if atIdx < 0 && intIdx < 0 {
		return nil
	}

	var calleeStart int
	if intIdx >= 0 && (atIdx < 0 || intIdx < atIdx) {
		ci.RetType = strings.TrimSpace(afterCall[:intIdx])
		parenEnd := findClosingParen(afterCall, intIdx)
		if parenEnd < 0 {
			return nil
		}
		ci.Callee = strings.TrimSpace(afterCall[intIdx : parenEnd+1])
		calleeStart = parenEnd + 1
	} else if atIdx >= 0 {
		ci.RetType = strings.TrimSpace(afterCall[:atIdx])
		nameEnd := atIdx + 1
		for nameEnd < len(afterCall) && isIdentChar(afterCall[nameEnd]) {
			nameEnd++
		}
		ci.Callee = afterCall[atIdx:nameEnd]
		calleeStart = nameEnd
	} else {
		return nil
	}

	rest := afterCall[calleeStart:]
	openParen := strings.IndexByte(rest, '(')
	if openParen < 0 {
		return ci
	}
	closeParen := findClosingParen(rest, openParen)
	if closeParen < 0 {
		ci.Args = rest[openParen+1:]
		return ci
	}
	ci.Args = rest[openParen+1 : closeParen]
	return ci
}

func tryParseGEP(work string) *GEPInst {
	gepIdx := strings.Index(work, "getelementptr")
	if gepIdx < 0 {
		return nil
	}

	gi := &GEPInst{}
	after := strings.TrimSpace(work[gepIdx+len("getelementptr"):])

	if strings.HasPrefix(after, "inbounds") {
		gi.Inbounds = true
		after = strings.TrimSpace(after[len("inbounds"):])
	}

	for strings.HasPrefix(after, "nuw") || strings.HasPrefix(after, "nsw") {
		flag := after[:3]
		if gi.Flags != "" {
			gi.Flags += " "
		}
		gi.Flags += flag
		after = strings.TrimSpace(after[3:])
	}

	parts := splitGEPOperands(after)
	if len(parts) < 3 {
		return nil
	}

	gi.BaseType = parts[0]

	ptrParts := strings.Fields(parts[1])
	if len(ptrParts) >= 2 {
		gi.PtrType = ptrParts[0]
		gi.Base = ptrParts[1]
	} else if len(ptrParts) == 1 {
		gi.Base = ptrParts[0]
	}

	for _, idx := range parts[2:] {
		idx = strings.TrimSpace(idx)
		if metaIdx := strings.Index(idx, "!"); metaIdx > 0 {
			idx = strings.TrimSpace(idx[:metaIdx])
		}
		if idx != "" {
			gi.Indices = append(gi.Indices, idx)
		}
	}

	return gi
}

func tryParseAlloca(work string) *AllocaInst {
	allocaIdx := strings.Index(work, "alloca ")
	if allocaIdx < 0 {
		return nil
	}

	after := strings.TrimSpace(work[allocaIdx+7:])
	ai := &AllocaInst{}

	commaIdx := strings.IndexByte(after, ',')
	if commaIdx >= 0 {
		ai.Type = strings.TrimSpace(after[:commaIdx])
		rest := after[commaIdx+1:]
		ai.Align = parseAlignFromRest(rest)
	} else {
		metaIdx := strings.Index(after, "!")
		if metaIdx > 0 {
			ai.Type = strings.TrimSpace(after[:metaIdx])
		} else {
			ai.Type = after
		}
	}

	if strings.HasPrefix(ai.Type, "[") {
		brEnd := findMatchingBrace(ai.Type, '[', ']')
		if brEnd >= 0 {
			ai.Type = ai.Type[:brEnd+1]
		}
	}

	return ai
}

func parseAlignFromRest(rest string) int {
	idx := strings.Index(rest, "align ")
	if idx < 0 {
		return 0
	}
	start := idx + 6
	end := start
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	if end == start {
		return 0
	}
	n, _ := strconv.Atoi(rest[start:end])
	return n
}

func splitGEPOperands(s string) []string {
	var parts []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	if f := strings.TrimSpace(s[start:]); f != "" {
		parts = append(parts, f)
	}
	return parts
}

func findClosingParen(s string, openIdx int) int {
	depth := 0
	for i := openIdx; i < len(s); i++ {
		if s[i] == '(' {
			depth++
		} else if s[i] == ')' {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}
