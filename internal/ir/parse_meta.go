package ir

import "strings"

// parseMetadataNode parses a numbered metadata definition into a MetadataNode.
func parseMetadataNode(line, trimmed string, id int) *MetadataNode {
	mn := &MetadataNode{
		ID:  id,
		Raw: line,
	}

	eqIdx := strings.IndexByte(trimmed, '=')
	if eqIdx < 0 {
		return mn
	}
	rhs := strings.TrimSpace(trimmed[eqIdx+1:])

	if strings.HasPrefix(rhs, "distinct ") {
		rhs = strings.TrimSpace(rhs[9:])
	}

	if strings.HasPrefix(rhs, "!{") {
		mn.Tuple = parseTupleRefs(rhs)
		return mn
	}

	if strings.HasPrefix(rhs, "!DI") || strings.HasPrefix(rhs, "!DW") {
		parenIdx := strings.IndexByte(rhs, '(')
		if parenIdx > 1 {
			mn.Kind = rhs[1:parenIdx]
		}
		mn.Fields = parseDIFields(rhs)
	}

	return mn
}

// parseNamedMetadata parses a named metadata node into a NamedMetadata.
func parseNamedMetadata(line, trimmed string) *NamedMetadata {
	nm := &NamedMetadata{Raw: line}
	eqIdx := strings.IndexByte(trimmed, '=')
	if eqIdx < 0 {
		return nm
	}
	nm.Name = strings.TrimSpace(trimmed[1:eqIdx])
	rhs := strings.TrimSpace(trimmed[eqIdx+1:])
	if strings.HasPrefix(rhs, "!{") {
		nm.Refs = parseTupleRefs(rhs)
	}
	return nm
}

// parseTupleRefs extracts metadata references from "!{!0, !1, !2}".
func parseTupleRefs(s string) []string {
	inner := extractBraced(s, '{', '}')
	if inner == "" {
		return nil
	}
	parts := strings.Split(inner, ",")
	var refs []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			refs = append(refs, p)
		}
	}
	return refs
}

// parseDIFields extracts key-value pairs from a DI metadata node's parenthesized body.
func parseDIFields(s string) map[string]string {
	parenIdx := strings.IndexByte(s, '(')
	if parenIdx < 0 {
		return nil
	}
	closeIdx := strings.LastIndexByte(s, ')')
	if closeIdx <= parenIdx {
		return nil
	}
	body := s[parenIdx+1 : closeIdx]
	return splitDIKeyValues(body)
}

// splitDIKeyValues splits comma-separated "key: value" pairs into a map.
func splitDIKeyValues(body string) map[string]string {
	fields := make(map[string]string)
	kvPairs := splitDIPairs(body)
	for _, kv := range kvPairs {
		colonIdx := strings.IndexByte(kv, ':')
		if colonIdx <= 0 {
			continue
		}
		key := strings.TrimSpace(kv[:colonIdx])
		val := strings.TrimSpace(kv[colonIdx+1:])
		if strings.HasPrefix(val, `"`) && strings.HasSuffix(val, `"`) && len(val) >= 2 {
			val = val[1 : len(val)-1]
		}
		fields[key] = val
	}
	return fields
}

// splitDIPairs splits on commas, respecting nested delimiters and quoted strings.
func splitDIPairs(body string) []string {
	var pairs []string
	depth := 0
	inQuote := false
	start := 0
	for i := range len(body) {
		c := body[i]
		if c == '"' && (i == 0 || body[i-1] != '\\') {
			inQuote = !inQuote
			continue
		}
		if inQuote {
			continue
		}
		switch c {
		case '(', '{':
			depth++
		case ')', '}':
			depth--
		case ',':
			if depth == 0 {
				pairs = append(pairs, strings.TrimSpace(body[start:i]))
				start = i + 1
			}
		}
	}
	if f := strings.TrimSpace(body[start:]); f != "" {
		pairs = append(pairs, f)
	}
	return pairs
}

// extractBraced returns the content between the first open and last close delimiter in s.
func extractBraced(s string, open, close byte) string {
	openIdx := strings.IndexByte(s, open)
	if openIdx < 0 {
		return ""
	}
	closeIdx := strings.LastIndexByte(s, close)
	if closeIdx <= openIdx {
		return ""
	}
	return s[openIdx+1 : closeIdx]
}
