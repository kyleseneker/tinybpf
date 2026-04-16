package transform

import (
	"strings"

	"github.com/kyleseneker/tinybpf/internal/ir"
)

const (
	bpfDatalayoutValue = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
	bpfTripleValue     = "bpf"
)

// strippedAttrPrefixes lists attribute prefixes that are invalid for BPF targets.
var strippedAttrPrefixes = []string{
	`"target-cpu"`,
	`"target-features"`,
	`allockind(`,
	`allocsize(`,
	`"alloc-family"`,
}

// moduleRewriteModule sets BPF target properties and strips invalid attributes in a single pass.
func moduleRewriteModule(m *ir.Module) error {
	if err := retargetModule(m); err != nil {
		return err
	}
	return stripAttributesModule(m)
}

// retargetModule sets the module's data layout and triple to BPF targets.
func retargetModule(m *ir.Module) error {
	m.DataLayout = bpfDatalayoutValue
	m.Triple = bpfTripleValue
	return nil
}

// stripAttributesModule removes target-specific attributes from attribute groups
// by tokenizing the body and filtering out BPF-invalid entries. LLVM's `opt`
// rejects empty attribute groups (`attributes #N = {  }`), so if stripping
// empties a group we substitute `nounwind` — benign and always true for BPF.
func stripAttributesModule(m *ir.Module) error {
	for _, ag := range m.AttrGroups {
		tokens := tokenizeAttrs(ag.Body)
		filtered := make([]string, 0, len(tokens))
		changed := false
		for _, tok := range tokens {
			if isStrippedAttr(tok) {
				changed = true
				continue
			}
			filtered = append(filtered, tok)
		}
		if changed {
			if len(filtered) == 0 {
				filtered = []string{"nounwind"}
			}
			ag.Body = strings.Join(filtered, " ")
			ag.Modified = true
		}
	}
	return nil
}

// tokenizeAttrs splits an LLVM attribute body string into individual attribute
// tokens, handling parenthesized groups (e.g. `memory(readwrite)`,
// `allockind("alloc,zeroed")`) and quoted key=value pairs as single tokens.
func tokenizeAttrs(body string) []string {
	body = strings.TrimSpace(body)
	if body == "" {
		return nil
	}
	var tokens []string
	i := 0
	for i < len(body) {
		// skip whitespace
		for i < len(body) && body[i] == ' ' {
			i++
		}
		if i >= len(body) {
			break
		}
		start := i
		if body[i] == '"' {
			// Quoted attribute: "key"="value" or just "key"
			i = skipQuotedAttr(body, i)
		} else {
			// Bare word, possibly followed by parenthesized args
			i = skipBareAttr(body, i)
		}
		tokens = append(tokens, body[start:i])
	}
	return tokens
}

// skipQuotedAttr advances past a quoted attribute starting at pos.
// Handles "key"="value" pairs by consuming the =value part too.
func skipQuotedAttr(body string, pos int) int {
	pos = skipQuotedString(body, pos)
	if pos < len(body) && body[pos] == '=' {
		pos++ // skip '='
		if pos < len(body) && body[pos] == '"' {
			pos = skipQuotedString(body, pos)
		} else {
			// bare value after =
			for pos < len(body) && body[pos] != ' ' {
				pos++
			}
		}
	}
	return pos
}

// skipBareAttr advances past a bare (unquoted) attribute starting at pos.
// Handles parenthesized groups like memory(readwrite, inaccessiblemem: write).
func skipBareAttr(body string, pos int) int {
	for pos < len(body) && body[pos] != ' ' && body[pos] != '(' {
		pos++
	}
	if pos < len(body) && body[pos] == '(' {
		pos = skipParenGroup(body, pos)
	}
	return pos
}

// skipQuotedString advances past a double-quoted string starting at pos.
func skipQuotedString(body string, pos int) int {
	if pos >= len(body) || body[pos] != '"' {
		return pos
	}
	pos++ // opening quote
	for pos < len(body) && body[pos] != '"' {
		pos++
	}
	if pos < len(body) {
		pos++ // closing quote
	}
	return pos
}

// skipParenGroup advances past a parenthesized group starting at pos.
func skipParenGroup(body string, pos int) int {
	if pos >= len(body) || body[pos] != '(' {
		return pos
	}
	depth := 1
	pos++ // opening paren
	for pos < len(body) && depth > 0 {
		switch body[pos] {
		case '(':
			depth++
		case ')':
			depth--
		}
		pos++
	}
	return pos
}

// isStrippedAttr reports whether an attribute token should be removed for BPF.
func isStrippedAttr(tok string) bool {
	for _, prefix := range strippedAttrPrefixes {
		if strings.HasPrefix(tok, prefix) {
			return true
		}
	}
	return false
}
