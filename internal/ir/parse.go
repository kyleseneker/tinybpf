package ir

import (
	"fmt"
	"strconv"
	"strings"
)

// Parse reads LLVM IR text and returns a structured Module. It recognizes
// the subset of IR that TinyGo emits: module header, type definitions,
// globals, declares, defines (with basic blocks and instructions), attribute
// groups, and metadata. Unrecognized constructs are preserved as-is.
func Parse(input string) (*Module, error) {
	lines := strings.Split(input, "\n")
	m := &Module{}
	p := &parser{lines: lines, mod: m}
	if err := p.parseModule(); err != nil {
		return nil, err
	}
	return m, nil
}

type parser struct {
	lines []string
	pos   int
	mod   *Module
}

func (p *parser) atEnd() bool {
	return p.pos >= len(p.lines)
}

func (p *parser) peek() string {
	if p.atEnd() {
		return ""
	}
	return p.lines[p.pos]
}

func (p *parser) advance() string {
	line := p.lines[p.pos]
	p.pos++
	return line
}

func (p *parser) parseModule() error {
	for !p.atEnd() {
		line := p.peek()
		trimmed := strings.TrimSpace(line)

		switch {
		case trimmed == "":
			p.mod.Entries = append(p.mod.Entries, TopLevelEntry{Kind: TopBlank, Raw: line})
			p.advance()

		case strings.HasPrefix(trimmed, ";"):
			p.mod.Entries = append(p.mod.Entries, TopLevelEntry{Kind: TopComment, Raw: line})
			p.advance()

		case strings.HasPrefix(trimmed, "source_filename"):
			p.mod.SourceFilename = extractQuoted(trimmed, "source_filename")
			p.mod.Entries = append(p.mod.Entries, TopLevelEntry{Kind: TopSourceFilename, Raw: line})
			p.advance()

		case strings.HasPrefix(trimmed, "target datalayout"):
			p.mod.DataLayout = extractQuoted(trimmed, "target datalayout")
			p.mod.Entries = append(p.mod.Entries, TopLevelEntry{Kind: TopDataLayout, Raw: line})
			p.advance()

		case strings.HasPrefix(trimmed, "target triple"):
			p.mod.Triple = extractQuoted(trimmed, "target triple")
			p.mod.Entries = append(p.mod.Entries, TopLevelEntry{Kind: TopTriple, Raw: line})
			p.advance()

		case strings.HasPrefix(trimmed, "%") && strings.Contains(trimmed, "= type"):
			td := p.parseTypeDef(line, trimmed)
			p.mod.TypeDefs = append(p.mod.TypeDefs, td)
			p.mod.Entries = append(p.mod.Entries, TopLevelEntry{Kind: TopTypeDef, Raw: line, TypeDef: td})
			p.advance()

		case strings.HasPrefix(trimmed, "@") && strings.Contains(trimmed, "=") && !strings.HasPrefix(trimmed, "@llvm."):
			g := parseGlobal(line, trimmed)
			if g != nil {
				p.mod.Globals = append(p.mod.Globals, g)
				p.mod.Entries = append(p.mod.Entries, TopLevelEntry{Kind: TopGlobal, Raw: line, Global: g})
			} else {
				p.mod.Entries = append(p.mod.Entries, TopLevelEntry{Kind: TopComment, Raw: line})
			}
			p.advance()

		case strings.HasPrefix(trimmed, "declare "):
			d := parseDeclare(line, trimmed)
			p.mod.Declares = append(p.mod.Declares, d)
			p.mod.Entries = append(p.mod.Entries, TopLevelEntry{Kind: TopDeclare, Raw: line, Declare: d})
			p.advance()

		case strings.HasPrefix(trimmed, "define "):
			fn, err := p.parseFunction()
			if err != nil {
				return err
			}
			p.mod.Functions = append(p.mod.Functions, fn)
			p.mod.Entries = append(p.mod.Entries, TopLevelEntry{Kind: TopFunction, Function: fn})

		case strings.HasPrefix(trimmed, "attributes #"):
			ag := parseAttrGroup(line, trimmed)
			p.mod.AttrGroups = append(p.mod.AttrGroups, ag)
			p.mod.Entries = append(p.mod.Entries, TopLevelEntry{Kind: TopAttrGroup, Raw: line, AttrGroup: ag})
			p.advance()

		case strings.HasPrefix(trimmed, "!") && strings.Contains(trimmed, "="):
			id := extractMetadataID(trimmed)
			if id >= 0 {
				mn := parseMetadataNode(line, trimmed, id)
				p.mod.MetadataNodes = append(p.mod.MetadataNodes, mn)
				p.mod.Entries = append(p.mod.Entries, TopLevelEntry{Kind: TopMetadata, Raw: line, Metadata: mn})
			} else {
				nm := parseNamedMetadata(line, trimmed)
				p.mod.NamedMetadata = append(p.mod.NamedMetadata, nm)
				p.mod.Entries = append(p.mod.Entries, TopLevelEntry{Kind: TopNamedMetadata, Raw: line, NamedMetadata: nm})
			}
			p.advance()

		case strings.HasPrefix(trimmed, "#dbg_"):
			p.mod.Entries = append(p.mod.Entries, TopLevelEntry{Kind: TopComment, Raw: line})
			p.advance()

		default:
			p.mod.Entries = append(p.mod.Entries, TopLevelEntry{Kind: TopComment, Raw: line})
			p.advance()
		}
	}
	return nil
}

func (p *parser) parseTypeDef(line, trimmed string) *TypeDef {
	td := &TypeDef{Raw: line}
	eqIdx := strings.Index(trimmed, " = type")
	if eqIdx > 0 {
		td.Name = trimmed[:eqIdx]
	}
	braceStart := strings.IndexByte(trimmed, '{')
	braceEnd := strings.LastIndexByte(trimmed, '}')
	if braceStart >= 0 && braceEnd > braceStart {
		body := trimmed[braceStart+1 : braceEnd]
		td.Fields = splitStructFields(body)
	}
	return td
}

func parseGlobal(line, trimmed string) *Global {
	if len(trimmed) < 2 || trimmed[0] != '@' {
		return nil
	}
	nameEnd := 1
	for nameEnd < len(trimmed) && isIdentChar(trimmed[nameEnd]) {
		nameEnd++
	}
	if nameEnd >= len(trimmed) {
		return nil
	}
	name := trimmed[1:nameEnd]

	rest := strings.TrimSpace(trimmed[nameEnd:])
	if !strings.HasPrefix(rest, "=") {
		return nil
	}
	rest = strings.TrimSpace(rest[1:])

	g := &Global{Name: name, Raw: line}

	g.Linkage, g.Type, g.Initializer, rest = parseGlobalBody(rest)
	g.Section = extractSection(line)
	g.Align = extractAlign(line)
	g.Metadata = extractMetaAttachments(line)
	return g
}

func parseGlobalBody(rest string) (linkage, typeName, init, remaining string) {
	linkage, rest = consumeLinkage(rest)

	if strings.HasPrefix(rest, "zeroinitializer") {
		return linkage, "", "zeroinitializer", rest[len("zeroinitializer"):]
	}

	typeEnd := findTypeEnd(rest)
	if typeEnd > 0 {
		typeName = strings.TrimSpace(rest[:typeEnd])
		rest = strings.TrimSpace(rest[typeEnd:])
	}

	if strings.HasPrefix(rest, "{") {
		braceEnd := findMatchingBrace(rest, '{', '}')
		if braceEnd > 0 {
			init = rest[:braceEnd+1]
			rest = rest[braceEnd+1:]
		}
	} else if strings.HasPrefix(rest, "[") {
		bracketEnd := findMatchingBrace(rest, '[', ']')
		if bracketEnd > 0 {
			init = rest[:bracketEnd+1]
			rest = rest[bracketEnd+1:]
		}
	} else if strings.HasPrefix(rest, "zeroinitializer") {
		init = "zeroinitializer"
		rest = rest[len("zeroinitializer"):]
	} else if strings.HasPrefix(rest, `c"`) {
		qEnd := strings.Index(rest[2:], `"`)
		if qEnd >= 0 {
			init = rest[:qEnd+3]
			rest = rest[qEnd+3:]
		}
	} else {
		commaIdx := strings.IndexByte(rest, ',')
		if commaIdx > 0 {
			init = strings.TrimSpace(rest[:commaIdx])
			rest = rest[commaIdx:]
		} else {
			init = strings.TrimSpace(rest)
			rest = ""
		}
	}

	return linkage, typeName, init, rest
}

func consumeLinkage(s string) (string, string) {
	linkages := []string{
		"private unnamed_addr global ",
		"private unnamed_addr constant ",
		"internal unnamed_addr global ",
		"internal unnamed_addr constant ",
		"internal global ",
		"internal constant ",
		"global ",
		"constant ",
		"external global ",
		"external constant ",
	}
	for _, l := range linkages {
		if strings.HasPrefix(s, l) {
			return strings.TrimSpace(l), s[len(l):]
		}
	}
	return "", s
}

func findTypeEnd(s string) int {
	if len(s) == 0 {
		return 0
	}
	if s[0] == '%' {
		end := 1
		for end < len(s) && isIdentChar(s[end]) {
			end++
		}
		return end
	}
	if s[0] == '[' {
		brEnd := findMatchingBrace(s, '[', ']')
		if brEnd >= 0 {
			return brEnd + 1
		}
	}
	types := []string{"i8", "i16", "i32", "i64", "i128", "ptr", "void", "float", "double"}
	for _, t := range types {
		if strings.HasPrefix(s, t) && (len(s) == len(t) || !isIdentChar(s[len(t)])) {
			return len(t)
		}
	}
	return 0
}

func findMatchingBrace(s string, open, close byte) int {
	if len(s) == 0 || s[0] != open {
		return -1
	}
	depth := 0
	for i := 0; i < len(s); i++ {
		if s[i] == open {
			depth++
		} else if s[i] == close {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func parseDeclare(line, trimmed string) *Declare {
	d := &Declare{Raw: line}
	atIdx := strings.IndexByte(trimmed, '@')
	if atIdx < 0 {
		d.Name = ""
		return d
	}
	d.RetType = strings.TrimSpace(trimmed[len("declare "):atIdx])
	nameStart := atIdx + 1
	nameEnd := nameStart
	for nameEnd < len(trimmed) && isIdentChar(trimmed[nameEnd]) {
		nameEnd++
	}
	d.Name = trimmed[nameStart:nameEnd]
	if nameEnd < len(trimmed) && trimmed[nameEnd] == '(' {
		parenEnd := strings.LastIndexByte(trimmed, ')')
		if parenEnd > nameEnd {
			d.Params = trimmed[nameEnd+1 : parenEnd]
		}
	}
	return d
}

func (p *parser) parseFunction() (*Function, error) {
	line := p.advance()
	trimmed := strings.TrimSpace(line)
	fn := &Function{Raw: line}

	atIdx := strings.IndexByte(trimmed, '@')
	if atIdx < 0 {
		return nil, fmt.Errorf("line %d: define without function name: %s", p.pos, trimmed)
	}
	fn.RetType = extractDefineRetType(trimmed)
	nameStart := atIdx + 1
	nameEnd := nameStart
	for nameEnd < len(trimmed) && isIdentChar(trimmed[nameEnd]) {
		nameEnd++
	}
	fn.Name = trimmed[nameStart:nameEnd]

	if nameEnd < len(trimmed) && trimmed[nameEnd] == '(' {
		parenEnd := findCloseParen(trimmed, nameEnd)
		if parenEnd > nameEnd {
			fn.Params = trimmed[nameEnd+1 : parenEnd]
			fn.Attrs = strings.TrimSpace(trimmed[parenEnd+1:])
		}
	}

	fn.Section = extractSection(trimmed)
	fn.AttrRef = extractAttrRef(fn.Attrs)
	fn.Metadata = extractMetaAttachments(trimmed)

	depth := strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
	if depth <= 0 {
		return fn, nil
	}

	var curBlock *BasicBlock
	for !p.atEnd() && depth > 0 {
		bline := p.advance()
		fn.BodyRaw = append(fn.BodyRaw, bline)
		btrimmed := strings.TrimSpace(bline)

		depth += strings.Count(btrimmed, "{") - strings.Count(btrimmed, "}")

		if depth <= 0 {
			break
		}

		if btrimmed == "" || strings.HasPrefix(btrimmed, ";") || strings.HasPrefix(btrimmed, "#dbg_") {
			if curBlock != nil {
				curBlock.Instructions = append(curBlock.Instructions, &Instruction{
					Kind: InstOther,
					Raw:  bline,
				})
			}
			continue
		}

		if isLabel(btrimmed) {
			label := btrimmed[:len(btrimmed)-1]
			curBlock = &BasicBlock{Label: label}
			fn.Blocks = append(fn.Blocks, curBlock)
			continue
		}

		inst := parseInstruction(bline, btrimmed)
		if curBlock == nil {
			curBlock = &BasicBlock{Label: ""}
			fn.Blocks = append(fn.Blocks, curBlock)
		}
		curBlock.Instructions = append(curBlock.Instructions, inst)
	}

	return fn, nil
}

func parseAttrGroup(line, trimmed string) *AttrGroup {
	ag := &AttrGroup{Raw: line}
	rest := strings.TrimPrefix(trimmed, "attributes #")
	idEnd := 0
	for idEnd < len(rest) && rest[idEnd] >= '0' && rest[idEnd] <= '9' {
		idEnd++
	}
	ag.ID = rest[:idEnd]
	braceStart := strings.IndexByte(trimmed, '{')
	braceEnd := strings.LastIndexByte(trimmed, '}')
	if braceStart >= 0 && braceEnd > braceStart {
		ag.Body = trimmed[braceStart+1 : braceEnd]
	}
	return ag
}

func extractQuoted(line, prefix string) string {
	idx := strings.Index(line, `"`)
	if idx < 0 {
		return ""
	}
	end := strings.Index(line[idx+1:], `"`)
	if end < 0 {
		return ""
	}
	return line[idx+1 : idx+1+end]
}

func extractSection(line string) string {
	const marker = `section "`
	idx := strings.Index(line, marker)
	if idx < 0 {
		return ""
	}
	start := idx + len(marker)
	end := strings.IndexByte(line[start:], '"')
	if end < 0 {
		return ""
	}
	return line[start : start+end]
}

func extractAlign(line string) int {
	const marker = "align "
	idx := strings.LastIndex(line, marker)
	if idx < 0 {
		return 0
	}
	start := idx + len(marker)
	end := start
	for end < len(line) && line[end] >= '0' && line[end] <= '9' {
		end++
	}
	if end == start {
		return 0
	}
	n, _ := strconv.Atoi(line[start:end])
	return n
}

func extractMetaAttachments(line string) []MetaAttach {
	var attachments []MetaAttach
	pos := 0
	for pos < len(line) {
		idx := strings.Index(line[pos:], "!")
		if idx < 0 {
			break
		}
		absIdx := pos + idx
		if absIdx > 0 && line[absIdx-1] == '"' {
			pos = absIdx + 1
			continue
		}
		if absIdx+1 < len(line) && line[absIdx+1] >= '0' && line[absIdx+1] <= '9' {
			pos = absIdx + 1
			continue
		}
		if absIdx+1 >= len(line) {
			break
		}
		keyStart := absIdx + 1
		keyEnd := keyStart
		for keyEnd < len(line) && (isIdentChar(line[keyEnd]) || line[keyEnd] == '.') {
			keyEnd++
		}
		if keyEnd >= len(line) || keyEnd == keyStart {
			pos = keyEnd
			continue
		}
		key := line[keyStart:keyEnd]
		rest := strings.TrimSpace(line[keyEnd:])
		if strings.HasPrefix(rest, "!") {
			valEnd := 1
			for valEnd < len(rest) && rest[valEnd] >= '0' && rest[valEnd] <= '9' {
				valEnd++
			}
			if valEnd > 1 {
				attachments = append(attachments, MetaAttach{Key: key, Value: rest[:valEnd]})
			}
		}
		pos = keyEnd
	}
	return attachments
}

func extractAttrRef(attrs string) string {
	for i := 0; i < len(attrs); i++ {
		if attrs[i] == '#' {
			end := i + 1
			for end < len(attrs) && attrs[end] >= '0' && attrs[end] <= '9' {
				end++
			}
			if end > i+1 {
				return attrs[i:end]
			}
		}
	}
	return ""
}

func extractDefineRetType(line string) string {
	atIdx := strings.IndexByte(line, '@')
	if atIdx < 0 {
		return ""
	}
	before := strings.TrimSpace(line[len("define "):atIdx])
	tokens := strings.Fields(before)
	for _, t := range tokens {
		switch t {
		case "noundef", "internal", "hidden", "external", "private",
			"linkonce_odr", "weak_odr", "available_externally",
			"dso_local", "local_unnamed_addr":
			continue
		default:
			return t
		}
	}
	return ""
}

func findCloseParen(s string, openIdx int) int {
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

func isLabel(trimmed string) bool {
	if len(trimmed) < 2 || trimmed[len(trimmed)-1] != ':' {
		return false
	}
	name := trimmed[:len(trimmed)-1]
	if len(name) == 0 {
		return false
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '.' || r == '-') {
			return false
		}
	}
	return true
}

func isIdentChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '_' || c == '.'
}

func extractMetadataID(line string) int {
	if len(line) < 2 || line[0] != '!' || line[1] < '0' || line[1] > '9' {
		return -1
	}
	n := int(line[1] - '0')
	i := 2
	for i < len(line) && line[i] >= '0' && line[i] <= '9' {
		n = n*10 + int(line[i]-'0')
		i++
	}
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	if i < len(line) && line[i] == '=' {
		return n
	}
	return -1
}

func splitStructFields(body string) []string {
	var fields []string
	depth := 0
	start := 0
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '[', '{', '(':
			depth++
		case ']', '}', ')':
			depth--
		case ',':
			if depth == 0 {
				f := strings.TrimSpace(body[start:i])
				if f != "" {
					fields = append(fields, f)
				}
				start = i + 1
			}
		}
	}
	if f := strings.TrimSpace(body[start:]); f != "" {
		fields = append(fields, f)
	}
	return fields
}
