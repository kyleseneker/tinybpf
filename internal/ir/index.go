package ir

// ModuleIndex provides fast lookups over a parsed Module's contents.
type ModuleIndex struct {
	SSADefs   map[string]*Instruction // SSA name -> defining instruction
	MetaByID  map[int]*MetadataNode   // metadata ID -> node
	IdentRefs map[string][]IdentRef   // @name -> list of references
	MaxMetaID int                     // highest metadata ID seen
}

// IdentRef records where an @-identifier appears.
type IdentRef struct {
	Kind     IdentRefKind
	EntryIdx int
	Global   *Global
	Declare  *Declare
	Function *Function
}

// IdentRefKind classifies where an identifier reference lives.
type IdentRefKind int

const (
	RefInGlobal IdentRefKind = iota
	RefInDeclare
	RefInFunction
	RefInOther
)

// BuildIndex creates a ModuleIndex for fast lookups during transforms.
func BuildIndex(m *Module) *ModuleIndex {
	idx := &ModuleIndex{
		SSADefs:   make(map[string]*Instruction),
		MetaByID:  make(map[int]*MetadataNode),
		IdentRefs: make(map[string][]IdentRef),
		MaxMetaID: -1,
	}

	for _, mn := range m.MetadataNodes {
		idx.MetaByID[mn.ID] = mn
		if mn.ID > idx.MaxMetaID {
			idx.MaxMetaID = mn.ID
		}
	}

	for _, fn := range m.Functions {
		for _, block := range fn.Blocks {
			for _, inst := range block.Instructions {
				if inst.SSAName != "" {
					idx.SSADefs[inst.SSAName] = inst
				}
			}
		}
	}

	for i, entry := range m.Entries {
		switch entry.Kind {
		case TopGlobal:
			if entry.Global != nil {
				name := "@" + entry.Global.Name
				idx.IdentRefs[name] = append(idx.IdentRefs[name], IdentRef{
					Kind:     RefInGlobal,
					EntryIdx: i,
					Global:   entry.Global,
				})
				scanIdentRefs(idx, entry.Raw, i, nil)
			}
		case TopDeclare:
			if entry.Declare != nil {
				name := "@" + entry.Declare.Name
				idx.IdentRefs[name] = append(idx.IdentRefs[name], IdentRef{
					Kind:     RefInDeclare,
					EntryIdx: i,
					Declare:  entry.Declare,
				})
			}
		case TopFunction:
			if entry.Function != nil {
				name := "@" + entry.Function.Name
				idx.IdentRefs[name] = append(idx.IdentRefs[name], IdentRef{
					Kind:     RefInFunction,
					EntryIdx: i,
					Function: entry.Function,
				})
				for _, bline := range entry.Function.BodyRaw {
					scanIdentRefs(idx, bline, i, entry.Function)
				}
			}
		}
	}

	return idx
}

// scanIdentRefs scans a line for @-identifiers and appends IdentRef entries to the index.
func scanIdentRefs(idx *ModuleIndex, line string, entryIdx int, fn *Function) {
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
			kind := RefInOther
			if fn != nil {
				kind = RefInFunction
			}
			idx.IdentRefs[ident] = append(idx.IdentRefs[ident], IdentRef{
				Kind:     kind,
				EntryIdx: entryIdx,
				Function: fn,
			})
			pos = j - 1
		}
	}
}

// NextMetaID returns the next available metadata ID.
func (idx *ModuleIndex) NextMetaID() int {
	return idx.MaxMetaID + 1
}

// IsReferencedElsewhere reports whether @name appears in any entry other than defEntryIdx.
func (idx *ModuleIndex) IsReferencedElsewhere(name string, defEntryIdx int) bool {
	for _, ref := range idx.IdentRefs[name] {
		if ref.EntryIdx != defEntryIdx {
			return true
		}
	}
	return false
}
