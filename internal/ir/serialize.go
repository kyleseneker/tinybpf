package ir

import (
	"fmt"
	"strings"
)

// Serialize converts a Module back to LLVM IR text.
func Serialize(m *Module) string {
	var b strings.Builder
	b.Grow(estimateSize(m))

	for i, entry := range m.Entries {
		if entry.Removed {
			continue
		}
		if i > 0 {
			b.WriteByte('\n')
		}
		serializeEntry(&b, m, &entry)
	}
	return b.String()
}

// estimateSize returns a rough byte count for pre-allocating the output buffer.
func estimateSize(m *Module) int {
	n := 0
	for _, e := range m.Entries {
		n += len(e.Raw) + 1
		if e.Function != nil {
			for _, r := range e.Function.BodyRaw {
				n += len(r) + 1
			}
		}
	}
	return n
}

// serializeEntry writes a single top-level entry, regenerating modified nodes.
func serializeEntry(b *strings.Builder, m *Module, entry *TopLevelEntry) {
	switch entry.Kind {
	case TopDataLayout:
		if m.DataLayout != extractQuoted(entry.Raw) {
			fmt.Fprintf(b, `target datalayout = "%s"`, m.DataLayout)
			return
		}
		b.WriteString(entry.Raw)

	case TopTriple:
		if m.Triple != extractQuoted(entry.Raw) {
			fmt.Fprintf(b, `target triple = "%s"`, m.Triple)
			return
		}
		b.WriteString(entry.Raw)

	case TopTypeDef:
		serializeTypeDefEntry(b, entry)
	case TopGlobal:
		serializeGlobalEntry(b, entry)
	case TopDeclare:
		serializeDeclareEntry(b, entry)
	case TopFunction:
		serializeFunctionEntry(b, entry)

	case TopAttrGroup:
		if entry.AttrGroup != nil && entry.AttrGroup.Modified {
			serializeAttrGroup(b, entry.AttrGroup)
			return
		}
		b.WriteString(entry.Raw)

	case TopMetadata:
		if entry.Metadata != nil && entry.Metadata.Modified {
			serializeMetadata(b, entry.Metadata)
			return
		}
		b.WriteString(entry.Raw)

	default:
		b.WriteString(entry.Raw)
	}
}

// serializeTypeDefEntry writes a type definition entry, regenerating if modified.
func serializeTypeDefEntry(b *strings.Builder, entry *TopLevelEntry) {
	if entry.TypeDef != nil && entry.TypeDef.Modified {
		serializeTypeDef(b, entry.TypeDef)
		return
	}
	b.WriteString(entry.Raw)
}

// serializeGlobalEntry writes a global variable entry, regenerating if modified.
func serializeGlobalEntry(b *strings.Builder, entry *TopLevelEntry) {
	if entry.Global != nil && entry.Global.Modified {
		serializeGlobal(b, entry.Global)
		return
	}
	b.WriteString(entry.Raw)
}

// serializeDeclareEntry writes a declare entry, skipping if removed or regenerating if modified.
func serializeDeclareEntry(b *strings.Builder, entry *TopLevelEntry) {
	if entry.Declare != nil && entry.Declare.Removed {
		return
	}
	if entry.Declare != nil && entry.Declare.Modified {
		serializeDeclare(b, entry.Declare)
		return
	}
	b.WriteString(entry.Raw)
}

// serializeFunctionEntry writes a function entry, skipping if removed or serializing the parsed form.
func serializeFunctionEntry(b *strings.Builder, entry *TopLevelEntry) {
	if entry.Function != nil {
		if entry.Function.Removed {
			return
		}
		serializeFunction(b, entry.Function)
		return
	}
	b.WriteString(entry.Raw)
}

// serializeTypeDef writes a modified type definition.
func serializeTypeDef(b *strings.Builder, td *TypeDef) {
	fmt.Fprintf(b, "%s = type { %s }", td.Name, strings.Join(td.Fields, ", "))
}

// serializeGlobal writes a modified global definition.
func serializeGlobal(b *strings.Builder, g *Global) {
	fmt.Fprintf(b, "@%s = %s", g.Name, g.Linkage)
	if g.Type != "" {
		b.WriteByte(' ')
		b.WriteString(g.Type)
	}
	if g.Initializer != "" {
		b.WriteByte(' ')
		b.WriteString(g.Initializer)
	}
	if g.Section != "" {
		fmt.Fprintf(b, `, section "%s"`, g.Section)
	}
	if g.Align > 0 {
		fmt.Fprintf(b, ", align %d", g.Align)
	}
	for _, ma := range g.Metadata {
		fmt.Fprintf(b, ", !%s %s", ma.Key, ma.Value)
	}
}

// serializeDeclare writes a modified function declaration.
func serializeDeclare(b *strings.Builder, d *Declare) {
	fmt.Fprintf(b, "declare %s @%s(%s)", d.RetType, d.Name, d.Params)
}

// serializeFunction writes a function definition, dispatching to the modified path if needed.
func serializeFunction(b *strings.Builder, fn *Function) {
	if fn.Modified {
		serializeFunctionModified(b, fn)
		return
	}
	b.WriteString(fn.Raw)
	for _, bline := range fn.BodyRaw {
		b.WriteByte('\n')
		b.WriteString(bline)
	}
}

// serializeFunctionModified regenerates a function body from its parsed blocks and instructions.
func serializeFunctionModified(b *strings.Builder, fn *Function) {
	b.WriteString(fn.Raw)
	for _, block := range fn.Blocks {
		if block.Label != "" {
			b.WriteByte('\n')
			fmt.Fprintf(b, "%s:", block.Label)
		}
		for _, inst := range block.Instructions {
			b.WriteByte('\n')
			if inst.Modified {
				serializeInstruction(b, inst)
			} else {
				b.WriteString(inst.Raw)
			}
		}
	}
	b.WriteString("\n}")
}

// serializeInstruction dispatches to the appropriate instruction serializer by kind.
func serializeInstruction(b *strings.Builder, inst *Instruction) {
	switch inst.Kind {
	case InstCall:
		serializeCallInst(b, inst)
	case InstGEP:
		serializeGEPInst(b, inst)
	case InstAlloca:
		serializeAllocaInst(b, inst)
	default:
		b.WriteString(inst.Raw)
	}
}

// serializeCallInst writes a modified call instruction.
func serializeCallInst(b *strings.Builder, inst *Instruction) {
	ci := inst.Call
	b.WriteString("  ")
	if inst.SSAName != "" {
		fmt.Fprintf(b, "%s = ", inst.SSAName)
	}
	if ci.Tail != "" {
		b.WriteString(ci.Tail)
		b.WriteByte(' ')
	}
	fmt.Fprintf(b, "call %s %s(%s)", ci.RetType, ci.Callee, ci.Args)
	serializeMetaAttachments(b, inst.Metadata)
}

// serializeGEPInst writes a modified getelementptr instruction.
func serializeGEPInst(b *strings.Builder, inst *Instruction) {
	gi := inst.GEP
	b.WriteString("  ")
	if inst.SSAName != "" {
		fmt.Fprintf(b, "%s = ", inst.SSAName)
	}
	b.WriteString("getelementptr")
	if gi.Inbounds {
		b.WriteString(" inbounds")
	}
	if gi.Flags != "" {
		b.WriteByte(' ')
		b.WriteString(gi.Flags)
	}
	b.WriteByte(' ')
	b.WriteString(gi.BaseType)
	b.WriteString(", ")
	if gi.PtrType != "" {
		b.WriteString(gi.PtrType)
		b.WriteByte(' ')
	}
	b.WriteString(gi.Base)
	for _, idx := range gi.Indices {
		b.WriteString(", ")
		b.WriteString(idx)
	}
	serializeMetaAttachments(b, inst.Metadata)
}

// serializeAllocaInst writes a modified alloca instruction.
func serializeAllocaInst(b *strings.Builder, inst *Instruction) {
	ai := inst.Alloca
	b.WriteString("  ")
	if inst.SSAName != "" {
		fmt.Fprintf(b, "%s = ", inst.SSAName)
	}
	fmt.Fprintf(b, "alloca %s", ai.Type)
	if ai.Align > 0 {
		fmt.Fprintf(b, ", align %d", ai.Align)
	}
	serializeMetaAttachments(b, inst.Metadata)
}

// serializeAttrGroup writes a modified attribute group definition.
func serializeAttrGroup(b *strings.Builder, ag *AttrGroup) {
	fmt.Fprintf(b, "attributes #%s = { %s }", ag.ID, strings.TrimSpace(ag.Body))
}

// serializeMetadata writes a modified metadata node as either a tuple or DI definition.
func serializeMetadata(b *strings.Builder, mn *MetadataNode) {
	if mn.Kind == "" && len(mn.Tuple) > 0 {
		fmt.Fprintf(b, "!%d = !{%s}", mn.ID, strings.Join(mn.Tuple, ", "))
		return
	}
	if mn.Kind != "" && len(mn.Fields) > 0 {
		fmt.Fprintf(b, "!%d = !%s(", mn.ID, mn.Kind)
		first := true
		for k, v := range mn.Fields {
			if !first {
				b.WriteString(", ")
			}
			first = false
			if needsQuoting(v) {
				fmt.Fprintf(b, "%s: \"%s\"", k, v)
			} else {
				fmt.Fprintf(b, "%s: %s", k, v)
			}
		}
		b.WriteByte(')')
		return
	}
	b.WriteString(mn.Raw)
}

// serializeMetaAttachments appends ", !key !N" metadata attachments to the builder.
func serializeMetaAttachments(b *strings.Builder, attachments []MetaAttach) {
	for _, ma := range attachments {
		fmt.Fprintf(b, ", !%s %s", ma.Key, ma.Value)
	}
}

// needsQuoting reports whether a metadata field value requires double quotes.
func needsQuoting(v string) bool {
	if strings.HasPrefix(v, "!") || strings.HasPrefix(v, "DW_") {
		return false
	}
	for _, c := range v {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' {
			continue
		}
		return true
	}
	return false
}
