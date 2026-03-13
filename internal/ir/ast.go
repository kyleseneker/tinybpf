// Package ir provides a lightweight AST and parser for LLVM IR text files.
// It parses the subset of IR that TinyGo emits, giving structured access to
// the constructs that the BPF transform pipeline needs to manipulate. All
// other IR constructs are preserved verbatim through a Raw field on every node.
package ir

// Module is the top-level AST for a parsed .ll file. Entries preserves the
// source ordering of all top-level constructs for faithful round-trip
// serialization.
type Module struct {
	Entries []TopLevelEntry

	SourceFilename string
	DataLayout     string
	Triple         string

	TypeDefs      []*TypeDef
	Globals       []*Global
	Declares      []*Declare
	Functions     []*Function
	AttrGroups    []*AttrGroup
	MetadataNodes []*MetadataNode
	NamedMetadata []*NamedMetadata
}

// TopLevelKind identifies the kind of a top-level module entry.
type TopLevelKind int

const (
	TopComment TopLevelKind = iota
	TopBlank
	TopSourceFilename
	TopDataLayout
	TopTriple
	TopTypeDef
	TopGlobal
	TopDeclare
	TopFunction
	TopAttrGroup
	TopMetadata
	TopNamedMetadata
)

// TopLevelEntry preserves a single top-level item in source order.
// Exactly one of the pointer fields is non-nil (or none for comments/blanks).
type TopLevelEntry struct {
	Kind          TopLevelKind
	Raw           string
	TypeDef       *TypeDef
	Global        *Global
	Declare       *Declare
	Function      *Function
	AttrGroup     *AttrGroup
	Metadata      *MetadataNode
	NamedMetadata *NamedMetadata
	Removed       bool
}

// TypeDef represents a named struct type: %name = type { fields... }
type TypeDef struct {
	Name     string   // e.g. "%main.bpfMapDef"
	Fields   []string // raw field types: ["i32", "i32", "ptr"]
	Raw      string
	Modified bool
}

// Global represents a module-level global definition: @name = ...
type Global struct {
	Name        string       // without leading @
	Linkage     string       // "global", "internal global", "constant", "private unnamed_addr global", etc.
	Type        string       // e.g. "%main.bpfMapDef", "[4 x i8]", "i64"
	Initializer string       // "{ i32 27, ... }", "zeroinitializer", `c"GPL\00"`, "42", etc.
	Section     string       // ".maps", "license", ".data", etc. (empty if none)
	Align       int          // 0 if unspecified
	Metadata    []MetaAttach // !dbg !N, etc.
	Raw         string
	Modified    bool
}

// Declare represents a function declaration: declare retType @name(params)
type Declare struct {
	Name     string
	RetType  string
	Params   string // raw parameter list text
	Raw      string
	Modified bool
	Removed  bool
}

// Function represents a function definition with its body.
type Function struct {
	Name     string
	RetType  string
	Params   string
	Attrs    string       // everything between ) and { on the define line (attrs, section, metadata)
	AttrRef  string       // "#4" style attribute group reference
	Section  string       // section name if present
	Metadata []MetaAttach // !dbg !N on the define line
	Blocks   []*BasicBlock
	Raw      string // original define line
	BodyRaw  []string
	Modified bool
	Removed  bool
}

// BasicBlock represents a labeled block of instructions.
type BasicBlock struct {
	Label        string
	Instructions []*Instruction
}

// InstKind classifies instructions into those we parse structurally and
// those we treat as opaque.
type InstKind int

const (
	InstOther  InstKind = iota // opaque: load, store, br, icmp, phi, etc.
	InstCall                   // call/invoke with parsed callee and args
	InstGEP                    // getelementptr with parsed base type and indices
	InstAlloca                 // alloca with parsed type and alignment
)

// Instruction represents a single IR instruction within a basic block.
type Instruction struct {
	SSAName  string       // "%4" if this is an SSA assignment (empty otherwise)
	Kind     InstKind     // determines which sub-struct is populated
	Call     *CallInst    // non-nil when Kind == InstCall
	GEP      *GEPInst    // non-nil when Kind == InstGEP
	Alloca   *AllocaInst  // non-nil when Kind == InstAlloca
	Metadata []MetaAttach // trailing !dbg !N, !llvm.preserve.access.index !N
	Raw      string       // always preserved
	Modified bool
}

// CallInst holds parsed fields for a call instruction.
type CallInst struct {
	RetType string   // return type, e.g. "i64", "ptr", "void"
	Callee  string   // e.g. "@main.bpfGetCurrentPidTgid", "inttoptr (i64 35 to ptr)"
	Args    string   // raw argument list text
	Tail    string   // calling convention, attributes before the callee
}

// GEPInst holds parsed fields for a getelementptr instruction.
type GEPInst struct {
	Inbounds bool
	Flags    string   // extra flags like "nuw" after inbounds
	BaseType string   // element type, e.g. "%main.bpfCoreTaskStruct", "i8"
	PtrType  string   // pointer operand type, e.g. "ptr"
	Base     string   // pointer operand, e.g. "%task", "@main.events"
	Indices  []string // index operands as raw strings: ["i32 0", "i32 1"]
}

// AllocaInst holds parsed fields for an alloca instruction.
type AllocaInst struct {
	Type  string // allocated type, e.g. "[16 x i8]", "%main.bpfCoreTaskStruct"
	Align int    // 0 if unspecified
}

// MetaAttach represents a metadata attachment like !dbg !42.
type MetaAttach struct {
	Key   string // "dbg", "llvm.preserve.access.index", etc.
	Value string // "!42"
}

// AttrGroup represents an attribute group definition: attributes #N = { ... }
type AttrGroup struct {
	ID       string // "0", "4", etc. (the number after #)
	Body     string // everything inside the braces
	Raw      string
	Modified bool
}

// MetadataNode represents a numbered metadata definition: !N = ...
type MetadataNode struct {
	ID     int               // numeric ID
	Kind   string            // "DICompositeType", "DIDerivedType", "DIBasicType", "" (for tuples)
	Fields map[string]string // parsed key-value fields: "name" -> "main.bpfCoreTaskStruct"
	Tuple  []string          // for "!N = !{!1, !2}" nodes, the raw references
	Raw    string
	Modified bool
}

// NamedMetadata represents a named metadata node: !llvm.dbg.cu = !{!0}
type NamedMetadata struct {
	Name string // e.g. "llvm.dbg.cu"
	Refs []string
	Raw  string
}
