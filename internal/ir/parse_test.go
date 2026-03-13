package ir

import (
	"strings"
	"testing"
)

const minimalIR = `target triple = "bpf"

define i64 @xdp_prog(ptr %ctx) section "xdp" {
entry:
  ret i64 2
}
`

const transformSeedIR = `target datalayout = "e-m:o-p270:32:32-p271:32:32"
target triple = "arm64-apple-macosx11.0.0"

define i32 @my_program(ptr %ctx) {
entry:
  ret i32 0
}
`

const mapAndHelperIR = `target triple = "x86_64-unknown-linux-gnu"

@main.events = global %main.bpfMapDef { i32 27, i32 0, i32 0, i32 16777216, i32 0 }, align 4

define i32 @my_func(ptr %ctx) #0 {
entry:
  %0 = call i64 @main.bpfGetCurrentPidTgid(ptr undef) #7
  ret i32 0
}

attributes #0 = { "target-cpu"="generic" "target-features"="+neon" }
`

const runtimeAndAllocIR = `define void @runtime.runMain() {
entry:
  ret void
}

define i32 @handle(ptr %ctx) {
entry:
  %buf = call align 4 dereferenceable(16) ptr @runtime.alloc(i64 16, ptr null, ptr undef)
  %1 = call i64 @main.bpfRingbufOutput(ptr @main.events, ptr %buf, i64 16, i64 0, ptr undef) #7
  ret i32 0
}
`

const coreFieldExistsIR = `%main.bpfCoreTaskStruct = type { i32, i32 }

declare i32 @main.bpfCoreFieldExists(ptr, ptr)

define void @main.prog(ptr %ctx) {
entry:
  %core = alloca %main.bpfCoreTaskStruct, align 4
  %1 = getelementptr inbounds i8, ptr %core, i64 4
  %2 = call i32 @main.bpfCoreFieldExists(ptr nonnull %1, ptr undef)
  ret void
}
`

const coreGEPIR = `%main.bpfCoreTaskStruct = type { i32, i32, [16 x i8] }

define i32 @tracepoint_handler(ptr %ctx) {
entry:
  %task = call ptr inttoptr (i64 35 to ptr)()
  %pid_ptr = getelementptr inbounds %main.bpfCoreTaskStruct, ptr %task, i32 0, i32 0
  %pid = load i32, ptr %pid_ptr
  ret i32 %pid
}
`

const metadataIR = `!0 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfCoreTaskStruct", size: 192, elements: !{!1, !2, !3})
!1 = !DIDerivedType(tag: DW_TAG_member, name: "Pid", baseType: !4, size: 32, offset: 0)
!2 = !DIDerivedType(tag: DW_TAG_member, name: "Tgid", baseType: !4, size: 32, offset: 32)
!3 = !DIDerivedType(tag: DW_TAG_member, name: "Comm", baseType: !5, size: 128, offset: 64)
!4 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!5 = !DICompositeType(tag: DW_TAG_array_type, baseType: !6, elements: !{!7})
!6 = !DIBasicType(name: "byte", size: 8, encoding: DW_ATE_unsigned)
!7 = !DISubrange(count: 16)
`

const datasectionsIR = `@main.myConfig = global i64 42, align 8
@main.myTable = constant [4 x i32] [i32 1, i32 2, i32 3, i32 4], align 4
@main.counter = global i64 zeroinitializer, align 8
@main.events = global %main.bpfMapDef { i32 27, i32 0, i32 0, i32 16777216, i32 0 }, align 4
@_license = global [4 x i8] c"GPL\00", section "license", align 1
`

const cleanupIR = `; Function Attrs: nounwind
declare void @unused_func()

declare void @llvm.memset.p0.i64(ptr, i8, i64, i1)

define i32 @my_func() #4 {
entry:
  call void @llvm.memset.p0.i64(ptr null, i8 0, i64 16, i1 false)
  ret i32 0
}

attributes #0 = { nounwind }
attributes #4 = { nounwind }
`

func testRoundTrip(t *testing.T, name, input string) {
	t.Helper()
	m, err := Parse(input)
	if err != nil {
		t.Fatalf("%s: Parse: %v", name, err)
	}
	output := Serialize(m)

	inLines := strings.Split(input, "\n")
	outLines := strings.Split(output, "\n")

	if len(inLines) != len(outLines) {
		t.Errorf("%s: line count mismatch: input %d, output %d", name, len(inLines), len(outLines))
		maxShow := 20
		if len(inLines) > maxShow || len(outLines) > maxShow {
			t.Logf("first %d lines of diff:", maxShow)
		}
		for i := 0; i < len(inLines) && i < len(outLines) && i < maxShow; i++ {
			if inLines[i] != outLines[i] {
				t.Logf("  line %d:\n    in:  %q\n    out: %q", i+1, inLines[i], outLines[i])
			}
		}
		return
	}

	for i := range inLines {
		if inLines[i] != outLines[i] {
			t.Errorf("%s: line %d differs:\n  in:  %q\n  out: %q", name, i+1, inLines[i], outLines[i])
		}
	}
}

func mustParse(t *testing.T, input string) *Module {
	t.Helper()
	m, err := Parse(input)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return m
}

func hasEntryWithKind(m *Module, kind TopLevelKind, text string) bool {
	for _, e := range m.Entries {
		if e.Kind == kind && strings.Contains(e.Raw, text) {
			return true
		}
	}
	return false
}

func countEntriesOfKind(m *Module, kind TopLevelKind) int {
	n := 0
	for _, e := range m.Entries {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

func TestParseHeaders(t *testing.T) {
	tests := []struct {
		name  string
		input string
		check func(*testing.T, *Module)
	}{
		{
			name:  "empty input",
			input: "",
			check: func(t *testing.T, m *Module) {
				t.Helper()
				if len(m.Functions) != 0 {
					t.Errorf("Functions = %d, want 0", len(m.Functions))
				}
			},
		},
		{
			name:  "minimalIR",
			input: minimalIR,
			check: func(t *testing.T, m *Module) {
				t.Helper()
				if m.Triple != "bpf" {
					t.Errorf("Triple = %q, want %q", m.Triple, "bpf")
				}
				if len(m.Functions) != 1 {
					t.Fatalf("Functions = %d, want 1", len(m.Functions))
				}
				fn := m.Functions[0]
				if fn.Name != "xdp_prog" {
					t.Errorf("Name = %q", fn.Name)
				}
				if fn.Section != "xdp" {
					t.Errorf("Section = %q", fn.Section)
				}
				if fn.RetType != "i64" {
					t.Errorf("RetType = %q", fn.RetType)
				}
			},
		},
		{
			name:  "transformSeedIR",
			input: transformSeedIR,
			check: func(t *testing.T, m *Module) {
				t.Helper()
				if m.DataLayout != "e-m:o-p270:32:32-p271:32:32" {
					t.Errorf("DataLayout = %q", m.DataLayout)
				}
				if m.Triple != "arm64-apple-macosx11.0.0" {
					t.Errorf("Triple = %q", m.Triple)
				}
				if len(m.Functions) != 1 {
					t.Fatalf("Functions = %d, want 1", len(m.Functions))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if tt.check != nil {
				tt.check(t, m)
			}
		})
	}
}

func TestParseGlobalsAndDeclares(t *testing.T) {
	tests := []struct {
		name  string
		input string
		check func(*testing.T, *Module)
	}{
		{
			name:  "mapAndHelperIR",
			input: mapAndHelperIR,
			check: func(t *testing.T, m *Module) {
				t.Helper()
				if len(m.Globals) != 1 {
					t.Fatalf("Globals = %d, want 1", len(m.Globals))
				}
				if m.Globals[0].Name != "main.events" {
					t.Errorf("Global name = %q", m.Globals[0].Name)
				}
				if m.Globals[0].Align != 4 {
					t.Errorf("Align = %d", m.Globals[0].Align)
				}
				if len(m.AttrGroups) != 1 {
					t.Fatalf("AttrGroups = %d, want 1", len(m.AttrGroups))
				}
				if m.AttrGroups[0].ID != "0" {
					t.Errorf("AttrGroup ID = %q", m.AttrGroups[0].ID)
				}
			},
		},
		{
			name:  "datasectionsIR",
			input: datasectionsIR,
			check: func(t *testing.T, m *Module) {
				t.Helper()
				if len(m.Globals) != 5 {
					t.Fatalf("Globals = %d, want 5", len(m.Globals))
				}
				license := m.Globals[4]
				if license.Section != "license" {
					t.Errorf("license section = %q", license.Section)
				}
			},
		},
		{
			name:  "cleanupIR",
			input: cleanupIR,
			check: func(t *testing.T, m *Module) {
				t.Helper()
				if len(m.Declares) != 2 {
					t.Fatalf("Declares = %d, want 2", len(m.Declares))
				}
				if len(m.AttrGroups) != 2 {
					t.Fatalf("AttrGroups = %d, want 2", len(m.AttrGroups))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			tt.check(t, m)
		})
	}
}

func TestParseFunctions(t *testing.T) {
	tests := []struct {
		name  string
		input string
		check func(*testing.T, *Module)
	}{
		{
			name:  "runtimeAndAllocIR",
			input: runtimeAndAllocIR,
			check: func(t *testing.T, m *Module) {
				t.Helper()
				if len(m.Functions) != 2 {
					t.Fatalf("Functions = %d, want 2", len(m.Functions))
				}
				if m.Functions[0].Name != "runtime.runMain" {
					t.Errorf("func[0] = %q", m.Functions[0].Name)
				}
				if m.Functions[1].Name != "handle" {
					t.Errorf("func[1] = %q", m.Functions[1].Name)
				}
			},
		},
		{
			name:  "coreGEPIR",
			input: coreGEPIR,
			check: func(t *testing.T, m *Module) {
				t.Helper()
				if len(m.TypeDefs) != 1 {
					t.Fatalf("TypeDefs = %d, want 1", len(m.TypeDefs))
				}
				if m.TypeDefs[0].Name != "%main.bpfCoreTaskStruct" {
					t.Errorf("TypeDef name = %q", m.TypeDefs[0].Name)
				}
				if len(m.Functions) != 1 {
					t.Fatalf("Functions = %d, want 1", len(m.Functions))
				}
				if len(m.Functions[0].Blocks) == 0 {
					t.Fatal("no blocks")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			tt.check(t, m)
		})
	}
}

func TestParseTypesAndMeta(t *testing.T) {
	tests := []struct {
		name  string
		input string
		check func(*testing.T, *Module)
	}{
		{
			name:  "coreFieldExistsIR",
			input: coreFieldExistsIR,
			check: func(t *testing.T, m *Module) {
				t.Helper()
				if len(m.TypeDefs) != 1 {
					t.Fatalf("TypeDefs = %d, want 1", len(m.TypeDefs))
				}
				if len(m.Declares) != 1 {
					t.Fatalf("Declares = %d, want 1", len(m.Declares))
				}
				if m.Declares[0].Name != "main.bpfCoreFieldExists" {
					t.Errorf("Declare name = %q", m.Declares[0].Name)
				}
			},
		},
		{
			name:  "metadataIR",
			input: metadataIR,
			check: func(t *testing.T, m *Module) {
				t.Helper()
				if len(m.MetadataNodes) != 8 {
					t.Fatalf("MetadataNodes = %d, want 8", len(m.MetadataNodes))
				}
				if m.MetadataNodes[0].Kind != "DICompositeType" {
					t.Errorf("metadata[0] kind = %q", m.MetadataNodes[0].Kind)
				}
			},
		},
		{
			name:  "named metadata",
			input: "!llvm.dbg.cu = !{!0}\n",
			check: func(t *testing.T, m *Module) {
				t.Helper()
				if len(m.NamedMetadata) != 1 {
					t.Fatalf("NamedMetadata = %d, want 1", len(m.NamedMetadata))
				}
				if m.NamedMetadata[0].Name != "llvm.dbg.cu" {
					t.Errorf("Name = %q", m.NamedMetadata[0].Name)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			tt.check(t, m)
		})
	}
}

func TestParseEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		check   func(*testing.T, *Module)
	}{
		{
			name:  "source_filename",
			input: "source_filename = \"hello.go\"\n",
			check: func(t *testing.T, m *Module) {
				t.Helper()
				if m.SourceFilename != "hello.go" {
					t.Errorf("SourceFilename = %q", m.SourceFilename)
				}
			},
		},
		{
			name:  "comment line",
			input: "; this is a comment\n",
			check: func(t *testing.T, m *Module) {
				t.Helper()
				if !hasEntryWithKind(m, TopComment, "this is a comment") {
					t.Error("comment not preserved")
				}
			},
		},
		{
			name:  "dbg record line",
			input: "#dbg_value(!0, !1, !2)\n",
			check: func(t *testing.T, m *Module) {
				t.Helper()
				if !hasEntryWithKind(m, TopComment, "#dbg_value") {
					t.Error("#dbg_ line not preserved as comment")
				}
			},
		},
		{
			name:  "metadata line without equals treated as comment",
			input: "!0\n",
			check: func(t *testing.T, m *Module) {
				t.Helper()
				if !hasEntryWithKind(m, TopComment, "!0") {
					t.Error("metadata line without = not preserved as comment")
				}
			},
		},
		{
			name:  "unrecognized line preserved as comment",
			input: "this is not valid IR\n",
			check: func(t *testing.T, m *Module) {
				t.Helper()
				if !hasEntryWithKind(m, TopComment, "this is not valid IR") {
					t.Error("unrecognized line not preserved")
				}
			},
		},
		{
			name:  "llvm intrinsic global treated as comment",
			input: "@llvm.used = appending global [1 x ptr] [ptr @f]\n",
			check: func(t *testing.T, m *Module) {
				t.Helper()
				if len(m.Globals) != 0 {
					t.Errorf("Globals = %d, want 0", len(m.Globals))
				}
			},
		},
		{
			name:  "global returning nil treated as comment",
			input: "@foo bar = global i32 0\n",
			check: func(t *testing.T, m *Module) {
				t.Helper()
				if len(m.Globals) != 0 {
					t.Errorf("Globals = %d, want 0", len(m.Globals))
				}
			},
		},
		{
			name:    "define without @ sign",
			input:   "define i32 no_at() {\n}\n",
			wantErr: true,
		},
		{
			name:  "blank lines",
			input: "\n\n\n",
			check: func(t *testing.T, m *Module) {
				t.Helper()
				if countEntriesOfKind(m, TopBlank) != 4 {
					t.Errorf("blanks = %d, want 4", countEntriesOfKind(m, TopBlank))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := Parse(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if tt.check != nil {
				tt.check(t, m)
			}
		})
	}
}

func TestParseTypeDef(t *testing.T) {
	tests := []struct {
		name       string
		line       string
		trimmed    string
		wantName   string
		wantFields []string
	}{
		{
			name:       "struct with fields",
			line:       `%main.bpfMapDef = type { i32, i32, ptr }`,
			trimmed:    `%main.bpfMapDef = type { i32, i32, ptr }`,
			wantName:   "%main.bpfMapDef",
			wantFields: []string{"i32", "i32", "ptr"},
		},
		{
			name:       "opaque type no braces",
			line:       `%opaque = type opaque`,
			trimmed:    `%opaque = type opaque`,
			wantName:   "%opaque",
			wantFields: nil,
		},
		{
			name:       "empty struct",
			line:       `%empty = type {}`,
			trimmed:    `%empty = type {}`,
			wantName:   "%empty",
			wantFields: nil,
		},
		{
			name:       "nested array field",
			line:       `%s = type { i32, [16 x i8] }`,
			trimmed:    `%s = type { i32, [16 x i8] }`,
			wantName:   "%s",
			wantFields: []string{"i32", "[16 x i8]"},
		},
		{
			name:       "no = type marker",
			line:       `%broken`,
			trimmed:    `%broken`,
			wantName:   "",
			wantFields: nil,
		},
		{
			name:       "single field",
			line:       `%one = type { ptr }`,
			trimmed:    `%one = type { ptr }`,
			wantName:   "%one",
			wantFields: []string{"ptr"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &parser{}
			td := p.parseTypeDef(tt.line, tt.trimmed)
			if td.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", td.Name, tt.wantName)
			}
			if td.Raw != tt.line {
				t.Errorf("Raw = %q, want %q", td.Raw, tt.line)
			}
			if len(td.Fields) != len(tt.wantFields) {
				t.Fatalf("Fields = %v, want %v", td.Fields, tt.wantFields)
			}
			for i := range tt.wantFields {
				if td.Fields[i] != tt.wantFields[i] {
					t.Errorf("Field[%d] = %q, want %q", i, td.Fields[i], tt.wantFields[i])
				}
			}
		})
	}
}

func TestParseGlobal(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		trimmed     string
		wantNil     bool
		wantName    string
		wantSection string
		wantAlign   int
		wantMetaLen int
	}{
		{
			name:    "nil for empty",
			line:    "",
			trimmed: "",
			wantNil: true,
		},
		{
			name:    "nil for single @",
			line:    "@",
			trimmed: "@",
			wantNil: true,
		},
		{
			name:    "nil for non-@ start",
			line:    "xyz = global i32 0",
			trimmed: "xyz = global i32 0",
			wantNil: true,
		},
		{
			name:    "nil for name only no equals",
			line:    "@foo",
			trimmed: "@foo",
			wantNil: true,
		},
		{
			name:    "nil for missing equals",
			line:    "@foo global i32 0",
			trimmed: "@foo global i32 0",
			wantNil: true,
		},
		{
			name:      "simple global",
			line:      "@main.counter = global i64 42, align 8",
			trimmed:   "@main.counter = global i64 42, align 8",
			wantName:  "main.counter",
			wantAlign: 8,
		},
		{
			name:        "global with section",
			line:        `@_license = global [4 x i8] c"GPL\00", section "license", align 1`,
			trimmed:     `@_license = global [4 x i8] c"GPL\00", section "license", align 1`,
			wantName:    "_license",
			wantSection: "license",
			wantAlign:   1,
		},
		{
			name:        "global with metadata",
			line:        `@main.events = global %main.bpfMapDef { i32 27 }, section ".maps", align 4 !dbg !5`,
			trimmed:     `@main.events = global %main.bpfMapDef { i32 27 }, section ".maps", align 4 !dbg !5`,
			wantName:    "main.events",
			wantSection: ".maps",
			wantAlign:   4,
			wantMetaLen: 1,
		},
		{
			name:     "global with empty name after @",
			line:     "@ = global i32 0",
			trimmed:  "@ = global i32 0",
			wantName: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := parseGlobal(tt.line, tt.trimmed)
			if tt.wantNil {
				if g != nil {
					t.Fatalf("expected nil, got %+v", g)
				}
				return
			}
			if g == nil {
				t.Fatal("unexpected nil")
			}
			if g.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", g.Name, tt.wantName)
			}
			if g.Section != tt.wantSection {
				t.Errorf("Section = %q, want %q", g.Section, tt.wantSection)
			}
			if g.Align != tt.wantAlign {
				t.Errorf("Align = %d, want %d", g.Align, tt.wantAlign)
			}
			if len(g.Metadata) != tt.wantMetaLen {
				t.Errorf("Metadata len = %d, want %d", len(g.Metadata), tt.wantMetaLen)
			}
		})
	}
}

func TestParseGlobalBody(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantLinkage string
		wantType    string
		wantInit    string
	}{
		{
			name:        "empty",
			input:       "",
			wantLinkage: "",
			wantType:    "",
			wantInit:    "",
		},
		{
			name:        "zeroinitializer before type",
			input:       "global zeroinitializer",
			wantLinkage: "global",
			wantType:    "",
			wantInit:    "zeroinitializer",
		},
		{
			name:        "zeroinitializer no linkage",
			input:       "zeroinitializer",
			wantLinkage: "",
			wantType:    "",
			wantInit:    "zeroinitializer",
		},
		{
			name:        "zeroinitializer after type",
			input:       "global i64 zeroinitializer",
			wantLinkage: "global",
			wantType:    "i64",
			wantInit:    "zeroinitializer",
		},
		{
			name:        "braces initializer",
			input:       "global %main.bpfMapDef { i32 27, i32 0 }",
			wantLinkage: "global",
			wantType:    "%main.bpfMapDef",
			wantInit:    "{ i32 27, i32 0 }",
		},
		{
			name:        "brackets initializer",
			input:       "constant [4 x i32] [i32 1, i32 2, i32 3, i32 4]",
			wantLinkage: "constant",
			wantType:    "[4 x i32]",
			wantInit:    "[i32 1, i32 2, i32 3, i32 4]",
		},
		{
			name:        "c-string",
			input:       `global [4 x i8] c"GPL\00"`,
			wantLinkage: "global",
			wantType:    "[4 x i8]",
			wantInit:    `c"GPL\00"`,
		},
		{
			name:        "c-string unclosed quote",
			input:       `global [4 x i8] c"hello`,
			wantLinkage: "global",
			wantType:    "[4 x i8]",
			wantInit:    "",
		},
		{
			name:        "simple value with comma",
			input:       "global i64 42, align 8",
			wantLinkage: "global",
			wantType:    "i64",
			wantInit:    "42",
		},
		{
			name:        "simple value no comma",
			input:       "global i32 0",
			wantLinkage: "global",
			wantType:    "i32",
			wantInit:    "0",
		},
		{
			name:        "private unnamed_addr global",
			input:       "private unnamed_addr global i32 99",
			wantLinkage: "private unnamed_addr global",
			wantType:    "i32",
			wantInit:    "99",
		},
		{
			name:        "no linkage",
			input:       "i32 42",
			wantLinkage: "",
			wantType:    "i32",
			wantInit:    "42",
		},
		{
			name:        "unmatched braces no init",
			input:       "global %t { unclosed",
			wantLinkage: "global",
			wantType:    "%t",
			wantInit:    "",
		},
		{
			name:        "unmatched brackets no init",
			input:       "constant [4 x i32] [i32 1, i32 2",
			wantLinkage: "constant",
			wantType:    "[4 x i32]",
			wantInit:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			linkage, typeName, init, _ := parseGlobalBody(tt.input)
			if linkage != tt.wantLinkage {
				t.Errorf("linkage = %q, want %q", linkage, tt.wantLinkage)
			}
			if typeName != tt.wantType {
				t.Errorf("typeName = %q, want %q", typeName, tt.wantType)
			}
			if init != tt.wantInit {
				t.Errorf("init = %q, want %q", init, tt.wantInit)
			}
		})
	}
}

func TestConsumeLinkage(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantLink string
		wantRest string
	}{
		{"private unnamed_addr global", "private unnamed_addr global i32 0", "private unnamed_addr global", "i32 0"},
		{"private unnamed_addr constant", "private unnamed_addr constant i8 1", "private unnamed_addr constant", "i8 1"},
		{"internal unnamed_addr global", "internal unnamed_addr global i32 0", "internal unnamed_addr global", "i32 0"},
		{"internal unnamed_addr constant", "internal unnamed_addr constant i32 0", "internal unnamed_addr constant", "i32 0"},
		{"internal global", "internal global i32 0", "internal global", "i32 0"},
		{"internal constant", "internal constant i32 0", "internal constant", "i32 0"},
		{"global", "global i32 0", "global", "i32 0"},
		{"constant", "constant i32 0", "constant", "i32 0"},
		{"external global", "external global i32 0", "external global", "i32 0"},
		{"external constant", "external constant i32 0", "external constant", "i32 0"},
		{"no match", "something else", "", "something else"},
		{"empty", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			link, rest := consumeLinkage(tt.input)
			if link != tt.wantLink {
				t.Errorf("linkage = %q, want %q", link, tt.wantLink)
			}
			if rest != tt.wantRest {
				t.Errorf("rest = %q, want %q", rest, tt.wantRest)
			}
		})
	}
}

func TestFindTypeEnd(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{"empty", "", 0},
		{"percent type", "%main.foo rest", 9},
		{"percent type at end", "%abc", 4},
		{"array type", "[4 x i32] rest", 9},
		{"unmatched bracket", "[4 x i32 rest", 0},
		{"i8", "i8 val", 2},
		{"i16", "i16 val", 3},
		{"i32", "i32 val", 3},
		{"i64", "i64 val", 3},
		{"i128", "i128 val", 4},
		{"ptr", "ptr val", 3},
		{"void", "void", 4},
		{"float", "float val", 5},
		{"double", "double val", 6},
		{"i8 at word boundary", "i8foo", 0},
		{"i32 at word boundary", "i32x", 0},
		{"ptr at end of string", "ptr", 3},
		{"unrecognized", "xyz", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findTypeEnd(tt.input)
			if got != tt.want {
				t.Errorf("findTypeEnd(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestFindMatchingBrace(t *testing.T) {
	tests := []struct {
		name  string
		s     string
		open  byte
		close byte
		want  int
	}{
		{"matched braces", "{ i32, i32 }", '{', '}', 11},
		{"nested braces", "{ { i32 }, i32 }", '{', '}', 15},
		{"matched brackets", "[i32 1, i32 2]", '[', ']', 13},
		{"unmatched", "{ i32, i32", '{', '}', -1},
		{"empty string", "", '{', '}', -1},
		{"wrong opener", "x{ i32 }", '{', '}', -1},
		{"deeply nested", "{a{b{c}}}", '{', '}', 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findMatchingBrace(tt.s, tt.open, tt.close)
			if got != tt.want {
				t.Errorf("findMatchingBrace(%q, %q, %q) = %d, want %d",
					tt.s, string(tt.open), string(tt.close), got, tt.want)
			}
		})
	}
}

func TestParseDeclare(t *testing.T) {
	tests := []struct {
		name       string
		line       string
		trimmed    string
		wantName   string
		wantRet    string
		wantParams string
	}{
		{
			name:       "normal with params",
			line:       "declare i32 @main.bpfCoreFieldExists(ptr, ptr)",
			trimmed:    "declare i32 @main.bpfCoreFieldExists(ptr, ptr)",
			wantName:   "main.bpfCoreFieldExists",
			wantRet:    "i32",
			wantParams: "ptr, ptr",
		},
		{
			name:    "missing @ sign",
			line:    "declare void something()",
			trimmed: "declare void something()",
		},
		{
			name:       "void return type",
			line:       "declare void @llvm.memset.p0.i64(ptr, i8, i64, i1)",
			trimmed:    "declare void @llvm.memset.p0.i64(ptr, i8, i64, i1)",
			wantName:   "llvm.memset.p0.i64",
			wantRet:    "void",
			wantParams: "ptr, i8, i64, i1",
		},
		{
			name:     "no params",
			line:     "declare void @unused_func()",
			trimmed:  "declare void @unused_func()",
			wantName: "unused_func",
			wantRet:  "void",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := parseDeclare(tt.line, tt.trimmed)
			if d.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", d.Name, tt.wantName)
			}
			if d.RetType != tt.wantRet {
				t.Errorf("RetType = %q, want %q", d.RetType, tt.wantRet)
			}
			if d.Params != tt.wantParams {
				t.Errorf("Params = %q, want %q", d.Params, tt.wantParams)
			}
			if d.Raw != tt.line {
				t.Errorf("Raw = %q, want %q", d.Raw, tt.line)
			}
		})
	}
}

func TestParseAttrGroup(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		trimmed  string
		wantID   string
		wantBody string
	}{
		{
			name:     "simple",
			line:     `attributes #0 = { nounwind }`,
			trimmed:  `attributes #0 = { nounwind }`,
			wantID:   "0",
			wantBody: " nounwind ",
		},
		{
			name:     "with target features",
			line:     `attributes #4 = { "target-cpu"="generic" "target-features"="+neon" }`,
			trimmed:  `attributes #4 = { "target-cpu"="generic" "target-features"="+neon" }`,
			wantID:   "4",
			wantBody: ` "target-cpu"="generic" "target-features"="+neon" `,
		},
		{
			name:    "multi-digit ID",
			line:    `attributes #12 = { nounwind }`,
			trimmed: `attributes #12 = { nounwind }`,
			wantID:  "12",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ag := parseAttrGroup(tt.line, tt.trimmed)
			if ag.ID != tt.wantID {
				t.Errorf("ID = %q, want %q", ag.ID, tt.wantID)
			}
			if tt.wantBody != "" && ag.Body != tt.wantBody {
				t.Errorf("Body = %q, want %q", ag.Body, tt.wantBody)
			}
			if ag.Raw != tt.line {
				t.Errorf("Raw = %q, want %q", ag.Raw, tt.line)
			}
		})
	}
}

func TestExtractQuoted(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{"found", `source_filename = "hello.go"`, "hello.go"},
		{"empty quoted string", `source_filename = ""`, ""},
		{"missing first quote", "source_filename = hello", ""},
		{"missing second quote", `source_filename = "hello`, ""},
		{"target triple", `target triple = "bpf"`, "bpf"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractQuoted(tt.line)
			if got != tt.want {
				t.Errorf("extractQuoted(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

func TestExtractSection(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{"found", `@x = global i32 0, section "license", align 1`, "license"},
		{"dot maps", `@x = global i32 0, section ".maps"`, ".maps"},
		{"missing", `@x = global i32 0, align 1`, ""},
		{"missing closing quote", `@x = global i32 0, section "oops`, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSection(tt.line)
			if got != tt.want {
				t.Errorf("extractSection(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

func TestExtractAlign(t *testing.T) {
	tests := []struct {
		name string
		line string
		want int
	}{
		{"found 8", "@x = global i32 0, align 8", 8},
		{"found 1", "@x = global i32 0, align 1", 1},
		{"missing", "@x = global i32 0", 0},
		{"no digits after align", "@x = global i32 0, align ", 0},
		{"uses last occurrence", "@x align 4 = global i32 0, align 16", 16},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractAlign(tt.line)
			if got != tt.want {
				t.Errorf("extractAlign(%q) = %d, want %d", tt.line, got, tt.want)
			}
		})
	}
}

func TestExtractMetaAttachments(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantLen int
		wantKey string
		wantVal string
	}{
		{
			name:    "with dbg",
			line:    "  call void @foo() !dbg !42",
			wantLen: 1,
			wantKey: "dbg",
			wantVal: "!42",
		},
		{
			name:    "no metadata",
			line:    "  call void @foo()",
			wantLen: 0,
		},
		{
			name:    "multiple attachments",
			line:    "  %x = call i32 @f() !dbg !10 !prof !11",
			wantLen: 2,
			wantKey: "dbg",
			wantVal: "!10",
		},
		{
			name:    "numeric only skipped",
			line:    "!0 = distinct !DICompileUnit()",
			wantLen: 0,
		},
		{
			name:    "key after quote skipped",
			line:    `"x"!meta !5`,
			wantLen: 0,
		},
		{
			name:    "bang at end of line",
			line:    "something !",
			wantLen: 0,
		},
		{
			name:    "key without value",
			line:    "something !dbg",
			wantLen: 0,
		},
		{
			name:    "key with non-numeric value",
			line:    "something !dbg distinct",
			wantLen: 0,
		},
		{
			name:    "empty string",
			line:    "",
			wantLen: 0,
		},
		{
			name:    "bang followed by non-ident non-digit",
			line:    "x ! y",
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractMetaAttachments(tt.line)
			if len(got) != tt.wantLen {
				t.Fatalf("len = %d, want %d; got %v", len(got), tt.wantLen, got)
			}
			if tt.wantLen > 0 {
				if got[0].Key != tt.wantKey {
					t.Errorf("Key = %q, want %q", got[0].Key, tt.wantKey)
				}
				if got[0].Value != tt.wantVal {
					t.Errorf("Value = %q, want %q", got[0].Value, tt.wantVal)
				}
			}
		})
	}
}

func TestExtractAttrRef(t *testing.T) {
	tests := []struct {
		name  string
		attrs string
		want  string
	}{
		{"found single digit", `section "xdp" #0`, "#0"},
		{"found multi digit", `#42 nounwind`, "#42"},
		{"not found", `section "xdp"`, ""},
		{"hash without digits", `# nounwind`, ""},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractAttrRef(tt.attrs)
			if got != tt.want {
				t.Errorf("extractAttrRef(%q) = %q, want %q", tt.attrs, got, tt.want)
			}
		})
	}
}

func TestExtractDefineRetType(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{"simple i32", "define i32 @my_func() {", "i32"},
		{"void", "define void @my_func() {", "void"},
		{"with internal", "define internal i32 @my_func() {", "i32"},
		{"with dso_local", "define dso_local i64 @f() {", "i64"},
		{"with hidden", "define hidden ptr @f() {", "ptr"},
		{"with multiple keywords", "define private dso_local local_unnamed_addr i32 @f() {", "i32"},
		{"all keywords no type", "define internal @f() {", ""},
		{"no @ sign", "define i32 missing() {", ""},
		{"noundef keyword", "define noundef i32 @f() {", "i32"},
		{"linkonce_odr", "define linkonce_odr i32 @f() {", "i32"},
		{"weak_odr", "define weak_odr void @f() {", "void"},
		{"available_externally", "define available_externally i64 @f() {", "i64"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDefineRetType(tt.line)
			if got != tt.want {
				t.Errorf("extractDefineRetType(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

func TestFindCloseParen(t *testing.T) {
	tests := []struct {
		name    string
		s       string
		openIdx int
		want    int
	}{
		{"simple", "(hello)", 0, 6},
		{"nested", "((inner))", 0, 8},
		{"with content", "func(ptr %x, i32 %y)", 4, 19},
		{"unmatched", "(hello", 0, -1},
		{"deeply nested", "(a(b(c))d)", 0, 9},
		{"mid string open", "xx(yy)zz", 2, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findCloseParen(tt.s, tt.openIdx)
			if got != tt.want {
				t.Errorf("findCloseParen(%q, %d) = %d, want %d", tt.s, tt.openIdx, got, tt.want)
			}
		})
	}
}

func TestIsLabel(t *testing.T) {
	tests := []struct {
		name    string
		trimmed string
		want    bool
	}{
		{"simple", "entry:", true},
		{"with dot", "bb.1:", true},
		{"with dash", "bb-2:", true},
		{"with underscore", "my_label:", true},
		{"with digits", "block42:", true},
		{"all caps", "LABEL:", true},
		{"empty", "", false},
		{"single char no colon", "x", false},
		{"just colon", ":", false},
		{"space in name", "foo bar:", false},
		{"at sign", "foo@bar:", false},
		{"hash in name", "foo#1:", false},
		{"exclamation", "foo!:", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLabel(tt.trimmed)
			if got != tt.want {
				t.Errorf("isLabel(%q) = %v, want %v", tt.trimmed, got, tt.want)
			}
		})
	}
}

func TestIsIdentChar(t *testing.T) {
	tests := []struct {
		name string
		c    byte
		want bool
	}{
		{"lowercase a", 'a', true},
		{"lowercase z", 'z', true},
		{"uppercase A", 'A', true},
		{"uppercase Z", 'Z', true},
		{"digit 0", '0', true},
		{"digit 9", '9', true},
		{"underscore", '_', true},
		{"dot", '.', true},
		{"space", ' ', false},
		{"at sign", '@', false},
		{"hash", '#', false},
		{"comma", ',', false},
		{"paren", '(', false},
		{"dash", '-', false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isIdentChar(tt.c)
			if got != tt.want {
				t.Errorf("isIdentChar(%q) = %v, want %v", string(tt.c), got, tt.want)
			}
		})
	}
}

func TestExtractMetadataID(t *testing.T) {
	tests := []struct {
		name string
		line string
		want int
	}{
		{"single digit", "!0 = !{}", 0},
		{"multi digit", "!42 = !{}", 42},
		{"large number", "!999 = !{}", 999},
		{"with tabs before equals", "!5\t= !{}", 5},
		{"with spaces before equals", "!7   = !{}", 7},
		{"missing bang", "0 = !{}", -1},
		{"named metadata", "!llvm.dbg.cu = !{!0}", -1},
		{"no equals sign", "!0 !{}", -1},
		{"too short", "!", -1},
		{"empty", "", -1},
		{"single digit no space", "!3=!{}", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractMetadataID(tt.line)
			if got != tt.want {
				t.Errorf("extractMetadataID(%q) = %d, want %d", tt.line, got, tt.want)
			}
		})
	}
}

func TestSplitStructFields(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{"single field", " i32 ", []string{"i32"}},
		{"multiple fields", " i32, i64, ptr ", []string{"i32", "i64", "ptr"}},
		{"nested brackets", " i32, [16 x i8] ", []string{"i32", "[16 x i8]"}},
		{"nested braces", " i32, { i32, i32 } ", []string{"i32", "{ i32, i32 }"}},
		{"nested parens", " i32, ptr (i32, i32)* ", []string{"i32", "ptr (i32, i32)*"}},
		{"empty", "", nil},
		{"spaces only", "   ", nil},
		{"deeply nested", " [2 x { i32, [4 x i8] }] ", []string{"[2 x { i32, [4 x i8] }]"}},
		{"no spaces", "i32,i64", []string{"i32", "i64"}},
		{"trailing comma", " i32, ", []string{"i32"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitStructFields(tt.body)
			if len(got) != len(tt.want) {
				t.Fatalf("splitStructFields(%q) = %v, want %v", tt.body, got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("field[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func FuzzParse(f *testing.F) {
	f.Add(minimalIR)
	f.Add(mapAndHelperIR)
	f.Add(coreGEPIR)
	f.Add(coreFieldExistsIR)
	f.Add(metadataIR)
	f.Add(datasectionsIR)
	f.Add(runtimeAndAllocIR)
	f.Add(cleanupIR)
	f.Add(transformSeedIR)
	f.Add("this is not llvm ir\n")
	f.Add("")

	f.Fuzz(func(t *testing.T, input string) {
		m, err := Parse(input)
		if err != nil {
			return
		}
		_ = Serialize(m)
	})
}
