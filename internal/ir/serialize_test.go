package ir

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func makeInstModule(inst *Instruction) *Module {
	return &Module{
		Entries: []TopLevelEntry{{
			Kind: TopFunction,
			Function: &Function{
				Raw:      "define void @wrapper() {",
				Modified: true,
				Blocks: []*BasicBlock{{
					Label:        "entry",
					Instructions: []*Instruction{inst},
				}},
			},
		}},
	}
}

func wantInstFunc(instLine string) string {
	return "define void @wrapper() {\nentry:\n" + instLine + "\n}"
}

func TestSerialize(t *testing.T) {
	tests := []struct {
		name string
		mod  *Module
		want string
	}{
		{
			name: "empty module",
			mod:  &Module{},
			want: "",
		},
		{
			name: "single raw comment",
			mod: &Module{
				Entries: []TopLevelEntry{
					{Kind: TopComment, Raw: "; hello"},
				},
			},
			want: "; hello",
		},
		{
			name: "removed entry skipped",
			mod: &Module{
				Entries: []TopLevelEntry{
					{Kind: TopComment, Raw: "; keep"},
					{Kind: TopComment, Raw: "; skip", Removed: true},
					{Kind: TopComment, Raw: "; also keep"},
				},
			},
			want: "; keep\n; also keep",
		},
		{
			name: "newline separators between entries",
			mod: &Module{
				Entries: []TopLevelEntry{
					{Kind: TopComment, Raw: "; a"},
					{Kind: TopComment, Raw: "; b"},
					{Kind: TopComment, Raw: "; c"},
				},
			},
			want: "; a\n; b\n; c",
		},
		{
			name: "data layout unchanged uses raw",
			mod: &Module{
				DataLayout: "e-m:e-p:64:64",
				Entries: []TopLevelEntry{
					{Kind: TopDataLayout, Raw: `target datalayout = "e-m:e-p:64:64"`},
				},
			},
			want: `target datalayout = "e-m:e-p:64:64"`,
		},
		{
			name: "data layout modified",
			mod: &Module{
				DataLayout: "e-m:e-p:32:32",
				Entries: []TopLevelEntry{
					{Kind: TopDataLayout, Raw: `target datalayout = "e-m:e-p:64:64"`},
				},
			},
			want: `target datalayout = "e-m:e-p:32:32"`,
		},
		{
			name: "triple unchanged uses raw",
			mod: &Module{
				Triple: "bpf",
				Entries: []TopLevelEntry{
					{Kind: TopTriple, Raw: `target triple = "bpf"`},
				},
			},
			want: `target triple = "bpf"`,
		},
		{
			name: "triple modified",
			mod: &Module{
				Triple: "bpfel-unknown-none",
				Entries: []TopLevelEntry{
					{Kind: TopTriple, Raw: `target triple = "bpf"`},
				},
			},
			want: `target triple = "bpfel-unknown-none"`,
		},
		{
			name: "default kind uses raw",
			mod: &Module{
				Entries: []TopLevelEntry{
					{Kind: TopSourceFilename, Raw: `source_filename = "test.c"`},
				},
			},
			want: `source_filename = "test.c"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Serialize(tt.mod)
			if got != tt.want {
				t.Errorf("got:\n%s\nwant:\n%s", got, tt.want)
			}
		})
	}
}

func TestEstimateSize(t *testing.T) {
	tests := []struct {
		name string
		mod  *Module
		want int
	}{
		{
			name: "empty module",
			mod:  &Module{},
			want: 0,
		},
		{
			name: "two raw entries",
			mod: &Module{
				Entries: []TopLevelEntry{
					{Raw: "hello"},
					{Raw: "world"},
				},
			},
			want: 12,
		},
		{
			name: "entry with function body",
			mod: &Module{
				Entries: []TopLevelEntry{
					{
						Raw: "define void @f() {",
						Function: &Function{
							BodyRaw: []string{"entry:", "  ret void", "}"},
						},
					},
				},
			},
			want: 39,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := estimateSize(tt.mod)
			if got != tt.want {
				t.Errorf("estimateSize() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSerializeTypeDef(t *testing.T) {
	tests := []struct {
		name  string
		entry TopLevelEntry
		want  string
	}{
		{
			name: "modified two fields",
			entry: TopLevelEntry{
				Kind: TopTypeDef,
				TypeDef: &TypeDef{
					Name:     "%myStruct",
					Fields:   []string{"i32", "i64"},
					Modified: true,
				},
			},
			want: "%myStruct = type { i32, i64 }",
		},
		{
			name: "modified single field",
			entry: TopLevelEntry{
				Kind: TopTypeDef,
				TypeDef: &TypeDef{
					Name:     "%simple",
					Fields:   []string{"ptr"},
					Modified: true,
				},
			},
			want: "%simple = type { ptr }",
		},
		{
			name: "unmodified uses raw",
			entry: TopLevelEntry{
				Kind: TopTypeDef,
				Raw:  "%raw = type opaque",
				TypeDef: &TypeDef{
					Name:     "%raw",
					Modified: false,
				},
			},
			want: "%raw = type opaque",
		},
		{
			name: "nil typedef uses raw",
			entry: TopLevelEntry{
				Kind: TopTypeDef,
				Raw:  "%opaque = type opaque",
			},
			want: "%opaque = type opaque",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mod := &Module{Entries: []TopLevelEntry{tt.entry}}
			got := Serialize(mod)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSerializeGlobal(t *testing.T) {
	tests := []struct {
		name  string
		entry TopLevelEntry
		want  string
	}{
		{
			name: "name and linkage only",
			entry: TopLevelEntry{
				Kind: TopGlobal,
				Global: &Global{
					Name:     "foo",
					Linkage:  "global",
					Modified: true,
				},
			},
			want: "@foo = global",
		},
		{
			name: "with type and initializer",
			entry: TopLevelEntry{
				Kind: TopGlobal,
				Global: &Global{
					Name:        "bar",
					Linkage:     "global",
					Type:        "i32",
					Initializer: "42",
					Modified:    true,
				},
			},
			want: "@bar = global i32 42",
		},
		{
			name: "with section",
			entry: TopLevelEntry{
				Kind: TopGlobal,
				Global: &Global{
					Name:        "sec",
					Linkage:     "global",
					Type:        "i32",
					Initializer: "0",
					Section:     ".maps",
					Modified:    true,
				},
			},
			want: `@sec = global i32 0, section ".maps"`,
		},
		{
			name: "with align",
			entry: TopLevelEntry{
				Kind: TopGlobal,
				Global: &Global{
					Name:        "aligned",
					Linkage:     "global",
					Type:        "i64",
					Initializer: "0",
					Align:       8,
					Modified:    true,
				},
			},
			want: "@aligned = global i64 0, align 8",
		},
		{
			name: "with metadata",
			entry: TopLevelEntry{
				Kind: TopGlobal,
				Global: &Global{
					Name:        "meta",
					Linkage:     "global",
					Type:        "i32",
					Initializer: "0",
					Metadata:    []MetaAttach{{Key: "dbg", Value: "!5"}},
					Modified:    true,
				},
			},
			want: "@meta = global i32 0, !dbg !5",
		},
		{
			name: "all fields",
			entry: TopLevelEntry{
				Kind: TopGlobal,
				Global: &Global{
					Name:        "all",
					Linkage:     "internal global",
					Type:        "i64",
					Initializer: "42",
					Section:     ".data",
					Align:       8,
					Metadata: []MetaAttach{
						{Key: "dbg", Value: "!0"},
						{Key: "type", Value: "!1"},
					},
					Modified: true,
				},
			},
			want: `@all = internal global i64 42, section ".data", align 8, !dbg !0, !type !1`,
		},
		{
			name: "unmodified uses raw",
			entry: TopLevelEntry{
				Kind: TopGlobal,
				Raw:  "@raw = global i32 99",
				Global: &Global{
					Name:     "raw",
					Modified: false,
				},
			},
			want: "@raw = global i32 99",
		},
		{
			name: "nil global uses raw",
			entry: TopLevelEntry{
				Kind: TopGlobal,
				Raw:  "@x = external global i32",
			},
			want: "@x = external global i32",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mod := &Module{Entries: []TopLevelEntry{tt.entry}}
			got := Serialize(mod)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSerializeDeclare(t *testing.T) {
	tests := []struct {
		name  string
		entry TopLevelEntry
		want  string
	}{
		{
			name: "modified with params",
			entry: TopLevelEntry{
				Kind: TopDeclare,
				Declare: &Declare{
					Name:     "my_func",
					RetType:  "i32",
					Params:   "ptr, i64",
					Modified: true,
				},
			},
			want: "declare i32 @my_func(ptr, i64)",
		},
		{
			name: "modified void no params",
			entry: TopLevelEntry{
				Kind: TopDeclare,
				Declare: &Declare{
					Name:     "nop",
					RetType:  "void",
					Params:   "",
					Modified: true,
				},
			},
			want: "declare void @nop()",
		},
		{
			name: "removed declare produces nothing",
			entry: TopLevelEntry{
				Kind: TopDeclare,
				Declare: &Declare{
					Name:    "gone",
					Removed: true,
				},
			},
			want: "",
		},
		{
			name: "unmodified uses raw",
			entry: TopLevelEntry{
				Kind: TopDeclare,
				Raw:  "declare void @raw_func() #3",
				Declare: &Declare{
					Name: "raw_func",
				},
			},
			want: "declare void @raw_func() #3",
		},
		{
			name: "nil declare uses raw",
			entry: TopLevelEntry{
				Kind: TopDeclare,
				Raw:  "declare void @ext()",
			},
			want: "declare void @ext()",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mod := &Module{Entries: []TopLevelEntry{tt.entry}}
			got := Serialize(mod)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSerializeFunction(t *testing.T) {
	tests := []struct {
		name  string
		entry TopLevelEntry
		want  string
	}{
		{
			name: "unmodified uses raw and body",
			entry: TopLevelEntry{
				Kind: TopFunction,
				Function: &Function{
					Raw:     "define void @f() {",
					BodyRaw: []string{"entry:", "  ret void", "}"},
				},
			},
			want: "define void @f() {\nentry:\n  ret void\n}",
		},
		{
			name: "removed function produces nothing",
			entry: TopLevelEntry{
				Kind: TopFunction,
				Function: &Function{
					Raw:     "define void @f() {",
					Removed: true,
				},
			},
			want: "",
		},
		{
			name: "nil function uses entry raw",
			entry: TopLevelEntry{
				Kind: TopFunction,
				Raw:  "define void @f() {}",
			},
			want: "define void @f() {}",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mod := &Module{Entries: []TopLevelEntry{tt.entry}}
			got := Serialize(mod)
			if got != tt.want {
				t.Errorf("got:\n%s\nwant:\n%s", got, tt.want)
			}
		})
	}
}

func TestSerializeFunctionModified(t *testing.T) {
	tests := []struct {
		name string
		fn   *Function
		want string
	}{
		{
			name: "single block with label",
			fn: &Function{
				Raw:      "define void @f() {",
				Modified: true,
				Blocks: []*BasicBlock{{
					Label: "entry",
					Instructions: []*Instruction{
						{Raw: "  ret void"},
					},
				}},
			},
			want: "define void @f() {\nentry:\n  ret void\n}",
		},
		{
			name: "block without label",
			fn: &Function{
				Raw:      "define void @f() {",
				Modified: true,
				Blocks: []*BasicBlock{{
					Label: "",
					Instructions: []*Instruction{
						{Raw: "  ret void"},
					},
				}},
			},
			want: "define void @f() {\n  ret void\n}",
		},
		{
			name: "multiple blocks",
			fn: &Function{
				Raw:      "define i32 @f(i1 %cond) {",
				Modified: true,
				Blocks: []*BasicBlock{
					{
						Label: "entry",
						Instructions: []*Instruction{
							{Raw: "  br i1 %cond, label %then, label %else"},
						},
					},
					{
						Label: "then",
						Instructions: []*Instruction{
							{Raw: "  ret i32 1"},
						},
					},
					{
						Label: "else",
						Instructions: []*Instruction{
							{Raw: "  ret i32 0"},
						},
					},
				},
			},
			want: "define i32 @f(i1 %cond) {\n" +
				"entry:\n  br i1 %cond, label %then, label %else\n" +
				"then:\n  ret i32 1\n" +
				"else:\n  ret i32 0\n}",
		},
		{
			name: "mixed modified and unmodified instructions",
			fn: &Function{
				Raw:      "define void @f() {",
				Modified: true,
				Blocks: []*BasicBlock{{
					Label: "entry",
					Instructions: []*Instruction{
						{
							Kind:     InstCall,
							Modified: true,
							Call:     &CallInst{RetType: "void", Callee: "@foo", Args: ""},
						},
						{Raw: "  ret void"},
					},
				}},
			},
			want: "define void @f() {\nentry:\n  call void @foo()\n  ret void\n}",
		},
		{
			name: "no blocks",
			fn: &Function{
				Raw:      "define void @empty() {",
				Modified: true,
			},
			want: "define void @empty() {\n}",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mod := &Module{
				Entries: []TopLevelEntry{{
					Kind:     TopFunction,
					Function: tt.fn,
				}},
			}
			got := Serialize(mod)
			if got != tt.want {
				t.Errorf("got:\n%s\nwant:\n%s", got, tt.want)
			}
		})
	}
}

func TestSerializeInstruction(t *testing.T) {
	tests := []struct {
		name     string
		inst     *Instruction
		wantLine string
	}{
		{
			name: "InstOther uses raw",
			inst: &Instruction{
				Kind:     InstOther,
				Modified: true,
				Raw:      "  ret void",
			},
			wantLine: "  ret void",
		},
		{
			name: "InstCall dispatches",
			inst: &Instruction{
				Kind:     InstCall,
				Modified: true,
				Call:     &CallInst{RetType: "void", Callee: "@nop", Args: ""},
			},
			wantLine: "  call void @nop()",
		},
		{
			name: "InstGEP dispatches",
			inst: &Instruction{
				Kind:     InstGEP,
				Modified: true,
				SSAName:  "%p",
				GEP: &GEPInst{
					BaseType: "i8",
					PtrType:  "ptr",
					Base:     "%x",
				},
			},
			wantLine: "  %p = getelementptr i8, ptr %x",
		},
		{
			name: "InstAlloca dispatches",
			inst: &Instruction{
				Kind:     InstAlloca,
				Modified: true,
				SSAName:  "%a",
				Alloca:   &AllocaInst{Type: "i32"},
			},
			wantLine: "  %a = alloca i32",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Serialize(makeInstModule(tt.inst))
			want := wantInstFunc(tt.wantLine)
			if got != want {
				t.Errorf("got:\n%s\nwant:\n%s", got, want)
			}
		})
	}
}

func TestSerializeCallInst(t *testing.T) {
	tests := []struct {
		name     string
		inst     *Instruction
		wantLine string
	}{
		{
			name: "no SSAName no Tail",
			inst: &Instruction{
				Kind:     InstCall,
				Modified: true,
				Call:     &CallInst{RetType: "void", Callee: "@foo", Args: ""},
			},
			wantLine: "  call void @foo()",
		},
		{
			name: "with SSAName",
			inst: &Instruction{
				Kind:     InstCall,
				Modified: true,
				SSAName:  "%0",
				Call:     &CallInst{RetType: "i32", Callee: "@bar", Args: "i32 1"},
			},
			wantLine: "  %0 = call i32 @bar(i32 1)",
		},
		{
			name: "with Tail",
			inst: &Instruction{
				Kind:     InstCall,
				Modified: true,
				Call:     &CallInst{RetType: "void", Callee: "@baz", Args: "", Tail: "tail"},
			},
			wantLine: "  tail call void @baz()",
		},
		{
			name: "with SSAName and Tail",
			inst: &Instruction{
				Kind:     InstCall,
				Modified: true,
				SSAName:  "%1",
				Call:     &CallInst{RetType: "i64", Callee: "@qux", Args: "ptr %p", Tail: "musttail"},
			},
			wantLine: "  %1 = musttail call i64 @qux(ptr %p)",
		},
		{
			name: "with metadata",
			inst: &Instruction{
				Kind:     InstCall,
				Modified: true,
				Call:     &CallInst{RetType: "void", Callee: "@foo", Args: ""},
				Metadata: []MetaAttach{{Key: "dbg", Value: "!3"}},
			},
			wantLine: "  call void @foo(), !dbg !3",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Serialize(makeInstModule(tt.inst))
			want := wantInstFunc(tt.wantLine)
			if got != want {
				t.Errorf("got:\n%s\nwant:\n%s", got, want)
			}
		})
	}
}

func TestSerializeGEPInst(t *testing.T) {
	tests := []struct {
		name     string
		inst     *Instruction
		wantLine string
	}{
		{
			name: "minimal without inbounds or PtrType",
			inst: &Instruction{
				Kind:     InstGEP,
				Modified: true,
				GEP: &GEPInst{
					BaseType: "i8",
					Base:     "%p",
				},
			},
			wantLine: "  getelementptr i8, %p",
		},
		{
			name: "with inbounds",
			inst: &Instruction{
				Kind:     InstGEP,
				Modified: true,
				SSAName:  "%gep",
				GEP: &GEPInst{
					Inbounds: true,
					BaseType: "i8",
					PtrType:  "ptr",
					Base:     "%p",
					Indices:  []string{"i64 4"},
				},
			},
			wantLine: "  %gep = getelementptr inbounds i8, ptr %p, i64 4",
		},
		{
			name: "with flags",
			inst: &Instruction{
				Kind:     InstGEP,
				Modified: true,
				GEP: &GEPInst{
					Inbounds: true,
					Flags:    "nuw",
					BaseType: "i8",
					PtrType:  "ptr",
					Base:     "%p",
					Indices:  []string{"i64 4"},
				},
			},
			wantLine: "  getelementptr inbounds nuw i8, ptr %p, i64 4",
		},
		{
			name: "with PtrType and multiple indices",
			inst: &Instruction{
				Kind:     InstGEP,
				Modified: true,
				SSAName:  "%ptr",
				GEP: &GEPInst{
					Inbounds: true,
					BaseType: "%main.Task",
					PtrType:  "ptr",
					Base:     "%task",
					Indices:  []string{"i32 0", "i32 1"},
				},
			},
			wantLine: "  %ptr = getelementptr inbounds %main.Task, ptr %task, i32 0, i32 1",
		},
		{
			name: "with metadata",
			inst: &Instruction{
				Kind:     InstGEP,
				Modified: true,
				SSAName:  "%g",
				GEP: &GEPInst{
					Inbounds: true,
					BaseType: "i8",
					PtrType:  "ptr",
					Base:     "%p",
					Indices:  []string{"i64 0"},
				},
				Metadata: []MetaAttach{{Key: "llvm.preserve.access.index", Value: "!7"}},
			},
			wantLine: "  %g = getelementptr inbounds i8, ptr %p, i64 0, !llvm.preserve.access.index !7",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Serialize(makeInstModule(tt.inst))
			want := wantInstFunc(tt.wantLine)
			if got != want {
				t.Errorf("got:\n%s\nwant:\n%s", got, want)
			}
		})
	}
}

func TestSerializeAllocaInst(t *testing.T) {
	tests := []struct {
		name     string
		inst     *Instruction
		wantLine string
	}{
		{
			name: "without align",
			inst: &Instruction{
				Kind:     InstAlloca,
				Modified: true,
				SSAName:  "%a",
				Alloca:   &AllocaInst{Type: "i32"},
			},
			wantLine: "  %a = alloca i32",
		},
		{
			name: "with align",
			inst: &Instruction{
				Kind:     InstAlloca,
				Modified: true,
				SSAName:  "%buf",
				Alloca:   &AllocaInst{Type: "[16 x i8]", Align: 4},
			},
			wantLine: "  %buf = alloca [16 x i8], align 4",
		},
		{
			name: "no SSAName",
			inst: &Instruction{
				Kind:     InstAlloca,
				Modified: true,
				Alloca:   &AllocaInst{Type: "i8"},
			},
			wantLine: "  alloca i8",
		},
		{
			name: "with metadata",
			inst: &Instruction{
				Kind:     InstAlloca,
				Modified: true,
				SSAName:  "%s",
				Alloca:   &AllocaInst{Type: "%myStruct", Align: 8},
				Metadata: []MetaAttach{{Key: "dbg", Value: "!2"}},
			},
			wantLine: "  %s = alloca %myStruct, align 8, !dbg !2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Serialize(makeInstModule(tt.inst))
			want := wantInstFunc(tt.wantLine)
			if got != want {
				t.Errorf("got:\n%s\nwant:\n%s", got, want)
			}
		})
	}
}

func TestSerializeAttrGroup(t *testing.T) {
	tests := []struct {
		name  string
		entry TopLevelEntry
		want  string
	}{
		{
			name: "modified attr group",
			entry: TopLevelEntry{
				Kind: TopAttrGroup,
				AttrGroup: &AttrGroup{
					ID:       "0",
					Body:     "nounwind",
					Modified: true,
				},
			},
			want: "attributes #0 = { nounwind }",
		},
		{
			name: "body with extra whitespace trimmed",
			entry: TopLevelEntry{
				Kind: TopAttrGroup,
				AttrGroup: &AttrGroup{
					ID:       "4",
					Body:     `  "target-cpu"="generic"  `,
					Modified: true,
				},
			},
			want: `attributes #4 = { "target-cpu"="generic" }`,
		},
		{
			name: "unmodified uses raw",
			entry: TopLevelEntry{
				Kind: TopAttrGroup,
				Raw:  `attributes #0 = { nounwind "frame-pointer"="all" }`,
				AttrGroup: &AttrGroup{
					ID:       "0",
					Modified: false,
				},
			},
			want: `attributes #0 = { nounwind "frame-pointer"="all" }`,
		},
		{
			name: "nil attr group uses raw",
			entry: TopLevelEntry{
				Kind: TopAttrGroup,
				Raw:  `attributes #1 = { optnone }`,
			},
			want: `attributes #1 = { optnone }`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mod := &Module{Entries: []TopLevelEntry{tt.entry}}
			got := Serialize(mod)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSerializeMetadata(t *testing.T) {
	tests := []struct {
		name         string
		entry        TopLevelEntry
		want         string
		wantContains []string
	}{
		{
			name: "tuple",
			entry: TopLevelEntry{
				Kind: TopMetadata,
				Metadata: &MetadataNode{
					ID:       0,
					Tuple:    []string{"!1", "!2", "!3"},
					Modified: true,
				},
			},
			want: "!0 = !{!1, !2, !3}",
		},
		{
			name: "DI single field unquoted DW_ prefix",
			entry: TopLevelEntry{
				Kind: TopMetadata,
				Metadata: &MetadataNode{
					ID:       1,
					Kind:     "DICompositeType",
					Fields:   map[string]string{"tag": "DW_TAG_structure_type"},
					Modified: true,
				},
			},
			want: "!1 = !DICompositeType(tag: DW_TAG_structure_type)",
		},
		{
			name: "DI single field unquoted metadata ref",
			entry: TopLevelEntry{
				Kind: TopMetadata,
				Metadata: &MetadataNode{
					ID:       2,
					Kind:     "DIDerivedType",
					Fields:   map[string]string{"baseType": "!4"},
					Modified: true,
				},
			},
			want: "!2 = !DIDerivedType(baseType: !4)",
		},
		{
			name: "DI single field unquoted numeric",
			entry: TopLevelEntry{
				Kind: TopMetadata,
				Metadata: &MetadataNode{
					ID:       3,
					Kind:     "DIBasicType",
					Fields:   map[string]string{"size": "32"},
					Modified: true,
				},
			},
			want: "!3 = !DIBasicType(size: 32)",
		},
		{
			name: "DI single field quoted value with dot",
			entry: TopLevelEntry{
				Kind: TopMetadata,
				Metadata: &MetadataNode{
					ID:       4,
					Kind:     "DICompositeType",
					Fields:   map[string]string{"name": "main.bpfCoreTaskStruct"},
					Modified: true,
				},
			},
			want: `!4 = !DICompositeType(name: "main.bpfCoreTaskStruct")`,
		},
		{
			name: "DI multiple fields check containment",
			entry: TopLevelEntry{
				Kind: TopMetadata,
				Metadata: &MetadataNode{
					ID:       5,
					Kind:     "DIDerivedType",
					Fields:   map[string]string{"tag": "DW_TAG_member", "size": "32"},
					Modified: true,
				},
			},
			wantContains: []string{"!5 = !DIDerivedType(", "tag: DW_TAG_member", "size: 32", ")"},
		},
		{
			name: "fallback to raw when no kind or tuple",
			entry: TopLevelEntry{
				Kind: TopMetadata,
				Metadata: &MetadataNode{
					ID:       6,
					Raw:      "!6 = distinct !DICompileUnit(language: DW_LANG_Go)",
					Modified: true,
				},
			},
			want: "!6 = distinct !DICompileUnit(language: DW_LANG_Go)",
		},
		{
			name: "unmodified uses entry raw",
			entry: TopLevelEntry{
				Kind: TopMetadata,
				Raw:  "!0 = !{!1, !2}",
				Metadata: &MetadataNode{
					ID:       0,
					Modified: false,
				},
			},
			want: "!0 = !{!1, !2}",
		},
		{
			name: "nil metadata uses raw",
			entry: TopLevelEntry{
				Kind: TopMetadata,
				Raw:  "!0 = !{null}",
			},
			want: "!0 = !{null}",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mod := &Module{Entries: []TopLevelEntry{tt.entry}}
			got := Serialize(mod)
			if tt.want != "" {
				if got != tt.want {
					t.Errorf("got %q, want %q", got, tt.want)
				}
			}
			for _, s := range tt.wantContains {
				if !strings.Contains(got, s) {
					t.Errorf("output %q missing %q", got, s)
				}
			}
		})
	}
}

func TestSerializeMetaAttachments(t *testing.T) {
	tests := []struct {
		name       string
		meta       []MetaAttach
		wantSuffix string
	}{
		{
			name:       "no attachments",
			meta:       nil,
			wantSuffix: "",
		},
		{
			name:       "single attachment",
			meta:       []MetaAttach{{Key: "dbg", Value: "!5"}},
			wantSuffix: ", !dbg !5",
		},
		{
			name: "multiple attachments",
			meta: []MetaAttach{
				{Key: "dbg", Value: "!5"},
				{Key: "llvm.preserve.access.index", Value: "!7"},
			},
			wantSuffix: ", !dbg !5, !llvm.preserve.access.index !7",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst := &Instruction{
				Kind:     InstCall,
				Modified: true,
				Call:     &CallInst{RetType: "void", Callee: "@target", Args: ""},
				Metadata: tt.meta,
			}
			got := Serialize(makeInstModule(inst))
			want := wantInstFunc("  call void @target()" + tt.wantSuffix)
			if got != want {
				t.Errorf("got:\n%s\nwant:\n%s", got, want)
			}
		})
	}
}

func TestNeedsQuoting(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"metadata ref", "!42", false},
		{"DW_TAG prefix", "DW_TAG_member", false},
		{"DW_ATE prefix", "DW_ATE_signed", false},
		{"plain alpha", "abc", false},
		{"alphanumeric", "abc123", false},
		{"underscore", "foo_bar", false},
		{"empty string", "", false},
		{"dot in name", "main.Struct", true},
		{"space", "hello world", true},
		{"slash", "a/b", true},
		{"colon", "a:b", true},
		{"dash", "a-b", true},
		{"at sign", "@foo", true},
		{"parenthesis", "(x)", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := needsQuoting(tt.input)
			if got != tt.want {
				t.Errorf("needsQuoting(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestRoundTripMinimal(t *testing.T) {
	testRoundTrip(t, "minimal", minimalIR)
}

func TestRoundTripTransformSeed(t *testing.T) {
	testRoundTrip(t, "transformSeed", transformSeedIR)
}

func TestRoundTripMapAndHelper(t *testing.T) {
	testRoundTrip(t, "mapAndHelper", mapAndHelperIR)
}

func TestRoundTripCoreGEP(t *testing.T) {
	testRoundTrip(t, "coreGEP", coreGEPIR)
}

func TestRoundTripCoreFieldExists(t *testing.T) {
	testRoundTrip(t, "coreFieldExists", coreFieldExistsIR)
}

func TestRoundTripMetadata(t *testing.T) {
	testRoundTrip(t, "metadata", metadataIR)
}

func TestRoundTripDataSections(t *testing.T) {
	testRoundTrip(t, "datasections", datasectionsIR)
}

func TestRoundTripRuntimeAndAlloc(t *testing.T) {
	testRoundTrip(t, "runtimeAndAlloc", runtimeAndAllocIR)
}

func TestRoundTripCleanup(t *testing.T) {
	testRoundTrip(t, "cleanup", cleanupIR)
}

func TestRoundTripMinimalFile(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "minimal.ll"))
	if err != nil {
		t.Skipf("testdata/minimal.ll not found: %v", err)
	}
	testRoundTrip(t, "minimal.ll", string(data))
}

func TestRoundTripTinyGoProbe(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "tinygo_probe.ll"))
	if err != nil {
		t.Skipf("testdata/tinygo_probe.ll not found: %v", err)
	}
	testRoundTrip(t, "tinygo_probe.ll", string(data))
}
