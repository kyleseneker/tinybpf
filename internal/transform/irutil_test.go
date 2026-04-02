package transform

import (
	"strings"
	"testing"

	"github.com/kyleseneker/tinybpf/internal/ir"
)

func TestIsRuntimeFunc(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"main", true},
		{"__dynamic_loader", true},
		{"tinygo_signal_handler", true},
		{"runtime.runMain", true},
		{"internal/task.start", true},
		{"my_program", false},
		{"handle_connect", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := isRuntimeFunc(tt.name); got != tt.want {
			t.Errorf("isRuntimeFunc(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestIsRuntimeGlobal(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"runtime.scheduler", true},
		{"internal/task.state", true},
		{"reflect.typemap", true},
		{".string.1", true},
		{"llvm.used", true},
		{"main.events", false},
		{"my_global", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := isRuntimeGlobal(tt.name); got != tt.want {
			t.Errorf("isRuntimeGlobal(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestInsertSectionAttr(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		section string
		want    string
	}{
		{
			name:    "before align",
			line:    `@main.events = global { ptr, ptr } zeroinitializer, align 8`,
			section: ".maps",
			want:    `@main.events = global { ptr, ptr } zeroinitializer, section ".maps", align 8`,
		},
		{
			name:    "no align",
			line:    `@_license = global [4 x i8] c"GPL\00"`,
			section: "license",
			want:    `@_license = global [4 x i8] c"GPL\00", section "license"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := insertSectionAttr(tt.line, tt.section); got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}

func TestInsertSection(t *testing.T) {
	tests := []struct {
		name string
		line string
		sec  string
		want string
	}{
		{
			name: "no brace",
			line: `declare i32 @my_func(ptr %ctx)`,
			sec:  "kprobe/test",
			want: `declare i32 @my_func(ptr %ctx) section "kprobe/test"`,
		},
		{
			name: "with brace",
			line: `define i32 @my_func(ptr %ctx) {`,
			sec:  "kprobe/test",
			want: `define i32 @my_func(ptr %ctx) section "kprobe/test"  {`,
		},
		{
			name: "with metadata",
			line: `define i32 @my_func(ptr %ctx) !dbg !5 {`,
			sec:  "kprobe/test",
			want: `define i32 @my_func(ptr %ctx) section "kprobe/test"  !dbg !5 {`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := insertSection(tt.line, tt.sec)
			if !strings.Contains(got, `section "`+tt.sec+`"`) {
				t.Errorf("missing section attr in: %s", got)
			}
			if tt.want != "" && got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}

func TestParseMetaID(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"!42", 42},
		{"  !0", 0},
		{"!123 = !DICompositeType(tag: DW_TAG_structure_type)", 123},
		{"!", -1},
		{"!abc", -1},
		{"not meta", -1},
		{"", -1},
	}
	for _, tt := range tests {
		if got := parseMetaID(tt.input); got != tt.want {
			t.Errorf("parseMetaID(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestIsBpfCoreStructMeta(t *testing.T) {
	tests := []struct {
		line string
		want bool
	}{
		{"!5 = !DICompositeType(tag: DW_TAG_structure_type, name: \"main.bpfCoreTaskStruct\")", true},
		{"!5 = !DIDerivedType(tag: DW_TAG_member, name: \"Pid\")", false},
		{"!5 = !DICompositeType(tag: DW_TAG_structure_type, name: \"main.bpfMapDef\")", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := isBpfCoreStructMeta(tt.line); got != tt.want {
			t.Errorf("isBpfCoreStructMeta(%q) = %v, want %v", tt.line, got, tt.want)
		}
	}
}

func TestIsIdentCharByte(t *testing.T) {
	tests := []struct {
		c    byte
		want bool
	}{
		{'a', true},
		{'z', true},
		{'A', true},
		{'Z', true},
		{'0', true},
		{'9', true},
		{'_', true},
		{'.', true},
		{' ', false},
		{'@', false},
		{'%', false},
		{'-', false},
	}
	for _, tt := range tests {
		if got := isIdentCharByte(tt.c); got != tt.want {
			t.Errorf("isIdentCharByte(%q) = %v, want %v", tt.c, got, tt.want)
		}
	}
}

func TestFirstCommaArg(t *testing.T) {
	tests := []struct {
		args string
		want string
	}{
		{"ptr %0, i32 4", "ptr %0"},
		{"i64 42", "i64 42"},
		{" ptr nonnull %sa , i32 16", "ptr nonnull %sa"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := firstCommaArg(tt.args); got != tt.want {
			t.Errorf("firstCommaArg(%q) = %q, want %q", tt.args, got, tt.want)
		}
	}
}

func TestFindSSADefInBody(t *testing.T) {
	body := []string{
		"  %0 = alloca i32",        // 0
		"  store i32 0, ptr %0",    // 1
		"  %1 = load i32, ptr %0",  // 2
		"  %2 = add i32 %1, 1",     // 3
		"  call void @foo(i32 %2)", // 4
	}
	tests := []struct {
		name     string
		ssaName  string
		startIdx int
		want     int
	}{
		{"found %2", "%2", 4, 3},
		{"found %0", "%0", 2, 0},
		{"not found", "%99", 4, -1},
		{"window limit", "%0", 4, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := findSSADefInBody(body, tt.ssaName, tt.startIdx); got != tt.want {
				t.Errorf("findSSADefInBody(_, %q, %d) = %d, want %d", tt.ssaName, tt.startIdx, got, tt.want)
			}
		})
	}
}

func TestFindFirstFuncEntry(t *testing.T) {
	tests := []struct {
		name    string
		entries []ir.TopLevelEntry
		want    int
	}{
		{
			name: "declare first",
			entries: []ir.TopLevelEntry{
				{Kind: ir.TopGlobal},
				{Kind: ir.TopDeclare},
				{Kind: ir.TopFunction},
			},
			want: 1,
		},
		{
			name: "skip removed",
			entries: []ir.TopLevelEntry{
				{Kind: ir.TopDeclare, Removed: true},
				{Kind: ir.TopFunction},
			},
			want: 1,
		},
		{
			name:    "none found",
			entries: []ir.TopLevelEntry{{Kind: ir.TopGlobal}},
			want:    -1,
		},
		{
			name:    "empty",
			entries: nil,
			want:    -1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &ir.Module{Entries: tt.entries}
			if got := findFirstFuncEntry(m); got != tt.want {
				t.Errorf("findFirstFuncEntry() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestEntryTextLines(t *testing.T) {
	tests := []struct {
		name  string
		entry ir.TopLevelEntry
		want  []string
	}{
		{
			name:  "non-function returns Raw",
			entry: ir.TopLevelEntry{Kind: ir.TopGlobal, Raw: "@x = global i32 0"},
			want:  []string{"@x = global i32 0"},
		},
		{
			name: "function returns header plus body",
			entry: ir.TopLevelEntry{
				Kind: ir.TopFunction,
				Function: &ir.Function{
					Raw:     "define i32 @f() {",
					BodyRaw: []string{"entry:", "  ret i32 0"},
				},
			},
			want: []string{"define i32 @f() {", "entry:", "  ret i32 0"},
		},
		{
			name:  "function kind with nil Function returns Raw",
			entry: ir.TopLevelEntry{Kind: ir.TopFunction, Raw: "define void @g() {}"},
			want:  []string{"define void @g() {}"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := entryTextLines(tt.entry)
			if len(got) != len(tt.want) {
				t.Fatalf("entryTextLines() returned %d lines, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("line %d = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestFindSSADefInBlocks(t *testing.T) {
	blocks := []*ir.BasicBlock{
		{
			Label: "entry",
			Instructions: []*ir.Instruction{
				{SSAName: "%0", Kind: ir.InstAlloca, Raw: "  %0 = alloca i32"},
				{SSAName: "%1", Kind: ir.InstOther, Raw: "  %1 = load i32, ptr %0"},
			},
		},
		{
			Label: "body",
			Instructions: []*ir.Instruction{
				{SSAName: "%2", Kind: ir.InstOther, Raw: "  %2 = add i32 %1, 1"},
				{SSAName: "%3", Kind: ir.InstCall, Raw: "  %3 = call i32 @foo(i32 %2)"},
				{SSAName: "", Kind: ir.InstOther, Raw: "  store i32 %3, ptr %0"},
			},
		},
	}
	tests := []struct {
		name      string
		ssaName   string
		blockIdx  int
		instIdx   int
		wantFound bool
		wantBlock int
		wantInst  int
	}{
		{
			name:      "found in same block",
			ssaName:   "%2",
			blockIdx:  1,
			instIdx:   2,
			wantFound: true,
			wantBlock: 1,
			wantInst:  0,
		},
		{
			name:      "found in previous block",
			ssaName:   "%1",
			blockIdx:  1,
			instIdx:   1,
			wantFound: true,
			wantBlock: 0,
			wantInst:  1,
		},
		{
			name:      "not found",
			ssaName:   "%99",
			blockIdx:  1,
			instIdx:   2,
			wantFound: false,
			wantBlock: -1,
			wantInst:  -1,
		},
		{
			name:      "window limit",
			ssaName:   "%0",
			blockIdx:  1,
			instIdx:   2,
			wantFound: true,
			wantBlock: 0,
			wantInst:  0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst, pos := findSSADefInBlocks(blocks, tt.ssaName, tt.blockIdx, tt.instIdx)
			if tt.wantFound {
				if inst == nil {
					t.Fatalf("findSSADefInBlocks(_, %q, %d, %d) returned nil, want non-nil",
						tt.ssaName, tt.blockIdx, tt.instIdx)
				}
				if pos.block != tt.wantBlock || pos.inst != tt.wantInst {
					t.Errorf("findSSADefInBlocks(_, %q, %d, %d) pos = {%d, %d}, want {%d, %d}",
						tt.ssaName, tt.blockIdx, tt.instIdx, pos.block, pos.inst, tt.wantBlock, tt.wantInst)
				}
			} else {
				if inst != nil {
					t.Errorf("findSSADefInBlocks(_, %q, %d, %d) = non-nil, want nil",
						tt.ssaName, tt.blockIdx, tt.instIdx)
				}
				if pos.block != -1 || pos.inst != -1 {
					t.Errorf("findSSADefInBlocks(_, %q, %d, %d) pos = {%d, %d}, want {-1, -1}",
						tt.ssaName, tt.blockIdx, tt.instIdx, pos.block, pos.inst)
				}
			}
		})
	}
}

func TestRenameInFunction(t *testing.T) {
	tests := []struct {
		name     string
		fn       *ir.Function
		old      string
		new      string
		wantRaw  string
		wantInst string // expected Raw of first instruction in first block
	}{
		{
			name: "rename in define line",
			fn: &ir.Function{
				Raw:    "define i32 @old_func(ptr %ctx) {",
				Blocks: []*ir.BasicBlock{{Label: "entry", Instructions: []*ir.Instruction{}}},
			},
			old:     "@old_func",
			new:     "@new_func",
			wantRaw: "define i32 @new_func(ptr %ctx) {",
		},
		{
			name: "rename in instruction Raw",
			fn: &ir.Function{
				Raw: "define void @caller() {",
				Blocks: []*ir.BasicBlock{
					{
						Label: "entry",
						Instructions: []*ir.Instruction{
							{Kind: ir.InstOther, Raw: "  call void @old_func()"},
						},
					},
				},
			},
			old:      "@old_func",
			new:      "@new_func",
			wantRaw:  "define void @caller() {",
			wantInst: "  call void @new_func()",
		},
		{
			name: "rename in modified instruction AST fields",
			fn: &ir.Function{
				Raw: "define void @caller() {",
				Blocks: []*ir.BasicBlock{
					{
						Label: "entry",
						Instructions: []*ir.Instruction{
							{
								Kind:     ir.InstCall,
								Modified: true,
								Raw:      "  call void @old_func(ptr @old_func)",
								Call: &ir.CallInst{
									RetType: "void",
									Callee:  "@old_func",
									Args:    "ptr @old_func",
								},
							},
						},
					},
				},
			},
			old:      "@old_func",
			new:      "@new_func",
			wantRaw:  "define void @caller() {",
			wantInst: "  call void @new_func(ptr @new_func)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			renameInFunction(tt.fn, tt.old, tt.new)
			if tt.fn.Raw != tt.wantRaw {
				t.Errorf("fn.Raw = %q, want %q", tt.fn.Raw, tt.wantRaw)
			}
			if tt.wantInst != "" {
				inst := tt.fn.Blocks[0].Instructions[0]
				if inst.Raw != tt.wantInst {
					t.Errorf("inst.Raw = %q, want %q", inst.Raw, tt.wantInst)
				}
			}
			// Check AST fields were updated for modified instructions
			if tt.name == "rename in modified instruction AST fields" {
				call := tt.fn.Blocks[0].Instructions[0].Call
				if call.Callee != "@new_func" {
					t.Errorf("Call.Callee = %q, want %q", call.Callee, "@new_func")
				}
				if call.Args != "ptr @new_func" {
					t.Errorf("Call.Args = %q, want %q", call.Args, "ptr @new_func")
				}
			}
		})
	}
}

func TestRenameInInstruction(t *testing.T) {
	tests := []struct {
		name     string
		inst     *ir.Instruction
		old      string
		new      string
		wantRaw  string
		checkAST func(t *testing.T, inst *ir.Instruction)
	}{
		{
			name:    "unmodified instruction updates Raw",
			inst:    &ir.Instruction{Kind: ir.InstOther, Raw: "  call void @old_fn()"},
			old:     "@old_fn",
			new:     "@new_fn",
			wantRaw: "  call void @new_fn()",
		},
		{
			name: "modified InstCall updates Callee and Args",
			inst: &ir.Instruction{
				Kind:     ir.InstCall,
				Modified: true,
				Raw:      "  call void @old_fn(ptr @old_fn)",
				Call: &ir.CallInst{
					RetType: "void",
					Callee:  "@old_fn",
					Args:    "ptr @old_fn",
				},
			},
			old:     "@old_fn",
			new:     "@new_fn",
			wantRaw: "  call void @new_fn(ptr @new_fn)",
			checkAST: func(t *testing.T, inst *ir.Instruction) {
				t.Helper()
				if inst.Call.Callee != "@new_fn" {
					t.Errorf("Call.Callee = %q, want %q", inst.Call.Callee, "@new_fn")
				}
				if inst.Call.Args != "ptr @new_fn" {
					t.Errorf("Call.Args = %q, want %q", inst.Call.Args, "ptr @new_fn")
				}
			},
		},
		{
			name: "modified InstGEP updates Base",
			inst: &ir.Instruction{
				Kind:     ir.InstGEP,
				Modified: true,
				Raw:      "  %1 = getelementptr inbounds i8, ptr @old_global, i32 0",
				GEP: &ir.GEPInst{
					Inbounds: true,
					BaseType: "i8",
					PtrType:  "ptr",
					Base:     "@old_global",
					Indices:  []string{"i32 0"},
				},
			},
			old:     "@old_global",
			new:     "@new_global",
			wantRaw: "  %1 = getelementptr inbounds i8, ptr @new_global, i32 0",
			checkAST: func(t *testing.T, inst *ir.Instruction) {
				t.Helper()
				if inst.GEP.Base != "@new_global" {
					t.Errorf("GEP.Base = %q, want %q", inst.GEP.Base, "@new_global")
				}
			},
		},
		{
			name:    "instruction without match no change",
			inst:    &ir.Instruction{Kind: ir.InstOther, Raw: "  ret void"},
			old:     "@nonexistent",
			new:     "@replacement",
			wantRaw: "  ret void",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			renameInInstruction(tt.inst, tt.old, tt.new)
			if tt.inst.Raw != tt.wantRaw {
				t.Errorf("inst.Raw = %q, want %q", tt.inst.Raw, tt.wantRaw)
			}
			if tt.checkAST != nil {
				tt.checkAST(t, tt.inst)
			}
		})
	}
}

func TestExtractQuotedName(t *testing.T) {
	tests := []struct {
		input    string
		wantName string
		wantOK   bool
	}{
		{`name: "task_struct"`, "task_struct", true},
		{`!5 = !DIDerivedType(tag: DW_TAG_member, name: "Pid", size: 32)`, "Pid", true},
		{`no name field here`, "", false},
		{`name: "`, "", false},
	}
	for _, tt := range tests {
		name, _, _, ok := extractQuotedName(tt.input)
		if ok != tt.wantOK || name != tt.wantName {
			t.Errorf("extractQuotedName(%q) = (%q, ok=%v), want (%q, ok=%v)",
				tt.input, name, ok, tt.wantName, tt.wantOK)
		}
	}
}
