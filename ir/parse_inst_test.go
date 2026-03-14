package ir

import (
	"testing"
)

func TestParseInstruction(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		trimmed  string
		wantKind InstKind
		wantSSA  string
		wantCall bool
		wantGEP  bool
		wantAlc  bool
	}{
		{
			name:     "call with SSA assignment",
			line:     "  %0 = call i64 @main.bpfGetCurrentPidTgid(ptr undef)",
			trimmed:  "%0 = call i64 @main.bpfGetCurrentPidTgid(ptr undef)",
			wantKind: InstCall,
			wantSSA:  "%0",
			wantCall: true,
		},
		{
			name:     "call without SSA assignment",
			line:     "  call void @llvm.memset.p0.i64(ptr null, i8 0, i64 16, i1 false)",
			trimmed:  "call void @llvm.memset.p0.i64(ptr null, i8 0, i64 16, i1 false)",
			wantKind: InstCall,
			wantSSA:  "",
			wantCall: true,
		},
		{
			name:     "getelementptr with SSA",
			line:     "  %1 = getelementptr inbounds i8, ptr %core, i64 4",
			trimmed:  "%1 = getelementptr inbounds i8, ptr %core, i64 4",
			wantKind: InstGEP,
			wantSSA:  "%1",
			wantGEP:  true,
		},
		{
			name:     "alloca with SSA",
			line:     "  %core = alloca %main.bpfCoreTaskStruct, align 4",
			trimmed:  "%core = alloca %main.bpfCoreTaskStruct, align 4",
			wantKind: InstAlloca,
			wantSSA:  "%core",
			wantAlc:  true,
		},
		{
			name:     "other instruction - ret",
			line:     "  ret i32 0",
			trimmed:  "ret i32 0",
			wantKind: InstOther,
			wantSSA:  "",
		},
		{
			name:     "other instruction - store",
			line:     "  store i32 42, ptr %x",
			trimmed:  "store i32 42, ptr %x",
			wantKind: InstOther,
			wantSSA:  "",
		},
		{
			name:     "other instruction with SSA - load",
			line:     "  %val = load i32, ptr %pid_ptr",
			trimmed:  "%val = load i32, ptr %pid_ptr",
			wantKind: InstOther,
			wantSSA:  "%val",
		},
		{
			name:     "empty trimmed falls through to other",
			line:     "",
			trimmed:  "",
			wantKind: InstOther,
			wantSSA:  "",
		},
		{
			name:     "call via inttoptr",
			line:     "  %task = call ptr inttoptr (i64 35 to ptr)()",
			trimmed:  "%task = call ptr inttoptr (i64 35 to ptr)()",
			wantKind: InstCall,
			wantSSA:  "%task",
			wantCall: true,
		},
		{
			name:     "GEP without SSA name uses work=trimmed",
			line:     "  getelementptr inbounds i8, ptr %p, i64 0",
			trimmed:  "getelementptr inbounds i8, ptr %p, i64 0",
			wantKind: InstGEP,
			wantGEP:  true,
		},
		{
			name:     "alloca without SSA falls through to work=trimmed",
			line:     "  alloca i32, align 4",
			trimmed:  "alloca i32, align 4",
			wantKind: InstAlloca,
			wantAlc:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst := parseInstruction(tt.line, tt.trimmed)
			if inst.Kind != tt.wantKind {
				t.Errorf("Kind = %d, want %d", inst.Kind, tt.wantKind)
			}
			if inst.SSAName != tt.wantSSA {
				t.Errorf("SSAName = %q, want %q", inst.SSAName, tt.wantSSA)
			}
			if (inst.Call != nil) != tt.wantCall {
				t.Errorf("Call non-nil = %v, want %v", inst.Call != nil, tt.wantCall)
			}
			if (inst.GEP != nil) != tt.wantGEP {
				t.Errorf("GEP non-nil = %v, want %v", inst.GEP != nil, tt.wantGEP)
			}
			if (inst.Alloca != nil) != tt.wantAlc {
				t.Errorf("Alloca non-nil = %v, want %v", inst.Alloca != nil, tt.wantAlc)
			}
			if inst.Raw != tt.line {
				t.Errorf("Raw = %q, want %q", inst.Raw, tt.line)
			}
		})
	}
}

func TestExtractSSAAssign(t *testing.T) {
	tests := []struct {
		name      string
		trimmed   string
		wantName  string
		wantAfter string
	}{
		{
			name:      "numeric SSA name",
			trimmed:   "%0 = call i64 @foo()",
			wantName:  "%0",
			wantAfter: "call i64 @foo()",
		},
		{
			name:      "alpha SSA name",
			trimmed:   "%foo = load i32, ptr %x",
			wantName:  "%foo",
			wantAfter: "load i32, ptr %x",
		},
		{
			name:      "dotted SSA name",
			trimmed:   "%my.var = add i32 1, 2",
			wantName:  "%my.var",
			wantAfter: "add i32 1, 2",
		},
		{
			name:      "underscore SSA name",
			trimmed:   "%my_val = add i32 1, 2",
			wantName:  "%my_val",
			wantAfter: "add i32 1, 2",
		},
		{
			name:      "no percent sign",
			trimmed:   "ret i32 0",
			wantName:  "",
			wantAfter: "",
		},
		{
			name:      "no equals sign",
			trimmed:   "%foo bar baz",
			wantName:  "",
			wantAfter: "",
		},
		{
			name:      "leading spaces returns empty",
			trimmed:   "  %x = add i32 1, 2",
			wantName:  "",
			wantAfter: "",
		},
		{
			name:      "empty string",
			trimmed:   "",
			wantName:  "",
			wantAfter: "",
		},
		{
			name:      "single character",
			trimmed:   "%",
			wantName:  "",
			wantAfter: "",
		},
		{
			name:      "invalid character in name",
			trimmed:   "%foo! = add i32 1, 2",
			wantName:  "",
			wantAfter: "",
		},
		{
			name:      "leading spaces without percent",
			trimmed:   "  ret void",
			wantName:  "",
			wantAfter: "",
		},
		{
			name:      "single leading space no recursion",
			trimmed:   " %x = add i32 1, 2",
			wantName:  "",
			wantAfter: "",
		},
		{
			name:      "mixed case SSA name",
			trimmed:   "%AbCd = add i32 1, 2",
			wantName:  "%AbCd",
			wantAfter: "add i32 1, 2",
		},
		{
			name:      "percent with equals but name has hyphen",
			trimmed:   "%foo-bar = add i32 1, 2",
			wantName:  "",
			wantAfter: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, after := extractSSAAssign(tt.trimmed)
			if name != tt.wantName {
				t.Errorf("name = %q, want %q", name, tt.wantName)
			}
			if after != tt.wantAfter {
				t.Errorf("after = %q, want %q", after, tt.wantAfter)
			}
		})
	}
}

func TestIsValidSSAName(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{name: "valid numeric", s: "%0", want: true},
		{name: "valid alpha", s: "%foo", want: true},
		{name: "valid dotted", s: "%my.var", want: true},
		{name: "valid underscore", s: "%my_val", want: true},
		{name: "too short", s: "%", want: false},
		{name: "empty", s: "", want: false},
		{name: "no percent", s: "foo", want: false},
		{name: "invalid char", s: "%foo!", want: false},
		{name: "hyphen invalid", s: "%foo-bar", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidSSAName(tt.s); got != tt.want {
				t.Errorf("isValidSSAName(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestContainsCallKeyword(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{
			name: "call followed by space",
			s:    "call void @foo()",
			want: true,
		},
		{
			name: "tail call",
			s:    "tail call i64 @bar()",
			want: true,
		},
		{
			name: "no call keyword",
			s:    "ret i32 0",
			want: false,
		},
		{
			name: "recall without space",
			s:    "recall",
			want: false,
		},
		{
			name: "call at start with leading whitespace",
			s:    "  call void @foo()",
			want: true,
		},
		{
			name: "empty string",
			s:    "",
			want: false,
		},
		{
			name: "only call no space after",
			s:    "call",
			want: false,
		},
		{
			name: "call with space in middle of string",
			s:    "musttail call fastcc void @f()",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsCallKeyword(tt.s)
			if got != tt.want {
				t.Errorf("containsCallKeyword(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestTryParseCall(t *testing.T) {
	tests := []struct {
		name       string
		work       string
		wantNil    bool
		wantCallee string
		wantRet    string
		wantArgs   string
		wantTail   string
	}{
		{
			name:       "simple @callee with args",
			work:       "call i64 @main.bpfGetCurrentPidTgid(ptr undef)",
			wantCallee: "@main.bpfGetCurrentPidTgid",
			wantRet:    "i64",
			wantArgs:   "ptr undef",
			wantTail:   "",
		},
		{
			name:       "tail call",
			work:       "tail call void @llvm.memset.p0.i64(ptr null, i8 0, i64 16, i1 false)",
			wantCallee: "@llvm.memset.p0.i64",
			wantRet:    "void",
			wantArgs:   "ptr null, i8 0, i64 16, i1 false",
			wantTail:   "tail",
		},
		{
			name:       "inttoptr callee",
			work:       "call ptr inttoptr (i64 35 to ptr)()",
			wantCallee: "inttoptr (i64 35 to ptr)",
			wantRet:    "ptr",
			wantArgs:   "",
			wantTail:   "",
		},
		{
			name:    "missing @ and inttoptr",
			work:    "call void undef()",
			wantNil: true,
		},
		{
			name:       "no open paren after callee",
			work:       "call i32 @no_paren",
			wantCallee: "@no_paren",
			wantRet:    "i32",
			wantArgs:   "",
			wantTail:   "",
		},
		{
			name:       "missing close paren",
			work:       "call i32 @foo(i32 42",
			wantCallee: "@foo",
			wantRet:    "i32",
			wantArgs:   "i32 42",
			wantTail:   "",
		},
		{
			name:    "no call keyword at all",
			work:    "ret i32 0",
			wantNil: true,
		},
		{
			name:    "inttoptr with missing close paren in callee",
			work:    "call ptr inttoptr (i64 99 to ptr",
			wantNil: true,
		},
		{
			name:       "callee with nested parens in args",
			work:       "call ptr @foo(ptr inttoptr (i64 10 to ptr))",
			wantCallee: "@foo",
			wantRet:    "ptr",
			wantArgs:   "ptr inttoptr (i64 10 to ptr)",
			wantTail:   "",
		},
		{
			name:       "empty args",
			work:       "call void @bar()",
			wantCallee: "@bar",
			wantRet:    "void",
			wantArgs:   "",
			wantTail:   "",
		},
		{
			name:       "inttoptr before @ sign",
			work:       "call ptr inttoptr (i64 1 to ptr)(i32 42)",
			wantCallee: "inttoptr (i64 1 to ptr)",
			wantRet:    "ptr",
			wantArgs:   "i32 42",
			wantTail:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ci := tryParseCall(tt.work)
			if tt.wantNil {
				if ci != nil {
					t.Fatalf("expected nil, got %+v", ci)
				}
				return
			}
			if ci == nil {
				t.Fatal("unexpected nil result")
			}
			if ci.Callee != tt.wantCallee {
				t.Errorf("Callee = %q, want %q", ci.Callee, tt.wantCallee)
			}
			if ci.RetType != tt.wantRet {
				t.Errorf("RetType = %q, want %q", ci.RetType, tt.wantRet)
			}
			if ci.Args != tt.wantArgs {
				t.Errorf("Args = %q, want %q", ci.Args, tt.wantArgs)
			}
			if ci.Tail != tt.wantTail {
				t.Errorf("Tail = %q, want %q", ci.Tail, tt.wantTail)
			}
		})
	}
}

func TestTryParseGEP(t *testing.T) {
	tests := []struct {
		name         string
		work         string
		wantNil      bool
		wantInbounds bool
		wantFlags    string
		wantBaseType string
		wantPtrType  string
		wantBase     string
		wantIndices  []string
	}{
		{
			name:         "inbounds with two indices",
			work:         "getelementptr inbounds %main.bpfCoreTaskStruct, ptr %task, i32 0, i32 0",
			wantInbounds: true,
			wantBaseType: "%main.bpfCoreTaskStruct",
			wantPtrType:  "ptr",
			wantBase:     "%task",
			wantIndices:  []string{"i32 0", "i32 0"},
		},
		{
			name:         "inbounds single index",
			work:         "getelementptr inbounds i8, ptr %core, i64 4",
			wantInbounds: true,
			wantBaseType: "i8",
			wantPtrType:  "ptr",
			wantBase:     "%core",
			wantIndices:  []string{"i64 4"},
		},
		{
			name:         "nuw flag",
			work:         "getelementptr inbounds nuw i8, ptr %p, i64 8",
			wantInbounds: true,
			wantFlags:    "nuw",
			wantBaseType: "i8",
			wantPtrType:  "ptr",
			wantBase:     "%p",
			wantIndices:  []string{"i64 8"},
		},
		{
			name:         "nuw nsw flags",
			work:         "getelementptr nuw nsw i8, ptr %p, i64 8",
			wantInbounds: false,
			wantFlags:    "nuw nsw",
			wantBaseType: "i8",
			wantPtrType:  "ptr",
			wantBase:     "%p",
			wantIndices:  []string{"i64 8"},
		},
		{
			name:    "too few parts returns nil",
			work:    "getelementptr i8, ptr %p",
			wantNil: true,
		},
		{
			name:    "no getelementptr keyword",
			work:    "load i32, ptr %x",
			wantNil: true,
		},
		{
			name:         "no inbounds, no flags",
			work:         "getelementptr i8, ptr %p, i64 0",
			wantInbounds: false,
			wantBaseType: "i8",
			wantPtrType:  "ptr",
			wantBase:     "%p",
			wantIndices:  []string{"i64 0"},
		},
		{
			name:         "three indices",
			work:         "getelementptr inbounds %struct.T, ptr %s, i32 0, i32 1, i32 2",
			wantInbounds: true,
			wantBaseType: "%struct.T",
			wantPtrType:  "ptr",
			wantBase:     "%s",
			wantIndices:  []string{"i32 0", "i32 1", "i32 2"},
		},
		{
			name:         "single ptr part in operand",
			work:         "getelementptr i8, %p, i64 0",
			wantInbounds: false,
			wantBaseType: "i8",
			wantPtrType:  "",
			wantBase:     "%p",
			wantIndices:  []string{"i64 0"},
		},
		{
			name:         "metadata stripped from index",
			work:         "getelementptr inbounds i8, ptr %x, i64 4 !dbg !42",
			wantInbounds: true,
			wantBaseType: "i8",
			wantPtrType:  "ptr",
			wantBase:     "%x",
			wantIndices:  []string{"i64 4"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gi := tryParseGEP(tt.work)
			if tt.wantNil {
				if gi != nil {
					t.Fatalf("expected nil, got %+v", gi)
				}
				return
			}
			if gi == nil {
				t.Fatal("unexpected nil result")
			}
			if gi.Inbounds != tt.wantInbounds {
				t.Errorf("Inbounds = %v, want %v", gi.Inbounds, tt.wantInbounds)
			}
			if gi.Flags != tt.wantFlags {
				t.Errorf("Flags = %q, want %q", gi.Flags, tt.wantFlags)
			}
			if gi.BaseType != tt.wantBaseType {
				t.Errorf("BaseType = %q, want %q", gi.BaseType, tt.wantBaseType)
			}
			if gi.PtrType != tt.wantPtrType {
				t.Errorf("PtrType = %q, want %q", gi.PtrType, tt.wantPtrType)
			}
			if gi.Base != tt.wantBase {
				t.Errorf("Base = %q, want %q", gi.Base, tt.wantBase)
			}
			if len(gi.Indices) != len(tt.wantIndices) {
				t.Fatalf("Indices len = %d, want %d: %v", len(gi.Indices), len(tt.wantIndices), gi.Indices)
			}
			for i := range tt.wantIndices {
				if gi.Indices[i] != tt.wantIndices[i] {
					t.Errorf("Indices[%d] = %q, want %q", i, gi.Indices[i], tt.wantIndices[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// tryParseAlloca
// ---------------------------------------------------------------------------

func TestTryParseAlloca(t *testing.T) {
	tests := []struct {
		name      string
		work      string
		wantNil   bool
		wantType  string
		wantAlign int
	}{
		{
			name:      "struct type with align",
			work:      "alloca %main.bpfCoreTaskStruct, align 4",
			wantType:  "%main.bpfCoreTaskStruct",
			wantAlign: 4,
		},
		{
			name:      "simple type without align",
			work:      "alloca i32",
			wantType:  "i32",
			wantAlign: 0,
		},
		{
			name:      "array type",
			work:      "alloca [16 x i8], align 1",
			wantType:  "[16 x i8]",
			wantAlign: 1,
		},
		{
			name:      "metadata-only suffix",
			work:      "alloca i64 !dbg !42",
			wantType:  "i64",
			wantAlign: 0,
		},
		{
			name:    "no alloca keyword",
			work:    "load i32, ptr %x",
			wantNil: true,
		},
		{
			name:      "align 8",
			work:      "alloca i8, align 8",
			wantType:  "i8",
			wantAlign: 8,
		},
		{
			name:      "array type with nested bracket",
			work:      "alloca [4 x [2 x i32]], align 4",
			wantType:  "[4 x [2 x i32]]",
			wantAlign: 4,
		},
		{
			name:    "no alloca space (alloca suffix mismatch)",
			work:    "allocate something",
			wantNil: true,
		},
		{
			name:      "comma but no align keyword",
			work:      "alloca i32, !dbg !5",
			wantType:  "i32",
			wantAlign: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ai := tryParseAlloca(tt.work)
			if tt.wantNil {
				if ai != nil {
					t.Fatalf("expected nil, got %+v", ai)
				}
				return
			}
			if ai == nil {
				t.Fatal("unexpected nil result")
			}
			if ai.Type != tt.wantType {
				t.Errorf("Type = %q, want %q", ai.Type, tt.wantType)
			}
			if ai.Align != tt.wantAlign {
				t.Errorf("Align = %d, want %d", ai.Align, tt.wantAlign)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseAlignFromRest
// ---------------------------------------------------------------------------

func TestParseAlignFromRest(t *testing.T) {
	tests := []struct {
		name string
		rest string
		want int
	}{
		{
			name: "align 4",
			rest: " align 4",
			want: 4,
		},
		{
			name: "align 16 with trailing text",
			rest: " align 16, !dbg !5",
			want: 16,
		},
		{
			name: "no align keyword",
			rest: " !dbg !5",
			want: 0,
		},
		{
			name: "align with no digits after",
			rest: " align ",
			want: 0,
		},
		{
			name: "align with no digits followed by text",
			rest: " align abc",
			want: 0,
		},
		{
			name: "empty string",
			rest: "",
			want: 0,
		},
		{
			name: "align 1",
			rest: "align 1",
			want: 1,
		},
		{
			name: "multiple align takes first",
			rest: "align 8, align 4",
			want: 8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseAlignFromRest(tt.rest)
			if got != tt.want {
				t.Errorf("parseAlignFromRest(%q) = %d, want %d", tt.rest, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// splitGEPOperands
// ---------------------------------------------------------------------------

func TestSplitGEPOperands(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want []string
	}{
		{
			name: "simple three operands",
			s:    "i8, ptr %p, i64 0",
			want: []string{"i8", "ptr %p", "i64 0"},
		},
		{
			name: "nested brackets preserved",
			s:    "[4 x i32], ptr %arr, i64 0, i64 1",
			want: []string{"[4 x i32]", "ptr %arr", "i64 0", "i64 1"},
		},
		{
			name: "nested parens preserved",
			s:    "i8, ptr inttoptr (i64 0 to ptr), i64 0",
			want: []string{"i8", "ptr inttoptr (i64 0 to ptr)", "i64 0"},
		},
		{
			name: "single element no comma",
			s:    "i8",
			want: []string{"i8"},
		},
		{
			name: "empty trailing is dropped",
			s:    "i8, ptr %p, ",
			want: []string{"i8", "ptr %p"},
		},
		{
			name: "empty string",
			s:    "",
			want: nil,
		},
		{
			name: "deeply nested braces",
			s:    "{ [2 x { i32, i32 }] }, ptr %s, i32 0",
			want: []string{"{ [2 x { i32, i32 }] }", "ptr %s", "i32 0"},
		},
		{
			name: "two operands",
			s:    "i8, ptr %p",
			want: []string{"i8", "ptr %p"},
		},
		{
			name: "whitespace only",
			s:    "   ",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitGEPOperands(tt.s)
			if len(got) != len(tt.want) {
				t.Fatalf("len = %d, want %d: %v", len(got), len(tt.want), got)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
