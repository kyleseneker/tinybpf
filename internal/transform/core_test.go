package transform

import (
	"strings"
	"testing"
)

func FuzzRewriteCoreAccess(f *testing.F) {
	f.Add(`%main.bpfCoreTaskStruct = type { i32, i32 }
  %1 = getelementptr inbounds %main.bpfCoreTaskStruct, ptr %task, i32 0, i32 0`)
	f.Add(`no core types here`)
	f.Add(`%main.bpfMapDef = type { i32 }
  %1 = getelementptr %main.bpfMapDef, ptr %0, i32 0, i32 0`)

	f.Fuzz(func(t *testing.T, ir string) {
		if len(ir) > 1<<16 {
			return
		}
		lines := strings.Split(ir, "\n")
		rewriteCoreAccess(lines)
	})
}

//nolint:dupword
var coreIRBasic = `
%main.bpfCoreTaskStruct = type { i32, i32, [16 x i8] }

define i32 @tracepoint_handler(ptr %ctx) {
entry:
  %task = call ptr inttoptr (i64 35 to ptr)()
  %pid_ptr = getelementptr inbounds %main.bpfCoreTaskStruct, ptr %task, i32 0, i32 0
  %pid = load i32, ptr %pid_ptr
  ret i32 %pid
}

!0 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfCoreTaskStruct", size: 192, elements: !{!1, !2, !3})
!1 = !DIDerivedType(tag: DW_TAG_member, name: "Pid", baseType: !4, size: 32, offset: 0)
!2 = !DIDerivedType(tag: DW_TAG_member, name: "Tgid", baseType: !4, size: 32, offset: 32)
!3 = !DIDerivedType(tag: DW_TAG_member, name: "Comm", baseType: !5, size: 128, offset: 64)
!4 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!5 = !DICompositeType(tag: DW_TAG_array_type, baseType: !6, elements: !{!7})
!6 = !DIBasicType(name: "byte", size: 8, encoding: DW_ATE_unsigned)
!7 = !DISubrange(count: 16)
`

//nolint:dupword
var coreIRMultipleFields = `
%main.bpfCoreTaskStruct = type { i32, i32, [16 x i8] }

define i32 @handler(ptr %ctx) {
entry:
  %task = call ptr inttoptr (i64 35 to ptr)()
  %pid_ptr = getelementptr inbounds %main.bpfCoreTaskStruct, ptr %task, i32 0, i32 0
  %tgid_ptr = getelementptr inbounds %main.bpfCoreTaskStruct, ptr %task, i32 0, i32 1
  %comm_ptr = getelementptr inbounds %main.bpfCoreTaskStruct, ptr %task, i32 0, i32 2
  ret i32 0
}

!0 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfCoreTaskStruct", size: 192, elements: !{!1, !2})
!1 = !DIDerivedType(tag: DW_TAG_member, name: "Pid", baseType: !3, size: 32, offset: 0)
!2 = !DIDerivedType(tag: DW_TAG_member, name: "Tgid", baseType: !3, size: 32, offset: 32)
!3 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
`

//nolint:dupword
var coreIRNoAnnotation = `
%main.bpfMapDef = type { i32, i32, i32, i32, i32 }

define i32 @handler(ptr %ctx) {
entry:
  %ptr = getelementptr inbounds %main.bpfMapDef, ptr %map, i32 0, i32 0
  ret i32 0
}
`

var coreIRWithDBG = `
%main.bpfCoreTaskStruct = type { i32, i32 }

define i32 @handler(ptr %ctx) {
entry:
  %task = call ptr inttoptr (i64 35 to ptr)()
  %pid_ptr = getelementptr inbounds %main.bpfCoreTaskStruct, ptr %task, i32 0, i32 0, !dbg !10
  ret i32 0
}

!0 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfCoreTaskStruct", size: 64, elements: !{!1})
!1 = !DIDerivedType(tag: DW_TAG_member, name: "Pid", baseType: !2, size: 32, offset: 0)
!2 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)
!10 = !DILocation(line: 42, column: 5, scope: !11)
!11 = distinct !DISubprogram(name: "handler")
`

var coreIRWithoutMeta = `
%main.bpfCoreFileStruct = type { i64 }

define i64 @handler(ptr %ctx) {
entry:
  %file = call ptr inttoptr (i64 35 to ptr)()
  %ino_ptr = getelementptr %main.bpfCoreFileStruct, ptr %file, i32 0, i32 0
  ret i64 0
}
`

func TestRewriteCoreAccess(t *testing.T) {
	tests := []struct {
		name        string
		ir          string
		wantContain []string
		notContain  []string
		check       func(t *testing.T, text string)
	}{
		{
			name: "GEP replaced with preserve_access_index",
			ir:   coreIRBasic,
			wantContain: []string{
				"call ptr @llvm.preserve.struct.access.index.p0.p0(ptr %task, i32 0, i32 0)",
				"!llvm.preserve.access.index !0",
				coreIntrinsicDecl,
			},
			notContain: []string{
				"getelementptr inbounds %main.bpfCoreTaskStruct",
			},
		},
		{
			name: "multiple field accesses rewritten",
			ir:   coreIRMultipleFields,
			wantContain: []string{
				"call ptr @llvm.preserve.struct.access.index.p0.p0(ptr %task, i32 0, i32 0)",
				"call ptr @llvm.preserve.struct.access.index.p0.p0(ptr %task, i32 1, i32 1)",
				"call ptr @llvm.preserve.struct.access.index.p0.p0(ptr %task, i32 2, i32 2)",
			},
			check: func(t *testing.T, text string) {
				t.Helper()
				count := strings.Count(text, "llvm.preserve.struct.access.index")
				if count < 4 {
					t.Errorf("expected at least 4 occurrences (3 calls + 1 decl), got %d", count)
				}
			},
		},
		{
			name:       "non-core GEPs unchanged",
			ir:         coreIRNoAnnotation,
			notContain: []string{"llvm.preserve"},
			wantContain: []string{
				"getelementptr inbounds %main.bpfMapDef",
			},
		},
		{
			name: "dbg metadata preserved",
			ir:   coreIRWithDBG,
			wantContain: []string{
				"!dbg !10",
				"!llvm.preserve.access.index !0",
			},
		},
		{
			name: "works without DICompositeType metadata",
			ir:   coreIRWithoutMeta,
			wantContain: []string{
				"call ptr @llvm.preserve.struct.access.index.p0.p0(ptr %file, i32 0, i32 0)",
				coreIntrinsicDecl,
			},
			notContain: []string{
				"!llvm.preserve.access.index",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := strings.Split(strings.TrimSpace(tt.ir), "\n")
			got := rewriteCoreAccess(input)
			text := strings.Join(got, "\n")
			for _, want := range tt.wantContain {
				if !strings.Contains(text, want) {
					t.Errorf("output missing %q\n---\n%s", want, text)
				}
			}
			for _, bad := range tt.notContain {
				if strings.Contains(text, bad) {
					t.Errorf("output should not contain %q", bad)
				}
			}
			if tt.check != nil {
				tt.check(t, text)
			}
		})
	}
}

//nolint:dupword
func TestFindCoreTypes(t *testing.T) {
	tests := []struct {
		name     string
		lines    []string
		wantKeys []string
	}{
		{
			name:     "detects bpfCore type",
			lines:    []string{"%main.bpfCoreTaskStruct = type { i32, i32 }"},
			wantKeys: []string{"%main.bpfCoreTaskStruct"},
		},
		{
			name:     "ignores non-core type",
			lines:    []string{"%main.bpfMapDef = type { i32, i32, i32, i32, i32 }"},
			wantKeys: nil,
		},
		{
			name: "multiple core types",
			lines: []string{
				"%main.bpfCoreTaskStruct = type { i32, i32 }",
				"%main.bpfCoreFileStruct = type { i64 }",
			},
			wantKeys: []string{"%main.bpfCoreTaskStruct", "%main.bpfCoreFileStruct"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findCoreTypes(tt.lines)
			if len(tt.wantKeys) == 0 && len(got) == 0 {
				return
			}
			for _, k := range tt.wantKeys {
				if !got[k] {
					t.Errorf("missing type %q", k)
				}
			}
			if len(got) != len(tt.wantKeys) {
				t.Errorf("expected %d types, got %d", len(tt.wantKeys), len(got))
			}
		})
	}
}

func TestExtractDBG(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{", !dbg !10", "!dbg !10"},
		{", !dbg !42, !other !5", "!dbg !42"},
		{"no dbg here", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := extractDBG(tt.in); got != tt.want {
			t.Errorf("extractDBG(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
