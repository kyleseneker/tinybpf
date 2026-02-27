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
			got, err := rewriteCoreAccess(input)
			if err != nil {
				t.Fatal(err)
			}
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
			got, err := findCoreTypes(tt.lines)
			if err != nil {
				t.Fatal(err)
			}
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

func TestSanitizeCoreFieldNames(t *testing.T) {
	tests := []struct {
		name        string
		lines       []string
		wantContain []string
		notContain  []string
	}{
		{
			name: "renames struct type and field names",
			lines: []string{
				`!0 = !DICompositeType(tag: DW_TAG_structure_type, name: "main_bpfCoreTaskStruct", size: 64, elements: !{!1, !2})`,
				`!1 = !DIDerivedType(tag: DW_TAG_member, name: "Pid", baseType: !3, size: 32, offset: 0)`,
				`!2 = !DIDerivedType(tag: DW_TAG_member, name: "Tgid", baseType: !3, size: 32, offset: 32)`,
				`!3 = !DIBasicType(name: "int32", size: 32)`,
			},
			wantContain: []string{
				`name: "task_struct"`,
				`name: "pid"`,
				`name: "tgid"`,
			},
			notContain: []string{
				`name: "Pid"`,
				`name: "Tgid"`,
				`name: "main_bpfCoreTaskStruct"`,
			},
		},
		{
			name: "multi-word field names become snake_case",
			lines: []string{
				`!0 = !DICompositeType(tag: DW_TAG_structure_type, name: "main_bpfCoreCredStruct", size: 64, elements: !{!1})`,
				`!1 = !DIDerivedType(tag: DW_TAG_member, name: "LoginUid", baseType: !2, size: 32, offset: 0)`,
				`!2 = !DIBasicType(name: "int32", size: 32)`,
			},
			wantContain: []string{
				`name: "cred_struct"`,
				`name: "login_uid"`,
			},
		},
		{
			name: "non-core metadata unchanged",
			lines: []string{
				`!0 = !DICompositeType(tag: DW_TAG_structure_type, name: "main_bpfMapDef", size: 160, elements: !{!1})`,
				`!1 = !DIDerivedType(tag: DW_TAG_member, name: "Type", baseType: !2, size: 32, offset: 0)`,
				`!2 = !DIBasicType(name: "int32", size: 32)`,
			},
			wantContain: []string{
				`name: "Type"`,
				`name: "main_bpfMapDef"`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sanitizeCoreFieldNames(tt.lines)
			if err != nil {
				t.Fatal(err)
			}
			text := strings.Join(got, "\n")
			for _, want := range tt.wantContain {
				if !strings.Contains(text, want) {
					t.Errorf("output missing %q\n---\n%s", want, text)
				}
			}
			for _, bad := range tt.notContain {
				if strings.Contains(text, bad) {
					t.Errorf("output should not contain %q\n---\n%s", bad, text)
				}
			}
		})
	}
}

func TestRewriteCoreExistsChecks(t *testing.T) {
	tests := []struct {
		name        string
		lines       []string
		wantContain []string
		notContain  []string
	}{
		{
			name: "field_exists with byte GEP",
			lines: []string{
				"%main.bpfCoreTaskStruct = type { i32, i32 }",
				"declare i32 @main.bpfCoreFieldExists(ptr, ptr)",
				"define void @main.prog(ptr %ctx) {",
				"  %core = alloca %main.bpfCoreTaskStruct, align 4",
				"  %1 = getelementptr inbounds i8, ptr %core, i64 4",
				"  %2 = call i32 @main.bpfCoreFieldExists(ptr nonnull %1, ptr undef)",
				"}",
			},
			wantContain: []string{
				"call ptr @llvm.preserve.struct.access.index.p0.p0(ptr %core, i32 1, i32 1)",
				"@llvm.bpf.preserve.field.info.p0(ptr nonnull %1, i64 2)",
				"declare i32 @llvm.bpf.preserve.field.info.p0(ptr, i64 immarg)",
				"declare ptr @llvm.preserve.struct.access.index.p0.p0(ptr, i32 immarg, i32 immarg)",
			},
			notContain: []string{
				"@main.bpfCoreFieldExists",
				"getelementptr inbounds i8",
			},
		},
		{
			name: "field_exists with nuw byte GEP",
			lines: []string{
				"%main.bpfCoreTaskStruct = type { i32, i32 }",
				"declare i32 @main.bpfCoreFieldExists(ptr, ptr)",
				"define void @main.prog(ptr %ctx) {",
				"  %core = alloca %main.bpfCoreTaskStruct, align 4",
				"  %1 = getelementptr inbounds nuw i8, ptr %core, i64 4, !dbg !10",
				"  %2 = call i32 @main.bpfCoreFieldExists(ptr nonnull %1, ptr undef)",
				"}",
			},
			wantContain: []string{
				"call ptr @llvm.preserve.struct.access.index.p0.p0(ptr %core, i32 1, i32 1)",
				"!dbg !10",
				"i64 2)",
			},
			notContain: []string{
				"getelementptr inbounds nuw i8",
			},
		},
		{
			name: "field_exists at offset 0 (direct alloca)",
			lines: []string{
				"%main.bpfCoreTaskStruct = type { i32, i32 }",
				"declare i32 @main.bpfCoreFieldExists(ptr, ptr)",
				"define void @main.prog(ptr %ctx) {",
				"  %core = alloca %main.bpfCoreTaskStruct, align 4",
				"  %1 = call i32 @main.bpfCoreFieldExists(ptr %core, ptr undef)",
				"}",
			},
			wantContain: []string{
				"preserve.struct.access.index.p0.p0(ptr %core, i32 0, i32 0)",
				"@llvm.bpf.preserve.field.info.p0(",
				"i64 2)",
			},
			notContain: []string{
				"@main.bpfCoreFieldExists",
			},
		},
		{
			name: "field_exists with metadata annotation",
			lines: []string{
				"%main.bpfCoreTaskStruct = type { i32, i32, [16 x i8] }", //nolint:dupword
				"declare i32 @main.bpfCoreFieldExists(ptr, ptr)",
				"define void @main.prog(ptr %ctx) {",
				"  %core = alloca %main.bpfCoreTaskStruct, align 4",
				"  %1 = getelementptr inbounds i8, ptr %core, i64 8",
				"  %2 = call i32 @main.bpfCoreFieldExists(ptr %1, ptr undef)",
				"}",
				`!0 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfCoreTaskStruct", size: 192, elements: !{!1, !2, !3})`,
			},
			wantContain: []string{
				"call ptr @llvm.preserve.struct.access.index.p0.p0(ptr %core, i32 2, i32 2)",
				"!llvm.preserve.access.index !0",
			},
		},
		{
			name: "field_exists with byte-array alloca (replaceAlloc output)",
			lines: []string{
				"%main.bpfCoreTaskStruct = type { i32, i32 }",
				"declare i32 @main.bpfCoreFieldExists(ptr, ptr)",
				"define void @main.prog(ptr %ctx) {",
				"  %core = alloca [8 x i8], align 4",
				"  %1 = getelementptr inbounds nuw i8, ptr %core, i64 4",
				"  %2 = call i32 @main.bpfCoreFieldExists(ptr nonnull %1, ptr undef)",
				"}",
			},
			wantContain: []string{
				"call ptr @llvm.preserve.struct.access.index.p0.p0(ptr %core, i32 1, i32 1)",
				"@llvm.bpf.preserve.field.info.p0(ptr nonnull %1, i64 2)",
			},
			notContain: []string{
				"@main.bpfCoreFieldExists",
				"getelementptr inbounds nuw i8",
			},
		},
		{
			name: "field_exists at offset 0 with byte-array alloca",
			lines: []string{
				"%main.bpfCoreTaskStruct = type { i32, i32 }",
				"declare i32 @main.bpfCoreFieldExists(ptr, ptr)",
				"define void @main.prog(ptr %ctx) {",
				"  %core = alloca [8 x i8], align 4",
				"  %1 = call i32 @main.bpfCoreFieldExists(ptr %core, ptr undef)",
				"}",
			},
			wantContain: []string{
				"preserve.struct.access.index.p0.p0(ptr %core, i32 0, i32 0)",
				"@llvm.bpf.preserve.field.info.p0(",
				"i64 2)",
			},
			notContain: []string{
				"@main.bpfCoreFieldExists",
			},
		},
		{
			name: "field_exists with metadata only (no type definition)",
			lines: []string{
				"declare i32 @main.bpfCoreFieldExists(ptr, ptr)",
				"define void @main.prog(ptr %ctx) {",
				"  %core = alloca [8 x i8], align 4",
				"  %1 = getelementptr inbounds nuw i8, ptr %core, i64 4",
				"  %2 = call i32 @main.bpfCoreFieldExists(ptr nonnull %1, ptr undef)",
				"}",
				`!0 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfCoreTaskStruct", size: 64, elements: !{!1, !2})`,
				`!1 = !DIDerivedType(tag: DW_TAG_member, name: "Pid", baseType: !3, size: 32)`,
				`!2 = !DIDerivedType(tag: DW_TAG_member, name: "Tgid", baseType: !3, size: 32, offset: 32)`,
				`!3 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)`,
			},
			wantContain: []string{
				"call ptr @llvm.preserve.struct.access.index.p0.p0(ptr %core, i32 1, i32 1)",
				"@llvm.bpf.preserve.field.info.p0(ptr nonnull %1, i64 2)",
				"!llvm.preserve.access.index !0",
			},
			notContain: []string{
				"@main.bpfCoreFieldExists",
				"getelementptr inbounds nuw i8",
			},
		},
		{
			name: "field_exists with indirect metadata elements",
			lines: []string{
				"declare i32 @main.bpfCoreFieldExists(ptr, ptr)",
				"define void @main.prog(ptr %ctx) {",
				"  %core = alloca [8 x i8], align 4",
				"  %1 = getelementptr inbounds nuw i8, ptr %core, i64 4",
				"  %2 = call i32 @main.bpfCoreFieldExists(ptr nonnull %1, ptr undef)",
				"}",
				`!0 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfCoreTaskStruct", size: 64, elements: !5)`,
				`!1 = !DIDerivedType(tag: DW_TAG_member, name: "Pid", baseType: !3, size: 32)`,
				`!2 = !DIDerivedType(tag: DW_TAG_member, name: "Tgid", baseType: !3, size: 32, offset: 32)`,
				`!3 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)`,
				`!5 = !{!1, !2}`,
			},
			wantContain: []string{
				"call ptr @llvm.preserve.struct.access.index.p0.p0(ptr %core, i32 1, i32 1)",
				"@llvm.bpf.preserve.field.info.p0(ptr nonnull %1, i64 2)",
				"!llvm.preserve.access.index !0",
			},
			notContain: []string{
				"@main.bpfCoreFieldExists",
				"getelementptr inbounds nuw i8",
			},
		},
		{
			name: "type_exists rewrite",
			lines: []string{
				"declare i32 @main.bpfCoreTypeExists(ptr, ptr)",
				"define void @main.prog(ptr %ctx) {",
				"  %1 = call i32 @main.bpfCoreTypeExists(ptr %type, ptr undef)",
				"}",
			},
			wantContain: []string{
				"@llvm.bpf.preserve.type.info.p0(ptr %type, i64 0)",
				"declare i32 @llvm.bpf.preserve.type.info.p0(ptr, i64 immarg)",
			},
			notContain: []string{
				"@main.bpfCoreTypeExists",
			},
		},
		{
			name: "both field and type exists",
			lines: []string{
				"%main.bpfCoreTaskStruct = type { i32, i32 }",
				"declare i32 @main.bpfCoreFieldExists(ptr, ptr)",
				"declare i32 @main.bpfCoreTypeExists(ptr, ptr)",
				"define void @main.prog(ptr %ctx) {",
				"  %core = alloca %main.bpfCoreTaskStruct, align 4",
				"  %1 = getelementptr inbounds i8, ptr %core, i64 4",
				"  %2 = call i32 @main.bpfCoreFieldExists(ptr %1, ptr undef)",
				"  %3 = call i32 @main.bpfCoreTypeExists(ptr %type, ptr undef)",
				"}",
			},
			wantContain: []string{
				"@llvm.bpf.preserve.field.info.p0",
				"@llvm.bpf.preserve.type.info.p0",
			},
			notContain: []string{
				"@main.bpfCoreFieldExists",
				"@main.bpfCoreTypeExists",
			},
		},
		{
			name: "no exists calls unchanged",
			lines: []string{
				"define void @main.prog(ptr %ctx) {",
				"  ret void",
				"}",
			},
			wantContain: []string{
				"define void @main.prog",
			},
			notContain: []string{
				"llvm.bpf.preserve",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := rewriteCoreExistsChecks(tt.lines)
			if err != nil {
				t.Fatal(err)
			}
			text := strings.Join(got, "\n")
			for _, want := range tt.wantContain {
				if !strings.Contains(text, want) {
					t.Errorf("output missing %q\n---\n%s", want, text)
				}
			}
			for _, bad := range tt.notContain {
				if strings.Contains(text, bad) {
					t.Errorf("output should not contain %q\n---\n%s", bad, text)
				}
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
