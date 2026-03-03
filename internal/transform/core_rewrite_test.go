package transform

import (
	"strings"
	"testing"
)

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
				"call ptr @llvm.preserve.struct.access.index.p0.p0(ptr elementtype(%main.bpfCoreTaskStruct) %core, i32 1, i32 1)",
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
				"call ptr @llvm.preserve.struct.access.index.p0.p0(ptr elementtype(%main.bpfCoreTaskStruct) %core, i32 1, i32 1)",
				"!dbg !10",
				"i64 2)",
			},
			notContain: []string{
				"getelementptr inbounds nuw i8",
			},
		},
		{
			name: "field_exists with nuw nsw byte GEP and noundef pointer arg",
			lines: []string{
				"%main.bpfCoreTaskStruct = type { i32, i32 }",
				"declare i32 @main.bpfCoreFieldExists(ptr, ptr)",
				"define void @main.prog(ptr %ctx) {",
				"  %core = alloca %main.bpfCoreTaskStruct, align 4",
				"  %1 = getelementptr inbounds nuw nsw i8, ptr %core, i64 4, !dbg !10",
				"  %2 = call i32 @main.bpfCoreFieldExists(ptr noundef nonnull %1, ptr undef)",
				"}",
			},
			wantContain: []string{
				"call ptr @llvm.preserve.struct.access.index.p0.p0(ptr elementtype(%main.bpfCoreTaskStruct) %core, i32 1, i32 1)",
				"!dbg !10",
				"@llvm.bpf.preserve.field.info.p0(ptr noundef nonnull %1, i64 2)",
			},
			notContain: []string{
				"getelementptr inbounds nuw nsw i8",
				"@main.bpfCoreFieldExists",
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
				"preserve.struct.access.index.p0.p0(ptr elementtype(%main.bpfCoreTaskStruct) %core, i32 0, i32 0)",
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
				"call ptr @llvm.preserve.struct.access.index.p0.p0(ptr elementtype(%main.bpfCoreTaskStruct) %core, i32 2, i32 2)",
				"!llvm.preserve.access.index !0",
			},
		},
		{
			name: "field_exists resolves offsets from metadata when type definition missing",
			lines: []string{
				"declare i32 @main.bpfCoreFieldExists(ptr, ptr)",
				"define void @main.prog(ptr %ctx) {",
				"  %core = alloca [8 x i8], align 4",
				"  %1 = getelementptr inbounds i8, ptr %core, i64 4",
				"  %2 = call i32 @main.bpfCoreFieldExists(ptr %1, ptr undef)",
				"}",
				`!0 = !DICompositeType(tag: DW_TAG_structure_type, name: "main.bpfCoreTaskStruct", size: 64, elements: !{!1, !2})`,
				`!1 = !DIDerivedType(tag: DW_TAG_member, name: "Pid", baseType: !3, size: 32, offset: 0)`,
				`!2 = !DIDerivedType(tag: DW_TAG_member, name: "Tgid", baseType: !3, size: 32, offset: 32)`,
				`!3 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)`,
			},
			wantContain: []string{
				"call ptr @llvm.preserve.struct.access.index.p0.p0(ptr elementtype(%main.bpfCoreTaskStruct) %core, i32 1, i32 1)",
				"!llvm.preserve.access.index !0",
				"@llvm.bpf.preserve.field.info.p0(ptr %1, i64 2)",
			},
			notContain: []string{
				"@main.bpfCoreFieldExists",
				"getelementptr inbounds i8",
			},
		},
		{
			name: "field_exists falls back to deterministic offset index when no core type info",
			lines: []string{
				"declare i32 @main.bpfCoreFieldExists(ptr, ptr)",
				"define void @main.prog(ptr %ctx) {",
				"  %core = alloca [8 x i8], align 4",
				"  %1 = getelementptr inbounds nuw i8, ptr %core, i64 4, !dbg !10",
				"  %2 = call i32 @main.bpfCoreFieldExists(ptr nonnull %1, ptr undef)",
				"}",
				`!0 = !DICompositeType(tag: DW_TAG_structure_type, name: "runtime.someStruct", size: 64, elements: !{!1, !2})`,
				`!1 = !DIDerivedType(tag: DW_TAG_member, name: "A", baseType: !3, size: 32, offset: 0)`,
				`!2 = !DIDerivedType(tag: DW_TAG_member, name: "B", baseType: !3, size: 32, offset: 32)`,
				`!3 = !DIBasicType(name: "int32", size: 32, encoding: DW_ATE_signed)`,
			},
			wantContain: []string{
				"call ptr @llvm.preserve.struct.access.index.p0.p0(ptr elementtype(%main.__tinybpfCoreFallback) %core, i32 1, i32 1)",
				"@llvm.bpf.preserve.field.info.p0(ptr nonnull %1, i64 2)",
				"!dbg !10",
				"!llvm.preserve.access.index !",
			},
			notContain: []string{
				"@main.bpfCoreFieldExists",
				"getelementptr inbounds nuw i8, ptr %core, i64 4",
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
				"call ptr @llvm.preserve.struct.access.index.p0.p0(ptr elementtype(%main.bpfCoreTaskStruct) %core, i32 1, i32 1)",
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
				"preserve.struct.access.index.p0.p0(ptr elementtype(%main.bpfCoreTaskStruct) %core, i32 0, i32 0)",
				"@llvm.bpf.preserve.field.info.p0(",
				"i64 2)",
			},
			notContain: []string{
				"@main.bpfCoreFieldExists",
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

func TestRewriteCoreExistsIdempotent(t *testing.T) {
	lines := []string{
		"%main.bpfCoreTaskStruct = type { i32, i32 }",
		"declare i32 @main.bpfCoreFieldExists(ptr, ptr)",
		"define void @main.prog(ptr %ctx) {",
		"  %core = alloca %main.bpfCoreTaskStruct, align 4",
		"  %1 = getelementptr inbounds i8, ptr %core, i64 4",
		"  %2 = call i32 @main.bpfCoreFieldExists(ptr nonnull %1, ptr undef)",
		"}",
	}

	first, err := rewriteCoreExistsChecks(lines)
	if err != nil {
		t.Fatalf("first pass: %v", err)
	}
	firstText := strings.Join(first, "\n")

	second, err := rewriteCoreExistsChecks(first)
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	secondText := strings.Join(second, "\n")

	if firstText != secondText {
		t.Errorf("rewrite is not idempotent\n--- first ---\n%s\n--- second ---\n%s", firstText, secondText)
	}
}

func TestRewriteCoreExistsMalformedCall(t *testing.T) {
	lines := []string{
		"define void @main.prog(ptr %ctx) {",
		"  %1 = call i32 @main.bpfCoreFieldExists(ptr %x)",
		"}",
	}
	_, err := rewriteCoreExistsChecks(lines)
	if err != nil {
		t.Fatalf("unexpected error for single-arg call: %v", err)
	}
}

func TestFindSSADefBeyondWindow(t *testing.T) {
	lines := make([]string, 50)
	lines[0] = "  %ptr = getelementptr inbounds i8, ptr %base, i64 4"
	for i := 1; i < 49; i++ {
		lines[i] = "  ; filler"
	}
	lines[49] = "  %result = call i32 @main.bpfCoreFieldExists(ptr %ptr, ptr undef)"

	got := findSSADef(lines, "%ptr", 49)
	if got != -1 {
		t.Errorf("expected -1 (beyond 30-line window), got %d", got)
	}

	got = findSSADef(lines, "%ptr", 30)
	if got != 0 {
		t.Errorf("expected 0 (within window), got %d", got)
	}
}

func TestResolveFieldAmbiguousOffset(t *testing.T) {
	ctx := &coreExistsContext{
		fieldOffsets: map[string][]int{
			"%main.bpfCoreA": {0, 4, 8},
			"%main.bpfCoreB": {0, 8, 16},
		},
	}
	typeName, idx := ctx.resolveField(8)
	if typeName == "" || idx < 0 {
		t.Fatal("expected a match for offset 8")
	}
	if typeName != "%main.bpfCoreA" && typeName != "%main.bpfCoreB" {
		t.Errorf("unexpected type: %s", typeName)
	}
}

func TestBuildCoreExistsContext(t *testing.T) {
	lines := []string{
		"%main.bpfCoreTaskStruct = type { i32, i32 }",
		"declare i32 @main.bpfCoreFieldExists(ptr, ptr)",
		"define void @main.prog(ptr %ctx) {",
		"  %core = alloca %main.bpfCoreTaskStruct, align 4",
		"  %1 = getelementptr inbounds i8, ptr %core, i64 4",
		"  %2 = call i32 @main.bpfCoreFieldExists(ptr nonnull %1, ptr undef)",
		"}",
	}

	ctx, err := buildCoreExistsContext(lines)
	if err != nil {
		t.Fatal(err)
	}
	if len(ctx.fieldOffsets) == 0 {
		t.Error("expected fieldOffsets to be populated")
	}
	if _, ok := ctx.fieldOffsets["%main.bpfCoreTaskStruct"]; !ok {
		t.Error("expected %main.bpfCoreTaskStruct in fieldOffsets")
	}
}

func TestDiscoverFallbackFieldIndices(t *testing.T) {
	lines := []string{
		"declare i32 @main.bpfCoreFieldExists(ptr, ptr)",
		"define void @main.prog(ptr %ctx) {",
		"  %core = alloca [8 x i8], align 4",
		"  %1 = getelementptr inbounds i8, ptr %core, i64 4",
		"  %2 = call i32 @main.bpfCoreFieldExists(ptr nonnull %1, ptr undef)",
		"}",
	}

	idx, err := discoverFallbackFieldIndices(lines)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := idx[0]; !ok {
		t.Error("expected offset 0 in fallback index (always seeded)")
	}
	if _, ok := idx[4]; !ok {
		t.Error("expected offset 4 in fallback index")
	}
	if idx[0] != 0 || idx[4] != 1 {
		t.Errorf("expected {0:0, 4:1}, got %v", idx)
	}
}

func TestFallbackSegmentSize(t *testing.T) {
	offsets := []int{0, 4, 8}
	tests := []struct {
		idx  int
		want int
	}{
		{0, 4},
		{1, 4},
		{2, 1},
	}
	for _, tt := range tests {
		got := fallbackSegmentSize(offsets, tt.idx)
		if got != tt.want {
			t.Errorf("fallbackSegmentSize(%v, %d) = %d, want %d", offsets, tt.idx, got, tt.want)
		}
	}
}

func TestFallbackTotalSize(t *testing.T) {
	tests := []struct {
		offsets []int
		want    int
	}{
		{[]int{0, 4, 8}, 9},
		{[]int{0}, 1},
		{[]int{0, 4}, 5},
	}
	for _, tt := range tests {
		got := fallbackTotalSize(tt.offsets)
		if got != tt.want {
			t.Errorf("fallbackTotalSize(%v) = %d, want %d", tt.offsets, got, tt.want)
		}
	}
}

func TestSoleType(t *testing.T) {
	single := &coreExistsContext{
		fieldOffsets: map[string][]int{
			"%main.bpfCoreTaskStruct": {0, 4},
		},
	}
	if got := single.soleType(); got != "%main.bpfCoreTaskStruct" {
		t.Errorf("expected sole type, got %q", got)
	}

	multiple := &coreExistsContext{
		fieldOffsets: map[string][]int{
			"%main.bpfCoreTaskStruct": {0, 4},
			"%main.bpfCoreFileStruct": {0, 8},
		},
	}
	if got := multiple.soleType(); got != "" {
		t.Errorf("expected empty for multiple types, got %q", got)
	}

	empty := &coreExistsContext{
		fieldOffsets: map[string][]int{},
	}
	if got := empty.soleType(); got != "" {
		t.Errorf("expected empty for no types, got %q", got)
	}
}
