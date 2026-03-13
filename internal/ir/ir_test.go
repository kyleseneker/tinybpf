package ir

import (
	"os"
	"path/filepath"
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

func TestParseMinimal(t *testing.T) {
	m, err := Parse(minimalIR)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if m.Triple != "bpf" {
		t.Errorf("Triple = %q, want %q", m.Triple, "bpf")
	}
	if len(m.Functions) != 1 {
		t.Fatalf("Functions = %d, want 1", len(m.Functions))
	}
	fn := m.Functions[0]
	if fn.Name != "xdp_prog" {
		t.Errorf("Function name = %q, want %q", fn.Name, "xdp_prog")
	}
	if fn.Section != "xdp" {
		t.Errorf("Function section = %q, want %q", fn.Section, "xdp")
	}
	if fn.RetType != "i64" {
		t.Errorf("Function rettype = %q, want %q", fn.RetType, "i64")
	}
}

func TestParseMapAndHelper(t *testing.T) {
	m, err := Parse(mapAndHelperIR)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if m.Triple != "x86_64-unknown-linux-gnu" {
		t.Errorf("Triple = %q", m.Triple)
	}
	if len(m.Globals) != 1 {
		t.Fatalf("Globals = %d, want 1", len(m.Globals))
	}
	g := m.Globals[0]
	if g.Name != "main.events" {
		t.Errorf("Global name = %q, want %q", g.Name, "main.events")
	}
	if g.Align != 4 {
		t.Errorf("Global align = %d, want 4", g.Align)
	}

	if len(m.Functions) != 1 {
		t.Fatalf("Functions = %d, want 1", len(m.Functions))
	}
	fn := m.Functions[0]
	if fn.AttrRef != "#0" {
		t.Errorf("AttrRef = %q, want %q", fn.AttrRef, "#0")
	}

	if len(m.AttrGroups) != 1 {
		t.Fatalf("AttrGroups = %d, want 1", len(m.AttrGroups))
	}
	if m.AttrGroups[0].ID != "0" {
		t.Errorf("AttrGroup ID = %q, want %q", m.AttrGroups[0].ID, "0")
	}
}

func TestParseCoreGEP(t *testing.T) {
	m, err := Parse(coreGEPIR)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(m.TypeDefs) != 1 {
		t.Fatalf("TypeDefs = %d, want 1", len(m.TypeDefs))
	}
	td := m.TypeDefs[0]
	if td.Name != "%main.bpfCoreTaskStruct" {
		t.Errorf("TypeDef name = %q", td.Name)
	}
	if len(td.Fields) != 3 {
		t.Errorf("TypeDef fields = %d, want 3", len(td.Fields))
	}

	fn := m.Functions[0]
	if len(fn.Blocks) == 0 {
		t.Fatalf("no blocks")
	}
	block := fn.Blocks[0]

	var foundGEP, foundCall bool
	for _, inst := range block.Instructions {
		if inst.Kind == InstGEP {
			foundGEP = true
			if inst.GEP.BaseType != "%main.bpfCoreTaskStruct" {
				t.Errorf("GEP base type = %q", inst.GEP.BaseType)
			}
			if !inst.GEP.Inbounds {
				t.Error("GEP not inbounds")
			}
		}
		if inst.Kind == InstCall && inst.Call != nil && strings.Contains(inst.Call.Callee, "inttoptr") {
			foundCall = true
		}
	}
	if !foundGEP {
		t.Error("did not find GEP instruction")
	}
	if !foundCall {
		t.Error("did not find inttoptr call")
	}
}

func TestParseCoreFieldExists(t *testing.T) {
	m, err := Parse(coreFieldExistsIR)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(m.Declares) != 1 {
		t.Fatalf("Declares = %d, want 1", len(m.Declares))
	}
	if m.Declares[0].Name != "main.bpfCoreFieldExists" {
		t.Errorf("Declare name = %q", m.Declares[0].Name)
	}

	fn := m.Functions[0]
	block := fn.Blocks[0]
	var foundAlloca, foundGEP, foundCall bool
	for _, inst := range block.Instructions {
		switch inst.Kind {
		case InstAlloca:
			foundAlloca = true
			if inst.Alloca.Type != "%main.bpfCoreTaskStruct" {
				t.Errorf("alloca type = %q", inst.Alloca.Type)
			}
		case InstGEP:
			foundGEP = true
		case InstCall:
			if inst.Call != nil && strings.Contains(inst.Call.Callee, "bpfCoreFieldExists") {
				foundCall = true
			}
		}
	}
	if !foundAlloca {
		t.Error("missing alloca")
	}
	if !foundGEP {
		t.Error("missing GEP")
	}
	if !foundCall {
		t.Error("missing bpfCoreFieldExists call")
	}
}

func TestParseMetadata(t *testing.T) {
	m, err := Parse(metadataIR)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(m.MetadataNodes) != 8 {
		t.Fatalf("MetadataNodes = %d, want 8", len(m.MetadataNodes))
	}

	mn0 := m.MetadataNodes[0]
	if mn0.ID != 0 {
		t.Errorf("metadata[0] ID = %d", mn0.ID)
	}
	if mn0.Kind != "DICompositeType" {
		t.Errorf("metadata[0] kind = %q", mn0.Kind)
	}
	if mn0.Fields["tag"] != "DW_TAG_structure_type" {
		t.Errorf("metadata[0] tag = %q", mn0.Fields["tag"])
	}
	if mn0.Fields["name"] != "main.bpfCoreTaskStruct" {
		t.Errorf("metadata[0] name = %q", mn0.Fields["name"])
	}

	mn4 := m.MetadataNodes[4]
	if mn4.Kind != "DIBasicType" {
		t.Errorf("metadata[4] kind = %q", mn4.Kind)
	}
}

func TestParseDataSections(t *testing.T) {
	m, err := Parse(datasectionsIR)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(m.Globals) != 5 {
		t.Fatalf("Globals = %d, want 5", len(m.Globals))
	}

	license := m.Globals[4]
	if license.Section != "license" {
		t.Errorf("license section = %q", license.Section)
	}
	if license.Align != 1 {
		t.Errorf("license align = %d", license.Align)
	}
}

func TestParseRuntimeAndAlloc(t *testing.T) {
	m, err := Parse(runtimeAndAllocIR)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(m.Functions) != 2 {
		t.Fatalf("Functions = %d, want 2", len(m.Functions))
	}
	if m.Functions[0].Name != "runtime.runMain" {
		t.Errorf("func[0] name = %q", m.Functions[0].Name)
	}
	if m.Functions[1].Name != "handle" {
		t.Errorf("func[1] name = %q", m.Functions[1].Name)
	}

	handleFn := m.Functions[1]
	if len(handleFn.Blocks) == 0 {
		t.Fatal("no blocks in handle")
	}
	var callCount int
	for _, inst := range handleFn.Blocks[0].Instructions {
		if inst.Kind == InstCall {
			callCount++
		}
	}
	if callCount < 2 {
		t.Errorf("expected at least 2 call instructions, got %d", callCount)
	}
}

func TestParseCleanup(t *testing.T) {
	m, err := Parse(cleanupIR)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(m.Declares) != 2 {
		t.Fatalf("Declares = %d, want 2", len(m.Declares))
	}
	if m.Declares[0].Name != "unused_func" {
		t.Errorf("declares[0] = %q", m.Declares[0].Name)
	}
	if m.Declares[1].Name != "llvm.memset.p0.i64" {
		t.Errorf("declares[1] = %q", m.Declares[1].Name)
	}
	if len(m.AttrGroups) != 2 {
		t.Fatalf("AttrGroups = %d, want 2", len(m.AttrGroups))
	}
}

func TestRoundTripMinimal(t *testing.T) {
	testRoundTrip(t, "minimal", minimalIR)
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

func TestRoundTripTransformSeed(t *testing.T) {
	testRoundTrip(t, "transformSeed", transformSeedIR)
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

func TestBuildIndex(t *testing.T) {
	m, err := Parse(mapAndHelperIR)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	idx := BuildIndex(m)

	if _, ok := idx.IdentRefs["@main.events"]; !ok {
		t.Error("missing @main.events in ident refs")
	}
	if _, ok := idx.IdentRefs["@my_func"]; !ok {
		t.Error("missing @my_func in ident refs")
	}
}

func TestBuildIndexSSA(t *testing.T) {
	m, err := Parse(coreFieldExistsIR)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	idx := BuildIndex(m)

	coreInst, coreOK := idx.SSADefs["%core"]
	if !coreOK {
		t.Fatal("missing SSA def for core")
	}
	if coreInst.Kind != InstAlloca {
		t.Fatalf("SSA def for core: kind = %d, want InstAlloca", coreInst.Kind)
	}

	gepInst, gepOK := idx.SSADefs["%1"]
	if !gepOK {
		t.Fatal("missing SSA def for 1")
	}
	if gepInst.Kind != InstGEP {
		t.Fatalf("SSA def for 1: kind = %d, want InstGEP", gepInst.Kind)
	}
}

func TestBuildIndexMetadata(t *testing.T) {
	m, err := Parse(metadataIR)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	idx := BuildIndex(m)

	if idx.MaxMetaID != 7 {
		t.Errorf("MaxMetaID = %d, want 7", idx.MaxMetaID)
	}
	if idx.NextMetaID() != 8 {
		t.Errorf("NextMetaID = %d, want 8", idx.NextMetaID())
	}
	if mn, ok := idx.MetaByID[0]; !ok {
		t.Error("missing metadata !0")
	} else if mn.Kind != "DICompositeType" {
		t.Errorf("metadata !0 kind = %q", mn.Kind)
	}
}

func TestModifyAndSerialize(t *testing.T) {
	m, err := Parse(minimalIR)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	m.Triple = "bpf-new"

	out := Serialize(m)
	if !strings.Contains(out, `target triple = "bpf-new"`) {
		t.Errorf("modified triple not in output:\n%s", out)
	}
}

func TestModifyGlobal(t *testing.T) {
	m, err := Parse(datasectionsIR)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	for _, g := range m.Globals {
		if g.Name == "main.myConfig" {
			g.Section = ".data"
			g.Modified = true
		}
	}

	out := Serialize(m)
	if !strings.Contains(out, `section ".data"`) {
		t.Errorf("modified section not in output:\n%s", out)
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
