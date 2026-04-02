package transform

import (
	"strings"
	"testing"

	"github.com/kyleseneker/tinybpf/internal/ir"
)

func TestSectionsPassModule(t *testing.T) {
	tests := []struct {
		name           string
		funcName       string
		funcRaw        string
		globalName     string
		globalLinkage  string
		globalInit     string
		globalRaw      string
		sections       map[string]string
		wantGlobalSect string
		wantFuncHasSec bool
	}{
		{
			name:           "assigns sections to globals and functions",
			funcName:       "probe_connect",
			funcRaw:        "define i32 @probe_connect() {",
			globalName:     "counter",
			globalLinkage:  "global",
			globalInit:     "0",
			globalRaw:      "@counter = global i32 0",
			sections:       map[string]string{"probe_connect": "tracepoint/tcp/tcp_connect"},
			wantGlobalSect: ".data",
			wantFuncHasSec: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := &ir.Function{Name: tt.funcName, Raw: tt.funcRaw}
			g := &ir.Global{Name: tt.globalName, Linkage: tt.globalLinkage, Initializer: tt.globalInit, Raw: tt.globalRaw}
			m := &ir.Module{
				Globals:   []*ir.Global{g},
				Functions: []*ir.Function{fn},
				Entries: []ir.TopLevelEntry{
					{Kind: ir.TopGlobal, Global: g, Raw: g.Raw},
					{Kind: ir.TopFunction, Function: fn, Raw: fn.Raw},
				},
			}
			if err := sectionsPassModule(m, tt.sections); err != nil {
				t.Fatal(err)
			}
			if g.Section != tt.wantGlobalSect {
				t.Errorf("global section = %q, want %q", g.Section, tt.wantGlobalSect)
			}
			if tt.wantFuncHasSec && !strings.Contains(fn.Raw, "section") {
				t.Error("function should have a section after sectionsPassModule")
			}
		})
	}
}

func TestClassifyGlobalSectionFromAST(t *testing.T) {
	tests := []struct {
		name   string
		global ir.Global
		want   string
	}{
		{"zeroinitializer -> .bss", ir.Global{Initializer: "zeroinitializer"}, ".bss"},
		{"constant -> .rodata", ir.Global{Linkage: "constant"}, ".rodata"},
		{"global with init -> .data", ir.Global{Linkage: "global", Initializer: "42"}, ".data"},
		{"global no init -> .data", ir.Global{Linkage: "global"}, ".data"},
		{"empty linkage with init -> .data", ir.Global{Initializer: "42"}, ".data"},
		{"empty -> empty", ir.Global{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyGlobalSectionFromAST(&tt.global); got != tt.want {
				t.Errorf("classifyGlobalSectionFromAST() = %q, want %q", got, tt.want)
			}
		})
	}
}
