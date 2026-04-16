package transform

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kyleseneker/tinybpf/internal/ir"
)

func TestStripAbortCallsModule(t *testing.T) {
	src := `; ModuleID = 'test'
target triple = "bpf"

declare void @abort() #0

define i32 @xdp_filter(ptr %0) {
entry:
  %cmp = icmp eq ptr %0, null
  br i1 %cmp, label %panic, label %ok

panic:
  call void @abort()
  unreachable

ok:
  ret i32 0
}

attributes #0 = { noreturn }
`
	m, err := ir.Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var buf bytes.Buffer
	stripAbortCallsModule(m, &buf)

	for _, fn := range m.Functions {
		for _, block := range fn.Blocks {
			for _, inst := range block.Instructions {
				if inst.Call != nil && strings.Contains(inst.Call.Callee, "abort") {
					t.Errorf("abort call survived in AST: %q", inst.Raw)
				}
				if strings.Contains(inst.Raw, "@abort") {
					t.Errorf("abort survived in Raw: %q", inst.Raw)
				}
			}
		}
	}
	for _, e := range m.Entries {
		if e.Removed {
			continue
		}
		if e.Kind == ir.TopDeclare && e.Declare != nil && e.Declare.Name == "abort" {
			t.Error("declare @abort should be removed")
		}
	}
	if diag := buf.String(); !strings.Contains(diag, "stripped 1 abort call") {
		t.Errorf("expected diagnostic mentioning 1 abort call, got %q", diag)
	}
}
