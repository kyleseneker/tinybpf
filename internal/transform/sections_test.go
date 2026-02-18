package transform

import (
	"strings"
	"testing"
)

func FuzzAssignSections(f *testing.F) {
	f.Add(`define i32 @handle_connect(ptr %ctx) #4 !dbg !0 {
entry:
  ret i32 0
}`)
	f.Add(`@main.events = internal global %main.bpfMapDef { i32 27 }, align 4`)
	f.Add(`@main.events = global %main.bpfMapDef { i32 27 }`)
	f.Add(`define i32 @my_func(ptr %ctx) section "existing" {
entry:
  ret i32 0
}`)
	f.Add(`just some text`)

	f.Fuzz(func(t *testing.T, ir string) {
		lines := strings.Split(ir, "\n")
		assignSections(lines, nil)
	})
}

func TestAssignSections(t *testing.T) {
	t.Run("with map", func(t *testing.T) {
		input := strings.Split(strings.TrimSpace(`
@main.events = internal global %main.bpfMapDef { i32 27 }, align 4

define i32 @handle_connect(ptr %ctx) #4 {
entry:
  ret i32 0
}
`), "\n")
		got := assignSections(input, map[string]string{"handle_connect": "kprobe/sys_connect"})
		text := strings.Join(got, "\n")
		if !strings.Contains(text, `section "kprobe/sys_connect"`) {
			t.Error("section not assigned")
		}
		if !strings.Contains(text, `section ".maps"`) {
			t.Error("map section not assigned")
		}
	})

	t.Run("default section name", func(t *testing.T) {
		input := []string{
			`define i32 @my_func(ptr %ctx) #4 {`,
			`entry:`, `  ret i32 0`, `}`,
		}
		text := strings.Join(assignSections(input, nil), "\n")
		if !strings.Contains(text, `section "my_func"`) {
			t.Errorf("expected default section name:\n%s", text)
		}
	})

	t.Run("no align fallback", func(t *testing.T) {
		input := []string{`@main.events = internal global %main.bpfMapDef { i32 27 }`}
		text := strings.Join(assignSections(input, nil), "\n")
		if !strings.Contains(text, `section ".maps"`) {
			t.Error("map section not assigned without align")
		}
	})
}

func TestInsertSectionNoBrace(t *testing.T) {
	got := insertSection(`declare i32 @my_func(ptr %ctx)`, "kprobe/test")
	if !strings.Contains(got, `section "kprobe/test"`) {
		t.Errorf("expected section attribute, got: %s", got)
	}
}
