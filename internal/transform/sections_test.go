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
		if len(ir) > 1<<16 {
			return
		}
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

func TestAssignSectionsSixFieldMap(t *testing.T) {
	input := strings.Split(strings.TrimSpace(`
@main.pinned = internal global %main.bpfMapDef { i32 1, i32 4, i32 4, i32 1024, i32 0, i32 1 }, align 4

define i32 @my_prog(ptr %ctx) #4 {
entry:
  ret i32 0
}
`), "\n")
	got := assignSections(input, nil)
	text := strings.Join(got, "\n")

	if !strings.Contains(text, `section ".maps"`) {
		t.Error("6-field map not assigned to .maps section")
	}
	if strings.Contains(text, " internal ") {
		t.Error("internal linkage should be stripped from map globals")
	}
}

func TestAssignSectionsPreserveExisting(t *testing.T) {
	input := []string{
		`define i32 @my_func(ptr %ctx) section "tracepoint/raw_syscalls/sys_enter" {`,
		`entry:`, `  ret i32 0`, `}`,
	}
	got := assignSections(input, map[string]string{"my_func": "kprobe/something_else"})
	text := strings.Join(got, "\n")
	if !strings.Contains(text, `section "tracepoint/raw_syscalls/sys_enter"`) {
		t.Error("existing section should be preserved")
	}
	if strings.Contains(text, "kprobe/something_else") {
		t.Error("should not override existing section attribute")
	}
}

func TestInsertSectionNoBrace(t *testing.T) {
	got := insertSection(`declare i32 @my_func(ptr %ctx)`, "kprobe/test")
	if !strings.Contains(got, `section "kprobe/test"`) {
		t.Errorf("expected section attribute, got: %s", got)
	}
}
