package transform

import (
	"strings"
	"testing"
)

func FuzzAssignProgramSections(f *testing.F) {
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
		assignProgramSections(lines, nil)
	})
}

func TestAssignProgramSections(t *testing.T) {
	tests := []struct {
		name        string
		input       []string
		sections    map[string]string
		wantContain []string
		notContain  []string
	}{
		{
			name: "with map",
			input: strings.Split(strings.TrimSpace(`
@main.events = internal global %main.bpfMapDef { i32 27 }, align 4

define i32 @handle_connect(ptr %ctx) #4 {
entry:
  ret i32 0
}
`), "\n"),
			sections:    map[string]string{"handle_connect": "kprobe/sys_connect"},
			wantContain: []string{`section "kprobe/sys_connect"`, `section ".maps"`},
		},
		{
			name: "default section name",
			input: []string{
				`define i32 @my_func(ptr %ctx) #4 {`,
				`entry:`, `  ret i32 0`, `}`,
			},
			wantContain: []string{`section "my_func"`},
		},
		{
			name:        "no align fallback",
			input:       []string{`@main.events = internal global %main.bpfMapDef { i32 27 }`},
			wantContain: []string{`section ".maps"`},
		},
		{
			name: "six field map",
			input: strings.Split(strings.TrimSpace(`
@main.pinned = internal global %main.bpfMapDef { i32 1, i32 4, i32 4, i32 1024, i32 0, i32 1 }, align 4

define i32 @my_prog(ptr %ctx) #4 {
entry:
  ret i32 0
}
`), "\n"),
			wantContain: []string{`section ".maps"`},
			notContain:  []string{" internal "},
		},
		{
			name: "preserve existing section",
			input: []string{
				`define i32 @my_func(ptr %ctx) section "tracepoint/raw_syscalls/sys_enter" {`,
				`entry:`, `  ret i32 0`, `}`,
			},
			sections:    map[string]string{"my_func": "kprobe/something_else"},
			wantContain: []string{`section "tracepoint/raw_syscalls/sys_enter"`},
			notContain:  []string{"kprobe/something_else"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := assignProgramSections(tt.input, tt.sections)
			text := strings.Join(got, "\n")
			for _, want := range tt.wantContain {
				if !strings.Contains(text, want) {
					t.Errorf("output missing %q", want)
				}
			}
			for _, bad := range tt.notContain {
				if strings.Contains(text, bad) {
					t.Errorf("output should not contain %q", bad)
				}
			}
		})
	}
}

func TestInsertSection(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		section     string
		wantContain string
	}{
		{
			name:        "no brace declare",
			line:        `declare i32 @my_func(ptr %ctx)`,
			section:     "kprobe/test",
			wantContain: `section "kprobe/test"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := insertSection(tt.line, tt.section)
			if !strings.Contains(got, tt.wantContain) {
				t.Errorf("expected section attribute, got: %s", got)
			}
		})
	}
}
