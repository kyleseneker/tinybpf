package transform

import (
	"strings"
	"testing"
)

func TestAssignDataSections(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{
			"mutable global gets .data",
			`@main.myConfig = global i64 42, align 8`,
			`section ".data"`,
		},
		{
			"constant global gets .rodata",
			`@main.myTable = constant [4 x i32] [i32 1, i32 2, i32 3, i32 4], align 4`,
			`section ".rodata"`,
		},
		{
			"zeroinitializer gets .bss",
			`@main.counter = global i64 zeroinitializer, align 8`,
			`section ".bss"`,
		},
		{
			"map global unchanged",
			`@main.events = global %main.bpfMapDef { i32 27, i32 0, i32 0, i32 16777216, i32 0 }, align 4`,
			`%main.bpfMapDef`,
		},
		{
			"runtime global unchanged",
			`@runtime.heapStart = global i64 0, align 8`,
			`@runtime.heapStart`,
		},
		{
			"existing section unchanged",
			`@main.myVar = global i32 1, section ".maps", align 4`,
			`section ".maps"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := assignDataSections([]string{tt.line})
			result := lines[0]
			if !strings.Contains(result, tt.want) {
				t.Errorf("expected %q in result:\n%s", tt.want, result)
			}
		})
	}

	t.Run("map global not modified", func(t *testing.T) {
		input := `@main.events = global %main.bpfMapDef { i32 27, i32 0, i32 0, i32 16777216, i32 0 }, align 4`
		lines := assignDataSections([]string{input})
		if lines[0] != input {
			t.Errorf("map global was modified:\n  got:  %s\n  want: %s", lines[0], input)
		}
	})

	t.Run("runtime global not modified", func(t *testing.T) {
		input := `@runtime.heapStart = global i64 0, align 8`
		lines := assignDataSections([]string{input})
		if lines[0] != input {
			t.Errorf("runtime global was modified:\n  got:  %s\n  want: %s", lines[0], input)
		}
	})
}

func TestClassifyGlobalSection(t *testing.T) {
	tests := []struct {
		name    string
		trimmed string
		want    string
	}{
		{"zeroinit", "@main.x = global i64 zeroinitializer, align 8", ".bss"},
		{"constant", "@main.x = constant i32 42, align 4", ".rodata"},
		{"mutable", "@main.x = global i32 42, align 4", ".data"},
		{"declare", "declare void @main.foo()", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyGlobalSection(tt.trimmed)
			if got != tt.want {
				t.Errorf("classifyGlobalSection = %q, want %q", got, tt.want)
			}
		})
	}
}
