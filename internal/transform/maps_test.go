package transform

import (
	"strings"
	"testing"
)

func TestStripMapPrefix(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name: "renames main.events to events",
			input: []string{
				`@main.events = global %main.bpfMapDef zeroinitializer, section ".maps", align 8`,
				`  call i64 @helper(ptr @main.events, i64 0)`,
			},
			want: []string{
				`@events = global %main.bpfMapDef zeroinitializer, section ".maps", align 8`,
				`  call i64 @helper(ptr @events, i64 0)`,
			},
		},
		{
			name: "multiple map globals",
			input: []string{
				`@main.events = global { ptr } zeroinitializer, section ".maps", align 8`,
				`@main.counters = global { ptr } zeroinitializer, section ".maps", align 8`,
				`  store ptr @main.events, ptr %1`,
				`  store ptr @main.counters, ptr %2`,
			},
			want: []string{
				`@events = global { ptr } zeroinitializer, section ".maps", align 8`,
				`@counters = global { ptr } zeroinitializer, section ".maps", align 8`,
				`  store ptr @events, ptr %1`,
				`  store ptr @counters, ptr %2`,
			},
		},
		{
			name: "globals without dots left unchanged",
			input: []string{
				`@events = global { ptr } zeroinitializer, section ".maps", align 8`,
				`  store ptr @events, ptr %1`,
			},
			want: []string{
				`@events = global { ptr } zeroinitializer, section ".maps", align 8`,
				`  store ptr @events, ptr %1`,
			},
		},
		{
			name: "non-map globals with dots left alone",
			input: []string{
				`@main.some_global = global i32 42`,
				`@main.events = global { ptr } zeroinitializer, section ".maps", align 8`,
				`  %v = load i32, ptr @main.some_global`,
				`  store ptr @main.events, ptr %1`,
			},
			want: []string{
				`@main.some_global = global i32 42`,
				`@events = global { ptr } zeroinitializer, section ".maps", align 8`,
				`  %v = load i32, ptr @main.some_global`,
				`  store ptr @events, ptr %1`,
			},
		},
		{
			name: "no map globals is a no-op",
			input: []string{
				`@main.x = global i32 0`,
				`define void @main.foo() {`,
				`  ret void`,
				`}`,
			},
			want: []string{
				`@main.x = global i32 0`,
				`define void @main.foo() {`,
				`  ret void`,
				`}`,
			},
		},
		{
			name: "trailing dot name is skipped",
			input: []string{
				`@trailingdot. = global { ptr } zeroinitializer, section ".maps", align 8`,
			},
			want: []string{
				`@trailingdot. = global { ptr } zeroinitializer, section ".maps", align 8`,
			},
		},
		{
			name: "deeply qualified package prefix",
			input: []string{
				`@mypackage.ringbuf = global { ptr } zeroinitializer, section ".maps", align 8`,
				`  call void @helper(ptr @mypackage.ringbuf)`,
			},
			want: []string{
				`@ringbuf = global { ptr } zeroinitializer, section ".maps", align 8`,
				`  call void @helper(ptr @ringbuf)`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripMapPrefix(tt.input)
			if strings.Join(got, "\n") != strings.Join(tt.want, "\n") {
				t.Errorf("stripMapPrefix():\n  got:  %v\n  want: %v", got, tt.want)
			}
		})
	}
}
