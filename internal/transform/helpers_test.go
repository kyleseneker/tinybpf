package transform

import (
	"fmt"
	"strings"
	"testing"
)

func FuzzRewriteHelpers(f *testing.F) {
	f.Add(`  %1 = call i64 @main.bpfGetCurrentPidTgid(ptr undef) #7`)
	f.Add(`  %2 = call i64 @main.bpfProbeReadUser(ptr nonnull %buf, i32 16, ptr %src, ptr undef) #7`)
	f.Add(`  %1 = call ptr @main.bpfMapLookupElem(ptr %map, ptr %key, ptr undef) #7`)
	f.Add(`  call void @main.bpfTailCall(ptr %ctx, ptr %map, i32 %idx, ptr undef) #7`)
	f.Add(`  no bpf call here, just a normal line`)
	f.Add(`  call i64 @main.bpf`)
	f.Add(`  call i64 @main.bpfUnclosed(`)

	f.Fuzz(func(t *testing.T, line string) {
		lines := strings.Split(line, "\n")
		rewriteHelpers(lines)
	})
}

func TestRewriteHelpers(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"context-only arg stripped",
			`  %1 = call i64 @main.bpfGetCurrentPidTgid(ptr undef) #7`,
			"call i64 inttoptr (i64 14 to ptr)()"},
		{"trailing undef stripped with real args",
			`  %1 = call i64 @main.bpfProbeReadUser(ptr nonnull %buf, i32 16, ptr %src, ptr undef) #7`,
			"call i64 inttoptr (i64 112 to ptr)(ptr nonnull %buf, i32 16, ptr %src)"},
		{"ptr return type",
			`  %1 = call ptr @main.bpfMapLookupElem(ptr %map, ptr %key, ptr undef) #7`,
			"call ptr inttoptr (i64 1 to ptr)(ptr %map, ptr %key)"},
		{"i32 return type",
			`  %1 = call i32 @main.bpfMapDeleteElem(ptr %map, ptr %key, ptr undef) #7`,
			"call i32 inttoptr (i64 3 to ptr)(ptr %map, ptr %key)"},
		{"void return type",
			`  call void @main.bpfRingbufSubmit(ptr %1, i64 0, ptr undef) #7`,
			"call void inttoptr (i64 132 to ptr)(ptr %1, i64 0)"},
		{"multi-arg networking helper",
			`  %1 = call i64 @main.bpfSkbStoreBytes(ptr %skb, i32 %off, ptr %from, i32 %len, i64 0, ptr undef) #7`,
			"inttoptr (i64 9 to ptr)"},
		{"ringbuf reserve",
			`  %1 = call ptr @main.bpfRingbufReserve(ptr @main.events, i64 16, i64 0, ptr undef) #7`,
			"inttoptr (i64 131 to ptr)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := rewriteHelpers([]string{tt.input})
			if err != nil {
				t.Fatal(err)
			}
			text := strings.Join(got, "\n")
			if !strings.Contains(text, tt.want) {
				t.Errorf("missing %q in:\n%s", tt.want, text)
			}
			if strings.Contains(text, "@main.bpf") {
				t.Error("mangled helper name still present")
			}
		})
	}

	t.Run("all known helpers resolve", func(t *testing.T) {
		for name, id := range knownHelpers {
			line := fmt.Sprintf(`  %%1 = call i64 @%s(ptr undef) #7`, name)
			got, err := rewriteHelpers([]string{line})
			if err != nil {
				t.Errorf("%s: %v", name, err)
				continue
			}
			want := fmt.Sprintf("inttoptr (i64 %d to ptr)", id)
			if !strings.Contains(strings.Join(got, "\n"), want) {
				t.Errorf("%s: expected %q", name, want)
			}
		}
	})

	t.Run("unknown helper", func(t *testing.T) {
		_, err := rewriteHelpers([]string{`  call i64 @main.bpfUnknownHelper(ptr undef) #7`})
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "bpfUnknownHelper") {
			t.Errorf("should mention unknown helper: %v", err)
		}
	})

	t.Run("non-helper line unchanged", func(t *testing.T) {
		input := []string{`  %1 = add i32 %a, %b`}
		got, err := rewriteHelpers(input)
		if err != nil {
			t.Fatal(err)
		}
		if got[0] != input[0] {
			t.Errorf("line changed: %q", got[0])
		}
	})
}

func TestStripTrailingUndef(t *testing.T) {
	tests := []struct{ in, want string }{
		{"ptr undef", ""},
		{"ptr nonnull %sa, i32 16, ptr %5, ptr undef", "ptr nonnull %sa, i32 16, ptr %5"},
		{
			"ptr nonnull @main.events, ptr nonnull %ev, i64 16, i64 0, ptr undef",
			"ptr nonnull @main.events, ptr nonnull %ev, i64 16, i64 0",
		},
		{"i32 42", "i32 42"},
	}
	for _, tt := range tests {
		if got := stripTrailingUndef(tt.in); got != tt.want {
			t.Errorf("stripTrailingUndef(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
