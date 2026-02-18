package transform

import (
	"strings"
	"testing"
)

func TestRewriteHelpers(t *testing.T) {
	t.Run("known helpers", func(t *testing.T) {
		input := strings.Split(strings.TrimSpace(`
  %1 = call i64 @main.bpfGetCurrentPidTgid(ptr undef) #7
  %2 = call i64 @main.bpfProbeReadUser(ptr nonnull %buf, i32 16, ptr %src, ptr undef) #7
  %3 = call i64 @main.bpfRingbufOutput(ptr nonnull @main.events, ptr nonnull %ev, i64 16, i64 0, ptr undef) #7
`), "\n")
		got, err := rewriteHelpers(input)
		if err != nil {
			t.Fatal(err)
		}
		text := strings.Join(got, "\n")

		expected := []struct {
			ret  string
			id   string
			args string
		}{
			{"i64", "14", "()"},
			{"i64", "112", "(ptr nonnull %buf, i32 16, ptr %src)"},
			{"i64", "130", "(ptr nonnull @main.events, ptr nonnull %ev, i64 16, i64 0)"},
		}
		for _, e := range expected {
			want := "call " + e.ret + " inttoptr (i64 " + e.id + " to ptr)" + e.args
			if !strings.Contains(text, want) {
				t.Errorf("missing %q in:\n%s", want, text)
			}
		}
		if strings.Contains(text, "@main.bpf") {
			t.Error("mangled BPF helper names still present")
		}
	})

	t.Run("pointer return type", func(t *testing.T) {
		input := []string{`  %1 = call ptr @main.bpfMapLookupElem(ptr %map, ptr %key, ptr undef) #7`}
		got, err := rewriteHelpers(input)
		if err != nil {
			t.Fatal(err)
		}
		text := strings.Join(got, "\n")
		want := "call ptr inttoptr (i64 1 to ptr)(ptr %map, ptr %key)"
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	})

	t.Run("i32 return type", func(t *testing.T) {
		input := []string{`  %1 = call i32 @main.bpfMapDeleteElem(ptr %map, ptr %key, ptr undef) #7`}
		got, err := rewriteHelpers(input)
		if err != nil {
			t.Fatal(err)
		}
		text := strings.Join(got, "\n")
		want := "call i32 inttoptr (i64 3 to ptr)(ptr %map, ptr %key)"
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	})

	t.Run("unknown helper", func(t *testing.T) {
		input := []string{`  call i64 @main.bpfUnknownHelper(ptr undef) #7`}
		_, err := rewriteHelpers(input)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "bpfUnknownHelper") {
			t.Errorf("should mention unknown helper: %v", err)
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
