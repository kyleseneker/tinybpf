package transform

import "testing"

func TestParseI32InitializerError(t *testing.T) {
	if got := parseI32Initializer("i32 abc, i32 1"); got != nil {
		t.Fatalf("expected nil for malformed initializer, got %v", got)
	}
}
