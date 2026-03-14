package transform

import "testing"

func TestLevenshtein(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want int
	}{
		{"identical", "abc", "abc", 0},
		{"empty both", "", "", 0},
		{"empty a", "", "abc", 3},
		{"empty b", "abc", "", 3},
		{"one substitution", "abc", "adc", 1},
		{"one insertion", "abc", "abcd", 1},
		{"one deletion", "abcd", "abc", 1},
		{"completely different", "abc", "xyz", 3},
		{"transposition", "ab", "ba", 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := levenshtein(tt.a, tt.b); got != tt.want {
				t.Fatalf("levenshtein(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestClosestHelper(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "exact match", input: "main.bpfMapLookupElem", want: "main.bpfMapLookupElem"},
		{name: "one-char typo", input: "main.bpfMapLookpElem", want: "main.bpfMapLookupElem"},
		{name: "trailing extra char", input: "main.bpfProbeReadUserr", want: "main.bpfProbeReadUser"},
		{name: "too far", input: "main.bpfCompletelyWrong", want: ""},
		{name: "empty string", input: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := closestHelper(tt.input)
			if got != tt.want {
				t.Fatalf("closestHelper(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
