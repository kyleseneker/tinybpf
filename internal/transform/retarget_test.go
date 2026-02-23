package transform

import "testing"

func TestRetarget(t *testing.T) {
	tests := []struct {
		name           string
		input          []string
		wantDatalayout string
		wantTriple     string
	}{
		{
			name: "arm64 to bpf",
			input: []string{
				`source_filename = "main"`,
				`target datalayout = "e-m:o-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-n32:64-S128-Fn32"`,
				`target triple = "arm64-apple-macosx11.0.0"`,
				``,
			},
			wantDatalayout: bpfDatalayout,
			wantTriple:     bpfTriple,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := retarget(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			if got[1] != tt.wantDatalayout {
				t.Errorf("datalayout:\n  got  %q\n  want %q", got[1], tt.wantDatalayout)
			}
			if got[2] != tt.wantTriple {
				t.Errorf("triple:\n  got  %q\n  want %q", got[2], tt.wantTriple)
			}
		})
	}
}
