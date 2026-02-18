package transform

import "testing"

func TestRetarget(t *testing.T) {
	lines := []string{
		`source_filename = "main"`,
		`target datalayout = "e-m:o-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-n32:64-S128-Fn32"`,
		`target triple = "arm64-apple-macosx11.0.0"`,
		``,
	}
	got := retarget(lines)
	if got[1] != bpfDatalayout {
		t.Errorf("datalayout:\n  got  %q\n  want %q", got[1], bpfDatalayout)
	}
	if got[2] != bpfTriple {
		t.Errorf("triple:\n  got  %q\n  want %q", got[2], bpfTriple)
	}
}
