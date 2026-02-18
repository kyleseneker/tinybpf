package transform

import "strings"

const (
	bpfDatalayout = `target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"`
	bpfTriple     = `target triple = "bpf"`
)

// retarget replaces the host triple and datalayout with BPF equivalents.
func retarget(lines []string) []string {
	for i, line := range lines {
		if strings.HasPrefix(line, "target datalayout = ") {
			lines[i] = bpfDatalayout
		} else if strings.HasPrefix(line, "target triple = ") {
			lines[i] = bpfTriple
		}
	}
	return lines
}
