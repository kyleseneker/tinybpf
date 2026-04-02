package transform

import (
	"regexp"

	"github.com/kyleseneker/tinybpf/internal/ir"
)

const (
	bpfDatalayoutValue = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
	bpfTripleValue     = "bpf"
)

var (
	reAttrTargetCPU      = regexp.MustCompile(`"target-cpu"="[^"]*"`)
	reAttrTargetFeatures = regexp.MustCompile(`"target-features"="[^"]*"`)
	reAttrAllocKind      = regexp.MustCompile(`allockind\("[^"]*"\)`)
	reAttrAllocSize      = regexp.MustCompile(`allocsize\(\d+\)`)
	reAttrAllocFamily    = regexp.MustCompile(`"alloc-family"="[^"]*"`)
	reAttrMultiSpace     = regexp.MustCompile(`  +`)
)

// moduleRewriteModule sets BPF target properties and strips invalid attributes in a single pass.
func moduleRewriteModule(m *ir.Module) error {
	if err := retargetModule(m); err != nil {
		return err
	}
	return stripAttributesModule(m)
}

// retargetModule sets the module's data layout and triple to BPF targets.
func retargetModule(m *ir.Module) error {
	m.DataLayout = bpfDatalayoutValue
	m.Triple = bpfTripleValue
	return nil
}

// stripAttributesModule removes target-specific attribute group entries that are invalid for BPF.
func stripAttributesModule(m *ir.Module) error {
	for _, ag := range m.AttrGroups {
		body := ag.Body
		body = reAttrTargetCPU.ReplaceAllString(body, "")
		body = reAttrTargetFeatures.ReplaceAllString(body, "")
		body = reAttrAllocKind.ReplaceAllString(body, "")
		body = reAttrAllocSize.ReplaceAllString(body, "")
		body = reAttrAllocFamily.ReplaceAllString(body, "")
		body = reAttrMultiSpace.ReplaceAllString(body, " ")
		if body != ag.Body {
			ag.Body = body
			ag.Modified = true
		}
	}
	return nil
}
