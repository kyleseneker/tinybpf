package transform

import (
	"github.com/kyleseneker/tinybpf/internal/ir"
)

// moduleStage pairs a name with an AST-based transform function.
type moduleStage struct {
	name string
	fn   func(*ir.Module) error
}

// buildModuleStages returns the ordered pipeline of AST-based IR transforms.
func buildModuleStages(opts Options) []moduleStage {
	return []moduleStage{
		{"module-rewrite", moduleRewriteModule},
		{"extract-programs", func(m *ir.Module) error {
			return extractProgramsModule(m, opts.Programs, opts.Verbose, opts.Stdout)
		}},
		{"replace-alloc", replaceAllocModule},
		{"rewrite-helpers", rewriteHelpersModule},
		{"core", corePassModule},
		{"sections", func(m *ir.Module) error {
			return sectionsPassModule(m, opts.Sections)
		}},
		{"map-btf", mapBTFPassModule},
		{"finalize", func(m *ir.Module) error {
			return finalizeModule(m, opts.Stdout)
		}},
	}
}
