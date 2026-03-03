package transform

import "io"

// transformStage pairs a human-readable name with a transform function.
type transformStage struct {
	name string
	fn   func([]string) ([]string, error)
}

// buildStages returns the ordered pipeline of IR transformation stages.
func buildStages(opts Options) []transformStage {
	extractProgs := func(l []string) ([]string, error) {
		return extractPrograms(l, opts.Programs, opts.Verbose, opts.Stdout)
	}
	assignProgSections := func(l []string) ([]string, error) {
		return assignProgramSections(l, opts.Sections)
	}

	return []transformStage{
		{"retarget", retarget},
		{"strip-attributes", stripAttributes},
		{"extract-programs", extractProgs},
		{"replace-alloc", replaceAlloc},
		{"rewrite-helpers", rewriteHelpers},
		{"rewrite-core-access", rewriteCoreAccess},
		{"rewrite-core-exists", rewriteCoreExistsChecks},
		{"assign-data-sections", assignDataSections},
		{"assign-program-sections", assignProgSections},
		{"strip-map-prefix", stripMapPrefix},
		{"rewrite-map-btf", rewriteMapForBTF},
		{"sanitize-btf-names", sanitizeBTFNames},
		{"sanitize-core-fields", sanitizeCoreFieldNames},
		{"add-license", addLicense},
		{"cleanup", cleanup},
	}
}

// Options configures the IR transformation pass.
type Options struct {
	Programs []string
	Sections map[string]string
	Verbose  bool
	Stdout   io.Writer
	DumpDir  string
}
