package transform

import "io"

// Options configures the IR transformation pass.
type Options struct {
	Programs []string
	Sections map[string]string
	Verbose  bool
	Stdout   io.Writer
	DumpDir  string
}
