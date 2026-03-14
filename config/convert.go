package config

import (
	"github.com/kyleseneker/tinybpf/pipeline"
)

// ToPipeline converts a Config into a pipeline.Config, applying defaults
// for any unset fields.
func ToPipeline(cfg *Config) pipeline.Config {
	pc := pipeline.Config{
		Output:       cfg.Build.Output,
		CPU:          cfg.Build.CPU,
		OptProfile:   cfg.Build.OptProfile,
		CustomPasses: cfg.Build.CustomPasses,
		Tools:        ResolveToolOverrides(cfg.Toolchain),
	}

	if cfg.Build.BTF != nil {
		pc.EnableBTF = *cfg.Build.BTF
	}

	if cfg.Build.Cache != nil {
		pc.Cache = *cfg.Build.Cache
	}

	if cfg.Build.Timeout != "" {
		d, _ := ParseTimeout(cfg.Build.Timeout)
		pc.Timeout = d
	}

	if len(cfg.Build.Programs) > 0 {
		programs := make([]string, 0, len(cfg.Build.Programs))
		sections := make(map[string]string, len(cfg.Build.Programs))
		for name, section := range cfg.Build.Programs {
			programs = append(programs, name)
			if section != "" {
				sections[name] = section
			}
		}
		pc.Programs = programs
		if len(sections) > 0 {
			pc.Sections = sections
		}
	}

	return pc
}
