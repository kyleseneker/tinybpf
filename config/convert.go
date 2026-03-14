package config

import (
	"path/filepath"

	"github.com/kyleseneker/tinybpf"
)

// ToRequest converts a Config into a [tinybpf.Request], applying defaults
// for any unset fields.
func ToRequest(cfg *Config) tinybpf.Request {
	req := tinybpf.Request{
		Output:       cfg.Build.Output,
		CPU:          cfg.Build.CPU,
		OptProfile:   cfg.Build.OptProfile,
		CustomPasses: cfg.Build.CustomPasses,
		Toolchain:    ResolveToolchain(cfg.Toolchain),
	}

	if cfg.Build.BTF != nil {
		req.EnableBTF = *cfg.Build.BTF
	}

	if cfg.Build.Cache != nil {
		req.Cache = *cfg.Build.Cache
	}

	if cfg.Build.Timeout != "" {
		d, _ := ParseTimeout(cfg.Build.Timeout)
		req.Timeout = d
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
		req.Programs = programs
		if len(sections) > 0 {
			req.Sections = sections
		}
	}

	return req
}

// ResolveToolchain builds a [tinybpf.Toolchain] from the config Toolchain,
// applying llvm_dir as a prefix for any tool not explicitly set.
func ResolveToolchain(tc Toolchain) tinybpf.Toolchain {
	resolve := func(explicit, name string) string {
		if explicit != "" {
			return explicit
		}
		if tc.LLVMDir != "" {
			return filepath.Join(tc.LLVMDir, name)
		}
		return ""
	}
	return tinybpf.Toolchain{
		TinyGo:   tc.TinyGo,
		LLVMLink: resolve(tc.LLVMLink, "llvm-link"),
		Opt:      resolve(tc.Opt, "opt"),
		LLC:      resolve(tc.LLC, "llc"),
		LLVMAr:   resolve(tc.LLVMAr, "llvm-ar"),
		Objcopy:  resolve(tc.LLVMObjcopy, "llvm-objcopy"),
		Pahole:   resolve(tc.Pahole, "pahole"),
	}
}
