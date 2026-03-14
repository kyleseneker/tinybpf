// Package config loads and merges tinybpf project configuration from
// a tinybpf.json file and CLI flag overrides.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kyleseneker/tinybpf/llvm"
)

// Filename is the conventional config file name.
const Filename = "tinybpf.json"

// Config holds all user-provided project settings.
type Config struct {
	Build     Build     `json:"build"`
	Toolchain Toolchain `json:"toolchain"`
}

// Build holds build-related settings.
type Build struct {
	Output       string            `json:"output"`
	CPU          string            `json:"cpu"`
	OptProfile   string            `json:"opt_profile"`
	BTF          *bool             `json:"btf"`
	Timeout      string            `json:"timeout"`
	Programs     map[string]string `json:"programs"`
	CustomPasses []string          `json:"custom_passes"`
}

// Toolchain holds LLVM and TinyGo tool path overrides.
type Toolchain struct {
	LLVMDir     string `json:"llvm_dir"`
	LLVMLink    string `json:"llvm_link"`
	Opt         string `json:"opt"`
	LLC         string `json:"llc"`
	LLVMAr      string `json:"llvm_ar"`
	LLVMObjcopy string `json:"llvm_objcopy"`
	Pahole      string `json:"pahole"`
	TinyGo      string `json:"tinygo"`
}

// Load reads and validates a tinybpf.json config file at the given path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %q: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config %q: %w", path, err)
	}
	if err := validate(&cfg, path); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Find walks parent directories from startDir looking for tinybpf.json.
func Find(startDir string) (string, error) {
	dir, err := filepath.Abs(startDir)
	if err != nil {
		return "", err
	}
	for {
		candidate := filepath.Join(dir, Filename)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", nil
		}
		dir = parent
	}
}

// Merge returns a new Config with file values as the base and flag values
// as overrides. Non-zero flag values take precedence over file values.
func Merge(file, flags *Config) *Config {
	out := *file

	if flags.Build.Output != "" {
		out.Build.Output = flags.Build.Output
	}
	if flags.Build.CPU != "" {
		out.Build.CPU = flags.Build.CPU
	}
	if flags.Build.OptProfile != "" {
		out.Build.OptProfile = flags.Build.OptProfile
	}
	if flags.Build.BTF != nil {
		out.Build.BTF = flags.Build.BTF
	}
	if flags.Build.Timeout != "" {
		out.Build.Timeout = flags.Build.Timeout
	}
	if len(flags.Build.Programs) > 0 {
		out.Build.Programs = flags.Build.Programs
	}
	if len(flags.Build.CustomPasses) > 0 {
		out.Build.CustomPasses = flags.Build.CustomPasses
	}

	out.Toolchain = mergeToolchain(file.Toolchain, flags.Toolchain)
	return &out
}

// ParseTimeout parses the timeout string into a time.Duration.
func ParseTimeout(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid timeout %q: %w", s, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("timeout must be positive, got %s", d)
	}
	return d, nil
}

// ResolveToolOverrides builds llvm.ToolOverrides from the Toolchain config,
// applying llvm_dir as a prefix for any tool not explicitly set.
func ResolveToolOverrides(tc Toolchain) llvm.ToolOverrides {
	resolve := func(explicit, name string) string {
		if explicit != "" {
			return explicit
		}
		if tc.LLVMDir != "" {
			return filepath.Join(tc.LLVMDir, name)
		}
		return ""
	}
	return llvm.ToolOverrides{
		LLVMLink: resolve(tc.LLVMLink, "llvm-link"),
		Opt:      resolve(tc.Opt, "opt"),
		LLC:      resolve(tc.LLC, "llc"),
		LLVMAr:   resolve(tc.LLVMAr, "llvm-ar"),
		Objcopy:  resolve(tc.LLVMObjcopy, "llvm-objcopy"),
		Pahole:   resolve(tc.Pahole, "pahole"),
	}
}

func validate(cfg *Config, path string) error {
	for i, p := range cfg.Build.CustomPasses {
		if err := llvm.ValidatePassFlag(p); err != nil {
			return fmt.Errorf("config %q: custom_passes[%d]: %w", path, i, err)
		}
	}
	if cfg.Build.Timeout != "" {
		if _, err := ParseTimeout(cfg.Build.Timeout); err != nil {
			return fmt.Errorf("config %q: %w", path, err)
		}
	}
	return nil
}

func mergeToolchain(file, flags Toolchain) Toolchain {
	out := file
	if flags.LLVMDir != "" {
		out.LLVMDir = flags.LLVMDir
	}
	if flags.LLVMLink != "" {
		out.LLVMLink = flags.LLVMLink
	}
	if flags.Opt != "" {
		out.Opt = flags.Opt
	}
	if flags.LLC != "" {
		out.LLC = flags.LLC
	}
	if flags.LLVMAr != "" {
		out.LLVMAr = flags.LLVMAr
	}
	if flags.LLVMObjcopy != "" {
		out.LLVMObjcopy = flags.LLVMObjcopy
	}
	if flags.Pahole != "" {
		out.Pahole = flags.Pahole
	}
	if flags.TinyGo != "" {
		out.TinyGo = flags.TinyGo
	}
	return out
}
