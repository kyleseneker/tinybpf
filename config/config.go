// Package config loads tinybpf project configuration from a tinybpf.json
// file and converts it to [github.com/kyleseneker/tinybpf.Request] values.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kyleseneker/tinybpf/internal/llvm"
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
	Cache        *bool             `json:"cache"`
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

// validate checks that all config values are well-formed.
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
