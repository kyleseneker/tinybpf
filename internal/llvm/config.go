package llvm

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// LinkerConfig holds optional tool configuration loaded from a JSON file.
type LinkerConfig struct {
	CustomPasses []string `json:"custom_passes"`
}

// LoadConfig reads, parses, and validates a linker configuration JSON file.
func LoadConfig(path string) (*LinkerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %q: %w", path, err)
	}

	var cfg LinkerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config %q: %w", path, err)
	}

	for i, p := range cfg.CustomPasses {
		if err := ValidatePassFlag(p); err != nil {
			return nil, fmt.Errorf("config %q: custom_passes[%d]: %w", path, i, err)
		}
		cfg.CustomPasses[i] = strings.TrimSpace(p)
	}

	return &cfg, nil
}
