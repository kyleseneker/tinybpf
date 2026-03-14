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
	data, err := readConfigFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := decodeConfig(path, data)
	if err != nil {
		return nil, err
	}
	if err := validateConfig(path, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// readConfigFile reads the config from a file.
func readConfigFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %q: %w", path, err)
	}
	return data, nil
}

// decodeConfig decodes the config from a JSON file.
func decodeConfig(path string, data []byte) (*LinkerConfig, error) {
	var cfg LinkerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config %q: %w", path, err)
	}
	return &cfg, nil
}

// validateConfig validates the custom pass names in the config.
func validateConfig(path string, cfg *LinkerConfig) error {
	for i, p := range cfg.CustomPasses {
		if err := ValidatePassFlag(p); err != nil {
			return fmt.Errorf("config %q: custom_passes[%d]: %w", path, i, err)
		}
		cfg.CustomPasses[i] = strings.TrimSpace(p)
	}
	return nil
}
