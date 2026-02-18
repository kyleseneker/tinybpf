package llvm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantN   int
		wantErr string
	}{
		{
			name:  "valid passes",
			json:  `{"custom_passes": ["-inline", "-instcombine"]}`,
			wantN: 2,
		},
		{
			name:  "empty config",
			json:  `{}`,
			wantN: 0,
		},
		{
			name:  "trims whitespace",
			json:  `{"custom_passes": ["  -dse  "]}`,
			wantN: 1,
		},
		{
			name:  "angle-bracket params",
			json:  `{"custom_passes": ["-simplifycfg<bonus-inst-threshold=4>", "-early-cse<memssa>"]}`,
			wantN: 2,
		},
		{
			name:    "shell injection",
			json:    `{"custom_passes": ["-inline; rm -rf /"]}`,
			wantErr: "prohibited characters",
		},
		{
			name:    "path traversal",
			json:    `{"custom_passes": ["../../etc/passwd"]}`,
			wantErr: "custom_passes",
		},
		{
			name:    "empty pass",
			json:    `{"custom_passes": [""]}`,
			wantErr: "empty pass flag",
		},
		{
			name:    "backtick injection",
			json:    `{"custom_passes": ["-inline` + "`id`" + `"]}`,
			wantErr: "prohibited characters",
		},
		{
			name:    "invalid JSON",
			json:    `not json`,
			wantErr: "parsing config",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "linker-config.json")
			os.WriteFile(path, []byte(tt.json), 0o644)

			cfg, err := LoadConfig(path)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(cfg.CustomPasses) != tt.wantN {
				t.Fatalf("expected %d passes, got %d: %v", tt.wantN, len(cfg.CustomPasses), cfg.CustomPasses)
			}
		})
	}
}

func TestLoadConfigTrimmedValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "linker-config.json")
	os.WriteFile(path, []byte(`{"custom_passes": ["  -dse  "]}`), 0o644)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CustomPasses[0] != "-dse" {
		t.Fatalf("expected trimmed pass, got %q", cfg.CustomPasses[0])
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	_, err := LoadConfig("/does/not/exist/linker-config.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "reading config") {
		t.Fatalf("expected reading error, got: %v", err)
	}
}
