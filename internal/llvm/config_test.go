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
		noFile  bool
		wantN   int
		wantErr string
		check   func(t *testing.T, cfg *LinkerConfig)
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
			check: func(t *testing.T, cfg *LinkerConfig) {
				t.Helper()
				if cfg.CustomPasses[0] != "-dse" {
					t.Fatalf("expected trimmed pass, got %q", cfg.CustomPasses[0])
				}
			},
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
		{
			name:    "missing file",
			noFile:  true,
			wantErr: "reading config",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var path string
			if tt.noFile {
				path = "/does/not/exist/linker-config.json"
			} else {
				path = filepath.Join(t.TempDir(), "linker-config.json")
				os.WriteFile(path, []byte(tt.json), 0o644)
			}

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
			if tt.check != nil {
				tt.check(t, cfg)
			}
		})
	}
}

func TestDecodeConfig(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantN   int
		wantErr bool
	}{
		{"valid object", `{"custom_passes":["a"]}`, 1, false},
		{"empty object", `{}`, 0, false},
		{"invalid json", `{bad`, 0, true},
		{"null passes", `{"custom_passes":null}`, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := decodeConfig("test.json", []byte(tt.data))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(cfg.CustomPasses) != tt.wantN {
				t.Fatalf("expected %d passes, got %d", tt.wantN, len(cfg.CustomPasses))
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		passes  []string
		wantErr bool
	}{
		{"valid passes", []string{"-inline", "-dse"}, false},
		{"empty list", nil, false},
		{"rejects injection", []string{"-inline;rm"}, true},
		{"rejects empty pass", []string{""}, true},
		{"trims whitespace", []string{"  -dse  "}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &LinkerConfig{CustomPasses: tt.passes}
			err := validateConfig("test.json", cfg)
			if tt.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
