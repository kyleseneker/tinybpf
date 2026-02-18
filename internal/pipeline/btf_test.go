package pipeline

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kyleseneker/tinybpf/internal/diag"
	"github.com/kyleseneker/tinybpf/internal/llvm"
)

func TestInjectBTF(t *testing.T) {
	tests := []struct {
		name      string
		script    string
		pahole    bool // if false, tools.Pahole is left empty
		verbose   bool
		wantErr   bool
		wantStage bool
	}{
		{
			name:   "success",
			script: "exit 0",
			pahole: true,
		},
		{
			name:    "verbose output",
			script:  "echo info >&2; exit 0",
			pahole:  true,
			verbose: true,
		},
		{
			name:      "tool failure",
			script:    "echo error >&2; exit 1",
			pahole:    true,
			wantErr:   true,
			wantStage: true,
		},
		{
			name:      "pahole not discovered",
			pahole:    false,
			wantErr:   true,
			wantStage: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp := t.TempDir()
			out := filepath.Join(tmp, "prog.o")
			os.WriteFile(out, []byte("elf-data"), 0o644)

			tools := llvm.Tools{}
			if tt.pahole {
				p := filepath.Join(tmp, "pahole")
				os.WriteFile(p, []byte("#!/bin/sh\n"+tt.script+"\n"), 0o755)
				tools.Pahole = p
			}

			var stderr bytes.Buffer
			err := injectBTF(context.Background(), Config{
				Output:  out,
				Timeout: 2 * time.Second,
				Verbose: tt.verbose,
				Stderr:  &stderr,
			}, tools)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if tt.wantStage && !diag.IsStage(err, diag.StageBTF) {
					t.Fatalf("expected BTF stage error, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.verbose && stderr.Len() == 0 {
				t.Error("expected verbose stderr output")
			}
		})
	}
}
