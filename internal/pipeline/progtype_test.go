package pipeline

import (
	"strings"
	"testing"
)

func TestValidateProgramType(t *testing.T) {
	tests := []struct {
		name        string
		programType string
		sections    map[string]string
		wantErr     string
	}{
		{
			"empty type skips validation",
			"",
			map[string]string{"prog": "kprobe/do_sys_openat2"},
			"",
		},
		{
			"matching kprobe",
			"kprobe",
			map[string]string{"prog": "kprobe/do_sys_openat2"},
			"",
		},
		{
			"matching xdp",
			"xdp",
			map[string]string{"prog": "xdp"},
			"",
		},
		{
			"matching tracepoint",
			"tracepoint",
			map[string]string{"prog": "tracepoint/syscalls/sys_enter_connect"},
			"",
		},
		{
			"matching cgroup/connect4",
			"cgroup/connect4",
			map[string]string{"check": "cgroup/connect4"},
			"",
		},
		{
			"matching fentry",
			"fentry",
			map[string]string{"trace": "fentry/do_sys_openat2"},
			"",
		},
		{
			"matching classifier",
			"classifier",
			map[string]string{"cls": "classifier/ingress"},
			"",
		},
		{
			"mismatched type",
			"xdp",
			map[string]string{"prog": "kprobe/do_sys_openat2"},
			"does not match",
		},
		{
			"unknown program type",
			"bogus",
			map[string]string{"prog": "bogus/foo"},
			"unknown --program-type",
		},
		{
			"nil sections with valid type",
			"xdp",
			nil,
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProgramType(tt.programType, tt.sections)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected %q in error, got: %v", tt.wantErr, err)
			}
		})
	}
}
