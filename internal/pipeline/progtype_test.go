package pipeline

import (
	"strings"
	"testing"
)

func TestInferProgramType(t *testing.T) {
	tests := []struct {
		name     string
		sections map[string]string
		want     string
		wantErr  string
	}{
		{
			"empty sections",
			nil,
			"",
			"",
		},
		{
			"single kprobe section",
			map[string]string{"prog": "kprobe/do_sys_openat2"},
			"kprobe",
			"",
		},
		{
			"single xdp section",
			map[string]string{"prog": "xdp"},
			"xdp",
			"",
		},
		{
			"multiple sections same type",
			map[string]string{
				"entry":  "kprobe/do_sys_openat2",
				"return": "kretprobe/do_sys_openat2",
			},
			"",
			"conflicting program types",
		},
		{
			"multiple kprobe sections agree",
			map[string]string{
				"open":  "kprobe/do_sys_openat2",
				"close": "kprobe/do_sys_close",
			},
			"kprobe",
			"",
		},
		{
			"tracepoint section",
			map[string]string{"prog": "tracepoint/syscalls/sys_enter_connect"},
			"tracepoint",
			"",
		},
		{
			"lsm section",
			map[string]string{"check": "lsm/bprm_check_security"},
			"lsm",
			"",
		},
		{
			"lsm sleepable section",
			map[string]string{"check": "lsm.s/bprm_check_security"},
			"lsm.s",
			"",
		},
		{
			"fentry section",
			map[string]string{"trace": "fentry/do_sys_openat2"},
			"fentry",
			"",
		},
		{
			"unknown section name returns empty",
			map[string]string{"prog": "custom_section"},
			"",
			"",
		},
		{
			"cgroup connect section",
			map[string]string{"check": "cgroup/connect4"},
			"cgroup/connect4",
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := InferProgramType(tt.sections)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected %q in error, got: %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("InferProgramType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestProgramTypeFromSection(t *testing.T) {
	tests := []struct {
		section string
		want    string
	}{
		{"kprobe/do_sys_openat2", "kprobe"},
		{"kretprobe/do_sys_openat2", "kretprobe"},
		{"tracepoint/syscalls/sys_enter_connect", "tracepoint"},
		{"xdp", "xdp"},
		{"tc", "tc"},
		{"lsm/bprm_check_security", "lsm"},
		{"lsm.s/bprm_check_security", "lsm.s"},
		{"fentry/do_sys_openat2", "fentry"},
		{"cgroup/connect4", "cgroup/connect4"},
		{"classifier/ingress", "classifier"},
		{"unknown_thing", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.section, func(t *testing.T) {
			if got := programTypeFromSection(tt.section); got != tt.want {
				t.Errorf("programTypeFromSection(%q) = %q, want %q", tt.section, got, tt.want)
			}
		})
	}
}

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
			"matching lsm",
			"lsm",
			map[string]string{"check": "lsm/bprm_check_security"},
			"",
		},
		{
			"matching lsm sleepable",
			"lsm.s",
			map[string]string{"check": "lsm.s/bprm_check_security"},
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
