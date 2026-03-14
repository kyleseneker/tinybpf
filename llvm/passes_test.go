package llvm

import (
	"strings"
	"testing"
)

func TestOptProfiles(t *testing.T) {
	tests := []struct {
		name  string
		check func(t *testing.T)
	}{
		{
			name: "default pipeline is Os",
			check: func(t *testing.T) {
				t.Helper()
				if DefaultPassPipeline != "default<Os>" {
					t.Fatalf("DefaultPassPipeline should be Os for BPF, got %q", DefaultPassPipeline)
				}
			},
		},
		{
			name: "all profiles resolvable",
			check: func(t *testing.T) {
				t.Helper()
				for name, pipeline := range profiles {
					if pipeline == "" {
						t.Errorf("profile %q has empty pipeline", name)
					}
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.check(t)
		})
	}
}

func TestVerifierSafePipeline(t *testing.T) {
	tests := []struct {
		name    string
		pass    string
		present bool
	}{
		{"excludes loop-unroll", "loop-unroll", false},
		{"excludes loop-vectorize", "loop-vectorize", false},
		{"excludes slp-vectorize", "slp-vectorize", false},
		{"excludes loop-idiom", "loop-idiom", false},
		{"includes sroa", "sroa", true},
		{"includes instcombine", "instcombine", true},
		{"includes simplifycfg", "simplifycfg", true},
		{"includes gvn", "gvn", true},
		{"includes dse", "dse", true},
		{"includes adce", "adce", true},
		{"includes sccp", "sccp", true},
		{"includes mem2reg", "mem2reg", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if strings.Contains(VerifierSafePipeline, tt.pass) != tt.present {
				if tt.present {
					t.Errorf("should contain %q", tt.pass)
				} else {
					t.Errorf("should not contain %q", tt.pass)
				}
			}
		})
	}
}

func TestValidatePassFlag(t *testing.T) {
	tests := []struct {
		name    string
		pass    string
		wantErr bool
	}{
		{"valid inline", "-inline", false},
		{"valid instcombine", "instcombine", false},
		{"valid simplifycfg with params", "-simplifycfg<bonus-inst-threshold=4>", false},
		{"valid early-cse with params", "-early-cse<memssa>", false},
		{"empty", "", true},
		{"whitespace only", "   ", true},
		{"shell semicolon", "-inline;rm", true},
		{"shell pipe", "pass|cat", true},
		{"shell ampersand", "pass&bg", true},
		{"shell dollar", "pass$var", true},
		{"shell backtick", "pass`id`", true},
		{"slash", "foo/bar", true},
		{"backslash", "foo\\bar", true},
		{"numeric prefix", "123bad", true},
		{"bare dash", "-", true},
		{"leading dot", ".leading-dot", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassFlag(tt.pass)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error for %q", tt.pass)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.pass, err)
			}
		})
	}
}

func TestAppendCustomPasses(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		passes    []string
		wantFirst string
		wantLen   int
		wantErr   bool
	}{
		{
			name:    "nil passes is no-op",
			args:    []string{"-passes=default<Os>", "-S", "in.ll", "-o", "out.ll"},
			passes:  nil,
			wantLen: 5,
		},
		{
			name:      "appends to existing -passes",
			args:      []string{"-passes=default<Os>", "-S", "in.ll", "-o", "out.ll"},
			passes:    []string{"-inline", "-instcombine"},
			wantFirst: "-passes=default<Os>,function(inline,instcombine)",
			wantLen:   5,
		},
		{
			name:      "prepends when no -passes arg",
			args:      []string{"-S", "in.ll", "-o", "out.ll"},
			passes:    []string{"-dse"},
			wantFirst: "-passes=function(dse)",
			wantLen:   5,
		},
		{
			name:    "rejects invalid pass",
			args:    []string{"-passes=default<Os>"},
			passes:  []string{"-inline;rm"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AppendCustomPasses(tt.args, tt.passes)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.wantLen > 0 && len(got) != tt.wantLen {
				t.Fatalf("expected %d args, got %d: %v", tt.wantLen, len(got), got)
			}
			if tt.wantFirst != "" && got[0] != tt.wantFirst {
				t.Fatalf("got[0] = %q, want %q", got[0], tt.wantFirst)
			}
		})
	}
}

func TestResolvePassPipeline(t *testing.T) {
	tests := []struct {
		name     string
		pipeline string
		profile  string
		want     string
	}{
		{"empty defaults to Os", "", "", DefaultPassPipeline},
		{"explicit pipeline wins", "function(dce)", "aggressive", "function(dce)"},
		{"conservative profile", "", "conservative", "default<O1>"},
		{"default profile", "", "default", DefaultPassPipeline},
		{"aggressive profile", "", "aggressive", "default<O2>"},
		{"verifier-safe profile", "", "verifier-safe", VerifierSafePipeline},
		{"unknown profile defaults", "", "nonexistent", DefaultPassPipeline},
		{"case insensitive profile", "", "AGGRESSIVE", "default<O2>"},
		{"whitespace trimmed from pipeline", "  function(dce)  ", "", "function(dce)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolvePassPipeline(tt.pipeline, tt.profile)
			if got != tt.want {
				t.Errorf("resolvePassPipeline(%q, %q) = %q, want %q", tt.pipeline, tt.profile, got, tt.want)
			}
		})
	}
}

func TestBuildOptArgs(t *testing.T) {
	tests := []struct {
		name      string
		pipeline  string
		profile   string
		wantFirst string
		wantSub   string
		wantLen   int
	}{
		{
			name:      "defaults pipeline",
			wantFirst: "-passes=" + DefaultPassPipeline,
			wantLen:   5,
		},
		{
			name:    "conservative profile",
			profile: "conservative",
			wantSub: "default<O1>",
		},
		{
			name:    "default profile",
			profile: "default",
			wantSub: "default<Os>",
		},
		{
			name:    "aggressive profile",
			profile: "aggressive",
			wantSub: "default<O2>",
		},
		{
			name:    "verifier-safe profile",
			profile: "verifier-safe",
			wantSub: "function(sroa,",
		},
		{
			name:      "explicit pipeline overrides profile",
			pipeline:  "function(dce)",
			profile:   "aggressive",
			wantFirst: "-passes=function(dce)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := BuildOptArgs("in.bc", "out.ll", tt.pipeline, tt.profile)
			if tt.wantFirst != "" && args[0] != tt.wantFirst {
				t.Fatalf("args[0] = %q, want %q", args[0], tt.wantFirst)
			}
			if tt.wantSub != "" && !strings.Contains(args[0], tt.wantSub) {
				t.Fatalf("args[0] = %q, want substring %q", args[0], tt.wantSub)
			}
			if tt.wantLen > 0 && len(args) != tt.wantLen {
				t.Fatalf("arg count: got=%d want=%d", len(args), tt.wantLen)
			}
		})
	}
}
