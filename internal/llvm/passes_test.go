package llvm

import (
	"strings"
	"testing"
)

func TestBuildOptArgsDefaultsPipeline(t *testing.T) {
	args := BuildOptArgs("in.bc", "out.ll", "", "")
	want := []string{"-passes=" + DefaultPassPipeline, "-S", "in.bc", "-o", "out.ll"}
	if len(args) != len(want) {
		t.Fatalf("arg count: got=%d want=%d", len(args), len(want))
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args[%d]: got=%q want=%q", i, args[i], want[i])
		}
	}
}

func TestBuildOptArgsUsesProfile(t *testing.T) {
	tests := []struct {
		profile string
		wantSub string
	}{
		{"conservative", "default<O1>"},
		{"default", "default<Os>"},
		{"aggressive", "default<O2>"},
		{"verifier-safe", "function(sroa,"},
	}
	for _, tt := range tests {
		t.Run(tt.profile, func(t *testing.T) {
			args := BuildOptArgs("in.bc", "out.ll", "", tt.profile)
			if !strings.Contains(args[0], tt.wantSub) {
				t.Fatalf("got %q, want substring %q", args[0], tt.wantSub)
			}
		})
	}
}

func TestBuildOptArgsExplicitPipelineOverridesProfile(t *testing.T) {
	args := BuildOptArgs("in.bc", "out.ll", "function(dce)", "aggressive")
	if args[0] != "-passes=function(dce)" {
		t.Fatalf("explicit pipeline not used: got %q", args[0])
	}
}

func TestDefaultPipelineIsOs(t *testing.T) {
	if DefaultPassPipeline != "default<Os>" {
		t.Fatalf("DefaultPassPipeline should be Os for BPF, got %q", DefaultPassPipeline)
	}
}

func TestAllProfilesResolvable(t *testing.T) {
	for name, pipeline := range profiles {
		if pipeline == "" {
			t.Errorf("profile %q has empty pipeline", name)
		}
	}
}

func TestVerifierSafePipeline(t *testing.T) {
	t.Run("excludes harmful passes", func(t *testing.T) {
		for _, pass := range []string{"loop-unroll", "loop-vectorize", "slp-vectorize", "loop-idiom"} {
			if strings.Contains(VerifierSafePipeline, pass) {
				t.Errorf("should not contain %q", pass)
			}
		}
	})
	t.Run("includes beneficial passes", func(t *testing.T) {
		for _, pass := range []string{"sroa", "instcombine", "simplifycfg", "gvn", "dse", "adce", "sccp", "mem2reg"} {
			if !strings.Contains(VerifierSafePipeline, pass) {
				t.Errorf("should contain %q", pass)
			}
		}
	})
}

func TestValidatePassFlag(t *testing.T) {
	valid := []string{
		"-inline", "instcombine",
		"-simplifycfg<bonus-inst-threshold=4>", "-early-cse<memssa>",
	}
	for _, p := range valid {
		t.Run("valid/"+p, func(t *testing.T) {
			if err := ValidatePassFlag(p); err != nil {
				t.Fatalf("expected valid: %v", err)
			}
		})
	}

	invalid := []struct {
		name, pass string
	}{
		{"empty", ""},
		{"whitespace-only", "   "},
		{"shell-semicolon", "-inline;rm"},
		{"shell-pipe", "pass|cat"},
		{"shell-ampersand", "pass&bg"},
		{"shell-dollar", "pass$var"},
		{"shell-backtick", "pass`id`"},
		{"slash", "foo/bar"},
		{"backslash", "foo\\bar"},
		{"numeric-prefix", "123bad"},
		{"bare-dash", "-"},
		{"leading-dot", ".leading-dot"},
	}
	for _, tt := range invalid {
		t.Run("invalid/"+tt.name, func(t *testing.T) {
			if err := ValidatePassFlag(tt.pass); err == nil {
				t.Fatalf("expected error for %q", tt.pass)
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
