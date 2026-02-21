package llvm

import (
	"fmt"
	"regexp"
	"strings"
)

// DefaultPassPipeline uses Os (optimize for size). Os applies GVN,
// instcombine, SROA, simplifycfg, and DSE like O2, but avoids aggressive
// inlining and unrolling that can exceed BPF verifier instruction limits.
const DefaultPassPipeline = "default<Os>"

// VerifierSafePipeline includes only passes known to benefit BPF verifier
// compliance. It excludes loop unrolling, vectorization, and loop idiom
// recognition. Use when a program fails the verifier with the default profile.
const VerifierSafePipeline = "function(" +
	"sroa," +
	"early-cse<memssa>," +
	"instcombine," +
	"simplifycfg<bonus-inst-threshold=4>," +
	"gvn," +
	"dse," +
	"mem2reg," +
	"adce," +
	"sccp," +
	"instcombine," +
	"simplifycfg<bonus-inst-threshold=4>," +
	"adce)"

// profiles maps named optimization profiles to LLVM pass pipeline strings.
//
// Profiled against network-sidecar kprobe IR:
//
//	conservative=37 insns, default=36, aggressive=36, verifier-safe=36
var profiles = map[string]string{
	"conservative":  "default<O1>",
	"default":       DefaultPassPipeline,
	"aggressive":    "default<O2>",
	"verifier-safe": VerifierSafePipeline,
}

// validPassName matches safe LLVM pass identifiers.
var validPassName = regexp.MustCompile(`^-?[a-zA-Z][a-zA-Z0-9-]*(<[a-zA-Z0-9=,;-]*>)?$`)

// ValidatePassFlag checks that a pass string is safe for use as an LLVM opt
// argument.
func ValidatePassFlag(pass string) error {
	cleaned := strings.TrimSpace(pass)
	if cleaned == "" {
		return fmt.Errorf("empty pass flag")
	}
	if strings.ContainsAny(cleaned, "/\\$`|;&(){}[]!~") {
		return fmt.Errorf("pass flag %q contains prohibited characters", cleaned)
	}
	if !validPassName.MatchString(cleaned) {
		return fmt.Errorf("pass flag %q does not match allowed pattern %s", cleaned, validPassName.String())
	}
	return nil
}

// AppendCustomPasses validates and appends user-provided pass names to an
// existing opt argument list.
func AppendCustomPasses(args []string, passes []string) ([]string, error) {
	if len(passes) == 0 {
		return args, nil
	}
	names := make([]string, 0, len(passes))
	for _, p := range passes {
		if err := ValidatePassFlag(p); err != nil {
			return nil, err
		}
		names = append(names, strings.TrimLeft(strings.TrimSpace(p), "-"))
	}
	fragment := "function(" + strings.Join(names, ",") + ")"

	result := make([]string, len(args))
	copy(result, args)
	for i, arg := range result {
		if strings.HasPrefix(arg, "-passes=") {
			result[i] = arg + "," + fragment
			return result, nil
		}
	}
	// No -passes= found; prepend one.
	return append([]string{"-passes=" + fragment}, result...), nil
}

// resolvePassPipeline determines the LLVM pass pipeline string from an
// explicit pipeline or named profile.
func resolvePassPipeline(passPipeline, profile string) string {
	pipeline := strings.TrimSpace(passPipeline)
	if pipeline == "" {
		if p, ok := profiles[strings.ToLower(strings.TrimSpace(profile))]; ok {
			pipeline = p
		}
	}
	if pipeline == "" {
		pipeline = DefaultPassPipeline
	}
	return pipeline
}

// BuildOptArgs constructs the argument list for the LLVM opt tool.
func BuildOptArgs(inputPath, outputPath, passPipeline, profile string) []string {
	pipeline := resolvePassPipeline(passPipeline, profile)
	return []string{
		"-passes=" + pipeline,
		"-S",
		inputPath,
		"-o",
		outputPath,
	}
}
