package pipeline

import (
	"fmt"
	"strings"
)

// knownProgramTypes maps BPF program type prefixes to their descriptions.
var knownProgramTypes = map[string]string{
	"socket":                "Socket filter",
	"kprobe/":               "Kprobe",
	"kretprobe/":            "Kretprobe",
	"tracepoint/":           "Tracepoint",
	"raw_tracepoint/":       "Raw tracepoint",
	"xdp":                   "XDP",
	"perf_event":            "Perf event",
	"cgroup/skb":            "Cgroup SKB",
	"cgroup/sock":           "Cgroup sock",
	"cgroup/dev":            "Cgroup device",
	"cgroup/connect4":       "Cgroup connect4",
	"cgroup/connect6":       "Cgroup connect6",
	"cgroup/bind4":          "Cgroup bind4",
	"cgroup/bind6":          "Cgroup bind6",
	"cgroup/sendmsg4":       "Cgroup sendmsg4",
	"cgroup/sendmsg6":       "Cgroup sendmsg6",
	"cgroup/post_bind4":     "Cgroup post-bind4",
	"cgroup/post_bind6":     "Cgroup post-bind6",
	"cgroup/sysctl":         "Cgroup sysctl",
	"cgroup/getsockopt":     "Cgroup getsockopt",
	"cgroup/setsockopt":     "Cgroup setsockopt",
	"classifier/":           "TC classifier",
	"tc":                    "TC",
	"action/":               "TC action",
	"lwt_in":                "LWT in",
	"lwt_out":               "LWT out",
	"lwt_xmit":              "LWT xmit",
	"lwt_seg6local":         "LWT seg6local",
	"sockops":               "Sock ops",
	"sk_skb/stream_parser":  "SK SKB stream parser",
	"sk_skb/stream_verdict": "SK SKB stream verdict",
	"sk_msg":                "SK msg",
	"sk_lookup":             "SK lookup",
	"fentry/":               "Fentry",
	"fexit/":                "Fexit",
	"fmod_ret/":             "Fmod ret",
	"freplace/":             "Freplace",
	"lsm/":                  "LSM",
	"lsm.s/":                "LSM sleepable",
	"syscall":               "Syscall",
}

// InferProgramType returns the BPF program type common to all section names,
// or "" if sections is empty or section names don't map to a known type.
// Returns an error if sections map to conflicting program types.
func InferProgramType(sections map[string]string) (string, error) {
	if len(sections) == 0 {
		return "", nil
	}
	inferred := ""
	for fn, section := range sections {
		pt := programTypeFromSection(section)
		if pt == "" {
			continue
		}
		if inferred == "" {
			inferred = pt
		} else if inferred != pt {
			return "", fmt.Errorf("sections have conflicting program types: %q is %q but %q is %q",
				fn, pt, inferredSource(sections, inferred), inferred)
		}
	}
	return inferred, nil
}

// programTypeFromSection extracts the BPF program type from a section name
// by matching against known type prefixes (e.g. "kprobe/sys_open" -> "kprobe").
func programTypeFromSection(section string) string {
	for prefix := range knownProgramTypes {
		name := strings.TrimSuffix(prefix, "/")
		if section == name || strings.HasPrefix(section, name+"/") {
			return name
		}
	}
	return ""
}

// inferredSource returns the function name of the first section that matches the given program type.
func inferredSource(sections map[string]string, pt string) string {
	for fn, section := range sections {
		if programTypeFromSection(section) == pt {
			return fn
		}
	}
	return ""
}

// unsupportedProgramTypes maps prefixes of BPF program types that tinybpf
// intentionally does not support to a short reason. They are rejected with an
// explicit error so users know the boundary rather than hitting an obscure
// failure later. Iterator programs depend on iterator-specific context struct
// handling and kfunc sequencing that tinybpf does not implement.
var unsupportedProgramTypes = map[string]string{
	"iter/": "iterator programs are not supported by tinybpf (require iterator-specific context handling and bpf_iter_* kfunc sequencing)",
}

// ValidateProgramType checks that all section names match the given BPF program type prefix.
func ValidateProgramType(programType string, sections map[string]string) error {
	if reason, ok := unsupportedProgramTypeReason(programType); ok {
		return fmt.Errorf("--program-type %q: %s", programType, reason)
	}
	for fn, section := range sections {
		if reason, ok := unsupportedProgramTypeReason(section); ok {
			return fmt.Errorf("section %q for program %q: %s", section, fn, reason)
		}
	}

	if programType == "" {
		return nil
	}

	if !isKnownType(programType) {
		return fmt.Errorf("unknown --program-type %q; known types: %s",
			programType, knownTypeList())
	}

	for fn, section := range sections {
		if !matchesProgramType(section, programType) {
			return fmt.Errorf("section %q for program %q does not match --program-type %q",
				section, fn, programType)
		}
	}
	return nil
}

// unsupportedProgramTypeReason reports whether s is an intentionally
// unsupported BPF program type (or a section for one), returning a
// user-facing reason.
func unsupportedProgramTypeReason(s string) (string, bool) {
	for prefix, reason := range unsupportedProgramTypes {
		bare := strings.TrimSuffix(prefix, "/")
		if s == bare || strings.HasPrefix(s, prefix) {
			return reason, true
		}
	}
	return "", false
}

// isKnownType reports whether pt matches a recognized BPF program type.
func isKnownType(pt string) bool {
	for prefix := range knownProgramTypes {
		if pt == strings.TrimSuffix(prefix, "/") {
			return true
		}
	}
	return false
}

// matchesProgramType reports whether section matches or is a child of programType.
func matchesProgramType(section, programType string) bool {
	return section == programType || strings.HasPrefix(section, programType+"/")
}

// knownTypeList returns a comma-separated list of all recognized program types.
func knownTypeList() string {
	seen := make(map[string]bool)
	var types []string
	for prefix := range knownProgramTypes {
		name := strings.TrimSuffix(prefix, "/")
		if !seen[name] {
			seen[name] = true
			types = append(types, name)
		}
	}
	return strings.Join(types, ", ")
}
