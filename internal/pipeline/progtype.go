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
	"iter/":                 "Iterator",
	"struct_ops/":           "Struct ops",
	"lsm/":                  "LSM",
	"lsm.s/":                "LSM sleepable",
	"syscall":               "Syscall",
}

// ValidateProgramType checks whether a section name matches a known BPF
// program type prefix. Returns nil if no program-type validation is
// requested (programType is empty).
func ValidateProgramType(programType string, sections map[string]string) error {
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

func isKnownType(pt string) bool {
	for prefix := range knownProgramTypes {
		if pt == strings.TrimSuffix(prefix, "/") {
			return true
		}
	}
	return false
}

func matchesProgramType(section, programType string) bool {
	return section == programType || strings.HasPrefix(section, programType+"/")
}

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
