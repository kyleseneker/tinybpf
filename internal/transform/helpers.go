package transform

//go:generate go run gen.go

import (
	"strings"
)

// helperIDs maps TinyGo-style BPF helper names (e.g. "main.bpfMapLookupElem") to kernel helper IDs.
var helperIDs map[string]int64

// init populates helperIDs by converting kernel snake_case names to Go camelCase.
func init() {
	helperIDs = make(map[string]int64, len(bpfHelperNames))
	for id, name := range bpfHelperNames {
		if name == "" {
			continue
		}
		helperIDs["main."+snakeToCamel("bpf_"+name)] = int64(id)
	}
}

// snakeToCamel converts "bpf_map_lookup_elem" to "bpfMapLookupElem".
func snakeToCamel(s string) string {
	parts := strings.Split(s, "_")
	var b strings.Builder
	b.Grow(len(s))
	b.WriteString(parts[0])
	for _, p := range parts[1:] {
		if p == "" {
			continue
		}
		b.WriteByte(p[0] - 'a' + 'A')
		b.WriteString(p[1:])
	}
	return b.String()
}

// stripTrailingUndef removes the TinyGo context pointer from a helper argument list.
func stripTrailingUndef(args string) string {
	if args == "ptr undef" {
		return ""
	}
	if idx := strings.LastIndex(args, ", ptr undef"); idx >= 0 {
		return args[:idx]
	}
	return args
}
