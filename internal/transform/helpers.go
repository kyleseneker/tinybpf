package transform

import (
	"fmt"
	"regexp"
	"strings"
)

// KnownHelpers maps TinyGo-mangled BPF helper names to kernel helper IDs.
var KnownHelpers = map[string]int64{
	"main.bpfMapLookupElem":     1,
	"main.bpfMapUpdateElem":     2,
	"main.bpfMapDeleteElem":     3,
	"main.bpfKtimeGetNs":        5,
	"main.bpfTracePrintk":       6,
	"main.bpfGetCurrentPidTgid": 14,
	"main.bpfGetCurrentComm":    16,
	"main.bpfPerfEventOutput":   25,
	"main.bpfProbeReadUser":     112,
	"main.bpfRingbufOutput":     130,
}

var reHelperCall = regexp.MustCompile(
	`call\s+(\w+)\s+@(main\.bpf\w+)\(([^)]*)\)`,
)

// rewriteHelpers replaces TinyGo-mangled @main.bpfXxx calls with
// inttoptr (i64 HELPER_ID to ptr) BPF helper invocations and strips
// the trailing TinyGo context pointer argument.
func rewriteHelpers(lines []string) ([]string, error) {
	for i, line := range lines {
		if !strings.Contains(line, "@main.bpf") {
			continue
		}
		loc := reHelperCall.FindStringSubmatchIndex(line)
		if loc == nil {
			continue
		}

		retType := line[loc[2]:loc[3]]
		funcName := line[loc[4]:loc[5]]
		helperID, ok := KnownHelpers[funcName]
		if !ok {
			return nil, fmt.Errorf(
				"transform: unknown BPF helper %q; add it to KnownHelpers or check spelling",
				funcName)
		}

		args := strings.TrimSpace(line[loc[6]:loc[7]])
		args = stripTrailingUndef(args)

		replacement := fmt.Sprintf("call %s inttoptr (i64 %d to ptr)(%s)", retType, helperID, args)
		lines[i] = line[:loc[0]] + replacement + line[loc[1]:]
	}
	return lines, nil
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
