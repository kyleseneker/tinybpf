package transform

import (
	"fmt"
	"regexp"
	"strings"
)

// knownHelpers maps TinyGo-mangled BPF helper names to kernel helper IDs.
var knownHelpers = map[string]int64{
	"main.bpfMapLookupElem":      1,
	"main.bpfMapUpdateElem":      2,
	"main.bpfMapDeleteElem":      3,
	"main.bpfKtimeGetNs":         5,
	"main.bpfTracePrintk":        6,
	"main.bpfGetSmpProcessorId":  8,
	"main.bpfSkbStoreBytes":      9,
	"main.bpfL3CsumReplace":      10,
	"main.bpfL4CsumReplace":      11,
	"main.bpfTailCall":           12,
	"main.bpfGetCurrentPidTgid":  14,
	"main.bpfGetCurrentComm":     16,
	"main.bpfRedirect":           23,
	"main.bpfPerfEventOutput":    25,
	"main.bpfSkbLoadBytes":       26,
	"main.bpfGetCurrentTask":     35,
	"main.bpfGetNumaNodeId":      42,
	"main.bpfXdpAdjustHead":      44,
	"main.bpfGetSocketCookie":    46,
	"main.bpfRedirectMap":        51,
	"main.bpfPerfEventReadValue": 55,
	"main.bpfXdpAdjustTail":      65,
	"main.bpfGetStack":           67,
	"main.bpfFibLookup":          69,
	"main.bpfGetCurrentCgroupId": 80,
	"main.bpfSkLookupTcp":        84,
	"main.bpfSkLookupUdp":        85,
	"main.bpfMapPushElem":        87,
	"main.bpfMapPopElem":         88,
	"main.bpfMapPeekElem":        89,
	"main.bpfProbeReadUser":      112,
	"main.bpfProbeReadKernel":    113,
	"main.bpfProbeReadKernelStr": 115,
	"main.bpfKtimeGetBootNs":     125,
	"main.bpfRingbufOutput":      130,
	"main.bpfRingbufReserve":     131,
	"main.bpfRingbufSubmit":      132,
	"main.bpfRingbufDiscard":     133,
	"main.bpfRingbufQuery":       134,
	"main.bpfGetCurrentTaskBtf":  158,
	"main.bpfGetFuncIp":          173,
	"main.bpfGetAttachCookie":    174,
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
		helperID, ok := knownHelpers[funcName]
		if !ok {
			return nil, fmt.Errorf(
				"unknown BPF helper %q; add it to knownHelpers or check spelling",
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
