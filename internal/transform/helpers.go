package transform

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/kyleseneker/tinybpf/internal/diag"
)

// knownHelpers maps TinyGo-mangled BPF helper names to kernel helper IDs.
// IDs from the __BPF_FUNC_MAPPER enum in include/uapi/linux/bpf.h.
var knownHelpers = map[string]int64{
	"main.bpfMapLookupElem":          1,
	"main.bpfMapUpdateElem":          2,
	"main.bpfMapDeleteElem":          3,
	"main.bpfProbeRead":              4,
	"main.bpfKtimeGetNs":             5,
	"main.bpfTracePrintk":            6,
	"main.bpfGetPrandomU32":          7,
	"main.bpfGetSmpProcessorId":      8,
	"main.bpfSkbStoreBytes":          9,
	"main.bpfL3CsumReplace":          10,
	"main.bpfL4CsumReplace":          11,
	"main.bpfTailCall":               12,
	"main.bpfCloneRedirect":          13,
	"main.bpfGetCurrentPidTgid":      14,
	"main.bpfGetCurrentUidGid":       15,
	"main.bpfGetCurrentComm":         16,
	"main.bpfSkbVlanPush":            18,
	"main.bpfSkbVlanPop":             19,
	"main.bpfSkbGetTunnelKey":        20,
	"main.bpfSkbSetTunnelKey":        21,
	"main.bpfRedirect":               23,
	"main.bpfPerfEventOutput":        25,
	"main.bpfSkbLoadBytes":           26,
	"main.bpfCsumDiff":               28,
	"main.bpfSkbChangeProto":         31,
	"main.bpfSkbChangeType":          32,
	"main.bpfSkbUnderCgroup":         33,
	"main.bpfGetCurrentTask":         35,
	"main.bpfSkbChangeTail":          38,
	"main.bpfSkbPullData":            39,
	"main.bpfGetNumaNodeId":          42,
	"main.bpfXdpAdjustHead":          44,
	"main.bpfGetSocketCookie":        46,
	"main.bpfSetHash":                48,
	"main.bpfSetsockopt":             49,
	"main.bpfGetsockopt":             50,
	"main.bpfRedirectMap":            51,
	"main.bpfXdpAdjustMeta":          54,
	"main.bpfPerfEventReadValue":     55,
	"main.bpfXdpAdjustTail":          65,
	"main.bpfGetStack":               67,
	"main.bpfFibLookup":              69,
	"main.bpfGetCurrentCgroupId":     80,
	"main.bpfSkLookupTcp":            84,
	"main.bpfSkLookupUdp":            85,
	"main.bpfSkRelease":              86,
	"main.bpfMapPushElem":            87,
	"main.bpfMapPopElem":             88,
	"main.bpfMapPeekElem":            89,
	"main.bpfSkcLookupTcp":           99,
	"main.bpfMapLookupAndDeleteElem": 110,
	"main.bpfProbeReadUser":          112,
	"main.bpfProbeReadKernel":        113,
	"main.bpfProbeReadUserStr":       114,
	"main.bpfProbeReadKernelStr":     115,
	"main.bpfKtimeGetBootNs":         125,
	"main.bpfRingbufOutput":          130,
	"main.bpfRingbufReserve":         131,
	"main.bpfRingbufSubmit":          132,
	"main.bpfRingbufDiscard":         133,
	"main.bpfRingbufQuery":           134,
	"main.bpfGetCurrentTaskBtf":      158,
	"main.bpfKtimeGetCoarseNs":       160,
	"main.bpfSnprintf":               165,
	"main.bpfTaskStorageGet":         169,
	"main.bpfTaskStorageDelete":      170,
	"main.bpfGetFuncIp":              173,
	"main.bpfGetAttachCookie":        174,
	"main.bpfCsumLevel":              183,
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
			snippet := irSnippet(lines, i, 2)
			return nil, &diag.Error{
				Stage:     diag.StageTransform,
				Err:       fmt.Errorf("unknown BPF helper %q", funcName),
				IRLine:    i + 1,
				IRSnippet: snippet,
				Hint:      "add this helper to knownHelpers in internal/transform/helpers.go, or check spelling",
			}
		}

		args := strings.TrimSpace(line[loc[6]:loc[7]])
		args = stripTrailingUndef(args)

		replacement := fmt.Sprintf("call %s inttoptr (i64 %d to ptr)(%s)", retType, helperID, args)
		lines[i] = line[:loc[0]] + replacement + line[loc[1]:]
	}
	return lines, nil
}

// irSnippet returns up to `radius` lines before and after index `center` for error context.
func irSnippet(lines []string, center, radius int) string {
	start := center - radius
	if start < 0 {
		start = 0
	}
	end := center + radius + 1
	if end > len(lines) {
		end = len(lines)
	}
	var b strings.Builder
	for i := start; i < end; i++ {
		marker := "  "
		if i == center {
			marker = "> "
		}
		fmt.Fprintf(&b, "%s%d: %s\n", marker, i+1, lines[i])
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
