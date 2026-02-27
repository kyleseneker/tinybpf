package transform

import (
	"fmt"
	"strings"
	"testing"
)

func FuzzRewriteHelpers(f *testing.F) {
	f.Add(`  %1 = call i64 @main.bpfGetCurrentPidTgid(ptr undef) #7`)
	f.Add(`  %2 = call i64 @main.bpfProbeReadUser(ptr nonnull %buf, i32 16, ptr %src, ptr undef) #7`)
	f.Add(`  %1 = call ptr @main.bpfMapLookupElem(ptr %map, ptr %key, ptr undef) #7`)
	f.Add(`  call void @main.bpfTailCall(ptr %ctx, ptr %map, i32 %idx, ptr undef) #7`)
	f.Add(`  no bpf call here, just a normal line`)
	f.Add(`  call i64 @main.bpf`)
	f.Add(`  call i64 @main.bpfUnclosed(`)

	f.Fuzz(func(t *testing.T, line string) {
		if len(line) > 1<<16 {
			return
		}
		lines := strings.Split(line, "\n")
		rewriteHelpers(lines)
	})
}

func TestRewriteHelpers(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      string
		unchanged bool
	}{
		{name: "context-only arg stripped",
			input: `  %1 = call i64 @main.bpfGetCurrentPidTgid(ptr undef) #7`,
			want:  "call i64 inttoptr (i64 14 to ptr)()"},
		{name: "trailing undef stripped with real args",
			input: `  %1 = call i64 @main.bpfProbeReadUser(ptr nonnull %buf, i32 16, ptr %src, ptr undef) #7`,
			want:  "call i64 inttoptr (i64 112 to ptr)(ptr nonnull %buf, i32 16, ptr %src)"},
		{name: "ptr return type",
			input: `  %1 = call ptr @main.bpfMapLookupElem(ptr %map, ptr %key, ptr undef) #7`,
			want:  "call ptr inttoptr (i64 1 to ptr)(ptr %map, ptr %key)"},
		{name: "i32 return type",
			input: `  %1 = call i32 @main.bpfMapDeleteElem(ptr %map, ptr %key, ptr undef) #7`,
			want:  "call i32 inttoptr (i64 3 to ptr)(ptr %map, ptr %key)"},
		{name: "void return type",
			input: `  call void @main.bpfRingbufSubmit(ptr %1, i64 0, ptr undef) #7`,
			want:  "call void inttoptr (i64 132 to ptr)(ptr %1, i64 0)"},
		{name: "multi-arg networking helper",
			input: `  %1 = call i64 @main.bpfSkbStoreBytes(ptr %skb, i32 %off, ptr %from, i32 %len, i64 0, ptr undef) #7`,
			want:  "inttoptr (i64 9 to ptr)"},
		{name: "ringbuf reserve",
			input: `  %1 = call ptr @main.bpfRingbufReserve(ptr @main.events, i64 16, i64 0, ptr undef) #7`,
			want:  "inttoptr (i64 131 to ptr)"},
		{name: "generic probe read",
			input: `  %1 = call i64 @main.bpfProbeRead(ptr %dst, i32 16, ptr %src, ptr undef) #7`,
			want:  "inttoptr (i64 4 to ptr)"},
		{name: "get prandom u32",
			input: `  %1 = call i32 @main.bpfGetPrandomU32(ptr undef) #7`,
			want:  "inttoptr (i64 7 to ptr)"},
		{name: "get current uid gid",
			input: `  %1 = call i64 @main.bpfGetCurrentUidGid(ptr undef) #7`,
			want:  "inttoptr (i64 15 to ptr)"},
		{name: "xdp adjust meta",
			input: `  %1 = call i32 @main.bpfXdpAdjustMeta(ptr %ctx, i32 %delta, ptr undef) #7`,
			want:  "inttoptr (i64 54 to ptr)"},
		{name: "sk release",
			input: `  call void @main.bpfSkRelease(ptr %sk, ptr undef) #7`,
			want:  "inttoptr (i64 86 to ptr)"},
		{name: "spin lock",
			input: `  call void @main.bpfSpinLock(ptr %lock, ptr undef) #7`,
			want:  "inttoptr (i64 93 to ptr)"},
		{name: "spin unlock",
			input: `  call void @main.bpfSpinUnlock(ptr %lock, ptr undef) #7`,
			want:  "inttoptr (i64 94 to ptr)"},
		{name: "probe read str",
			input: `  %1 = call i64 @main.bpfProbeReadStr(ptr %dst, i32 256, ptr %src, ptr undef) #7`,
			want:  "inttoptr (i64 45 to ptr)"},
		{name: "probe read user str",
			input: `  %1 = call i64 @main.bpfProbeReadUserStr(ptr %dst, i32 256, ptr %src, ptr undef) #7`,
			want:  "inttoptr (i64 114 to ptr)"},
		{name: "ktime get coarse ns",
			input: `  %1 = call i64 @main.bpfKtimeGetCoarseNs(ptr undef) #7`,
			want:  "inttoptr (i64 160 to ptr)"},
		{name: "task storage get",
			input: `  %1 = call ptr @main.bpfTaskStorageGet(ptr %map, ptr %task, ptr %value, i64 0, ptr undef) #7`,
			want:  "inttoptr (i64 156 to ptr)"},
		{name: "timer init",
			input: `  %1 = call i64 @main.bpfTimerInit(ptr %timer, ptr %map, i64 0, ptr undef) #7`,
			want:  "inttoptr (i64 169 to ptr)"},
		{name: "dynptr read",
			input: `  %1 = call i64 @main.bpfDynptrRead(ptr %dst, i32 16, ptr %dynptr, i32 0, i64 0, ptr undef) #7`,
			want:  "inttoptr (i64 201 to ptr)"},
		{name: "loop",
			input: `  %1 = call i64 @main.bpfLoop(i32 100, ptr %cb, ptr %ctx, i64 0, ptr undef) #7`,
			want:  "inttoptr (i64 181 to ptr)"},
		{name: "send signal",
			input: `  %1 = call i64 @main.bpfSendSignal(i32 9, ptr undef) #7`,
			want:  "inttoptr (i64 109 to ptr)"},
		{name: "csum level",
			input: `  %1 = call i64 @main.bpfCsumLevel(ptr %skb, i64 0, ptr undef) #7`,
			want:  "inttoptr (i64 135 to ptr)"},
		{name: "redirect neigh",
			input: `  %1 = call i64 @main.bpfRedirectNeigh(i32 %ifindex, ptr %params, i32 0, i64 0, ptr undef) #7`,
			want:  "inttoptr (i64 152 to ptr)"},
		{name: "clone redirect",
			input: `  %1 = call i64 @main.bpfCloneRedirect(ptr %skb, i32 %ifindex, i64 0, ptr undef) #7`,
			want:  "inttoptr (i64 13 to ptr)"},
		{name: "csum diff",
			input: `  %1 = call i64 @main.bpfCsumDiff(ptr %from, i32 0, ptr %to, i32 0, i32 0, ptr undef) #7`,
			want:  "inttoptr (i64 28 to ptr)"},
		{name: "snprintf",
			input: `  %1 = call i64 @main.bpfSnprintf(ptr %buf, i32 256, ptr %fmt, ptr %data, i32 1, ptr undef) #7`,
			want:  "inttoptr (i64 165 to ptr)"},
		{name: "perf event read",
			input: `  %1 = call i64 @main.bpfPerfEventRead(ptr %map, i64 %flags, ptr undef) #7`,
			want:  "inttoptr (i64 22 to ptr)"},
		{name: "override return",
			input: `  %1 = call i64 @main.bpfOverrideReturn(ptr %ctx, i64 %rc, ptr undef) #7`,
			want:  "inttoptr (i64 58 to ptr)"},
		{name: "seq printf",
			input: `  %1 = call i64 @main.bpfSeqPrintf(ptr %seq, ptr %fmt, i32 %len, ptr %data, i32 %cnt, ptr undef) #7`,
			want:  "inttoptr (i64 126 to ptr)"},
		{name: "inode storage get",
			input: `  %1 = call ptr @main.bpfInodeStorageGet(ptr %map, ptr %inode, ptr %value, i64 0, ptr undef) #7`,
			want:  "inttoptr (i64 145 to ptr)"},
		{name: "per cpu ptr",
			input: `  %1 = call ptr @main.bpfPerCpuPtr(ptr %percpu, i32 %cpu, ptr undef) #7`,
			want:  "inttoptr (i64 153 to ptr)"},
		{name: "sys bpf",
			input: `  %1 = call i64 @main.bpfSysBpf(i32 %cmd, ptr %attr, i32 %size, ptr undef) #7`,
			want:  "inttoptr (i64 166 to ptr)"},
		{name: "find vma",
			input: `  %1 = call i64 @main.bpfFindVma(ptr %task, i64 %addr, ptr %cb, ptr %ctx, i64 0, ptr undef) #7`,
			want:  "inttoptr (i64 180 to ptr)"},
		{name: "kptr xchg",
			input: `  %1 = call ptr @main.bpfKptrXchg(ptr %kptr, ptr %new, ptr undef) #7`,
			want:  "inttoptr (i64 194 to ptr)"},
		{name: "ringbuf reserve dynptr",
			input: `  %1 = call i64 @main.bpfRingbufReserveDynptr(ptr %rb, i32 %size, i64 0, ptr %dynptr, ptr undef) #7`,
			want:  "inttoptr (i64 198 to ptr)"},
		{name: "user ringbuf drain",
			input: `  %1 = call i64 @main.bpfUserRingbufDrain(ptr %rb, ptr %cb, ptr %ctx, i64 0, ptr undef) #7`,
			want:  "inttoptr (i64 209 to ptr)"},
		{name: "core field exists skipped",
			input:     `  %5 = call i32 @main.bpfCoreFieldExists(ptr nonnull %4, ptr undef) #7`,
			want:      `@main.bpfCoreFieldExists`,
			unchanged: true},
		{name: "core type exists skipped",
			input:     `  %1 = call i32 @main.bpfCoreTypeExists(ptr %type, ptr undef) #7`,
			want:      `@main.bpfCoreTypeExists`,
			unchanged: true},
		{name: "non-helper line unchanged",
			input:     `  %1 = add i32 %a, %b`,
			want:      `add i32 %a, %b`,
			unchanged: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := rewriteHelpers([]string{tt.input})
			if err != nil {
				t.Fatal(err)
			}
			text := strings.Join(got, "\n")
			if !strings.Contains(text, tt.want) {
				t.Errorf("missing %q in:\n%s", tt.want, text)
			}
			if !tt.unchanged && strings.Contains(text, "@main.bpf") {
				t.Error("mangled helper name still present")
			}
		})
	}

	t.Run("all known helpers resolve", func(t *testing.T) {
		if len(knownHelpers) != 211 {
			t.Fatalf("expected 211 helpers, got %d", len(knownHelpers))
		}
		for name, id := range knownHelpers {
			line := fmt.Sprintf(`  %%1 = call i64 @%s(ptr undef) #7`, name)
			got, err := rewriteHelpers([]string{line})
			if err != nil {
				t.Errorf("%s: %v", name, err)
				continue
			}
			want := fmt.Sprintf("inttoptr (i64 %d to ptr)", id)
			if !strings.Contains(strings.Join(got, "\n"), want) {
				t.Errorf("%s: expected %q", name, want)
			}
		}
	})

	t.Run("unknown helper", func(t *testing.T) {
		_, err := rewriteHelpers([]string{`  call i64 @main.bpfUnknownHelper(ptr undef) #7`})
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "bpfUnknownHelper") {
			t.Errorf("should mention unknown helper: %v", err)
		}
	})

}

func TestSnakeToCamel(t *testing.T) {
	tests := []struct{ in, want string }{
		{"bpf_map_lookup_elem", "bpfMapLookupElem"},
		{"bpf_get_current_pid_tgid", "bpfGetCurrentPidTgid"},
		{"bpf_l3_csum_replace", "bpfL3CsumReplace"},
		{"bpf_skc_to_tcp6_sock", "bpfSkcToTcp6Sock"},
		{"bpf_tcp_raw_gen_syncookie_ipv4", "bpfTcpRawGenSyncookieIpv4"},
		{"bpf_jiffies64", "bpfJiffies64"},
		{"bpf_d_path", "bpfDPath"},
		{"bpf_redirect", "bpfRedirect"},
		{"bpf_bind", "bpfBind"},
		{"bpf_loop", "bpfLoop"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := snakeToCamel(tt.in); got != tt.want {
				t.Errorf("snakeToCamel(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestStripTrailingUndef(t *testing.T) {
	tests := []struct{ in, want string }{
		{"ptr undef", ""},
		{"ptr nonnull %sa, i32 16, ptr %5, ptr undef", "ptr nonnull %sa, i32 16, ptr %5"},
		{
			"ptr nonnull @main.events, ptr nonnull %ev, i64 16, i64 0, ptr undef",
			"ptr nonnull @main.events, ptr nonnull %ev, i64 16, i64 0",
		},
		{"i32 42", "i32 42"},
	}
	for _, tt := range tests {
		if got := stripTrailingUndef(tt.in); got != tt.want {
			t.Errorf("stripTrailingUndef(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
