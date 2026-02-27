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
		name  string
		input string
		want  string
	}{
		{"context-only arg stripped",
			`  %1 = call i64 @main.bpfGetCurrentPidTgid(ptr undef) #7`,
			"call i64 inttoptr (i64 14 to ptr)()"},
		{"trailing undef stripped with real args",
			`  %1 = call i64 @main.bpfProbeReadUser(ptr nonnull %buf, i32 16, ptr %src, ptr undef) #7`,
			"call i64 inttoptr (i64 112 to ptr)(ptr nonnull %buf, i32 16, ptr %src)"},
		{"ptr return type",
			`  %1 = call ptr @main.bpfMapLookupElem(ptr %map, ptr %key, ptr undef) #7`,
			"call ptr inttoptr (i64 1 to ptr)(ptr %map, ptr %key)"},
		{"i32 return type",
			`  %1 = call i32 @main.bpfMapDeleteElem(ptr %map, ptr %key, ptr undef) #7`,
			"call i32 inttoptr (i64 3 to ptr)(ptr %map, ptr %key)"},
		{"void return type",
			`  call void @main.bpfRingbufSubmit(ptr %1, i64 0, ptr undef) #7`,
			"call void inttoptr (i64 132 to ptr)(ptr %1, i64 0)"},
		{"multi-arg networking helper",
			`  %1 = call i64 @main.bpfSkbStoreBytes(ptr %skb, i32 %off, ptr %from, i32 %len, i64 0, ptr undef) #7`,
			"inttoptr (i64 9 to ptr)"},
		{"ringbuf reserve",
			`  %1 = call ptr @main.bpfRingbufReserve(ptr @main.events, i64 16, i64 0, ptr undef) #7`,
			"inttoptr (i64 131 to ptr)"},
		{"generic probe read",
			`  %1 = call i64 @main.bpfProbeRead(ptr %dst, i32 16, ptr %src, ptr undef) #7`,
			"inttoptr (i64 4 to ptr)"},
		{"get prandom u32",
			`  %1 = call i32 @main.bpfGetPrandomU32(ptr undef) #7`,
			"inttoptr (i64 7 to ptr)"},
		{"get current uid gid",
			`  %1 = call i64 @main.bpfGetCurrentUidGid(ptr undef) #7`,
			"inttoptr (i64 15 to ptr)"},
		{"xdp adjust meta",
			`  %1 = call i32 @main.bpfXdpAdjustMeta(ptr %ctx, i32 %delta, ptr undef) #7`,
			"inttoptr (i64 54 to ptr)"},
		{"sk release",
			`  call void @main.bpfSkRelease(ptr %sk, ptr undef) #7`,
			"inttoptr (i64 86 to ptr)"},
		{"spin lock",
			`  call void @main.bpfSpinLock(ptr %lock, ptr undef) #7`,
			"inttoptr (i64 93 to ptr)"},
		{"spin unlock",
			`  call void @main.bpfSpinUnlock(ptr %lock, ptr undef) #7`,
			"inttoptr (i64 94 to ptr)"},
		{"probe read str",
			`  %1 = call i64 @main.bpfProbeReadStr(ptr %dst, i32 256, ptr %src, ptr undef) #7`,
			"inttoptr (i64 45 to ptr)"},
		{"probe read user str",
			`  %1 = call i64 @main.bpfProbeReadUserStr(ptr %dst, i32 256, ptr %src, ptr undef) #7`,
			"inttoptr (i64 114 to ptr)"},
		{"ktime get coarse ns",
			`  %1 = call i64 @main.bpfKtimeGetCoarseNs(ptr undef) #7`,
			"inttoptr (i64 160 to ptr)"},
		{"task storage get",
			`  %1 = call ptr @main.bpfTaskStorageGet(ptr %map, ptr %task, ptr %value, i64 0, ptr undef) #7`,
			"inttoptr (i64 156 to ptr)"},
		{"timer init",
			`  %1 = call i64 @main.bpfTimerInit(ptr %timer, ptr %map, i64 0, ptr undef) #7`,
			"inttoptr (i64 169 to ptr)"},
		{"dynptr read",
			`  %1 = call i64 @main.bpfDynptrRead(ptr %dst, i32 16, ptr %dynptr, i32 0, i64 0, ptr undef) #7`,
			"inttoptr (i64 201 to ptr)"},
		{"loop",
			`  %1 = call i64 @main.bpfLoop(i32 100, ptr %cb, ptr %ctx, i64 0, ptr undef) #7`,
			"inttoptr (i64 181 to ptr)"},
		{"send signal",
			`  %1 = call i64 @main.bpfSendSignal(i32 9, ptr undef) #7`,
			"inttoptr (i64 109 to ptr)"},
		{"csum level",
			`  %1 = call i64 @main.bpfCsumLevel(ptr %skb, i64 0, ptr undef) #7`,
			"inttoptr (i64 135 to ptr)"},
		{"redirect neigh",
			`  %1 = call i64 @main.bpfRedirectNeigh(i32 %ifindex, ptr %params, i32 0, i64 0, ptr undef) #7`,
			"inttoptr (i64 152 to ptr)"},
		{"clone redirect",
			`  %1 = call i64 @main.bpfCloneRedirect(ptr %skb, i32 %ifindex, i64 0, ptr undef) #7`,
			"inttoptr (i64 13 to ptr)"},
		{"csum diff",
			`  %1 = call i64 @main.bpfCsumDiff(ptr %from, i32 0, ptr %to, i32 0, i32 0, ptr undef) #7`,
			"inttoptr (i64 28 to ptr)"},
		{"snprintf",
			`  %1 = call i64 @main.bpfSnprintf(ptr %buf, i32 256, ptr %fmt, ptr %data, i32 1, ptr undef) #7`,
			"inttoptr (i64 165 to ptr)"},
		{"perf event read",
			`  %1 = call i64 @main.bpfPerfEventRead(ptr %map, i64 %flags, ptr undef) #7`,
			"inttoptr (i64 22 to ptr)"},
		{"override return",
			`  %1 = call i64 @main.bpfOverrideReturn(ptr %ctx, i64 %rc, ptr undef) #7`,
			"inttoptr (i64 58 to ptr)"},
		{"seq printf",
			`  %1 = call i64 @main.bpfSeqPrintf(ptr %seq, ptr %fmt, i32 %len, ptr %data, i32 %cnt, ptr undef) #7`,
			"inttoptr (i64 126 to ptr)"},
		{"inode storage get",
			`  %1 = call ptr @main.bpfInodeStorageGet(ptr %map, ptr %inode, ptr %value, i64 0, ptr undef) #7`,
			"inttoptr (i64 145 to ptr)"},
		{"per cpu ptr",
			`  %1 = call ptr @main.bpfPerCpuPtr(ptr %percpu, i32 %cpu, ptr undef) #7`,
			"inttoptr (i64 153 to ptr)"},
		{"sys bpf",
			`  %1 = call i64 @main.bpfSysBpf(i32 %cmd, ptr %attr, i32 %size, ptr undef) #7`,
			"inttoptr (i64 166 to ptr)"},
		{"find vma",
			`  %1 = call i64 @main.bpfFindVma(ptr %task, i64 %addr, ptr %cb, ptr %ctx, i64 0, ptr undef) #7`,
			"inttoptr (i64 180 to ptr)"},
		{"kptr xchg",
			`  %1 = call ptr @main.bpfKptrXchg(ptr %kptr, ptr %new, ptr undef) #7`,
			"inttoptr (i64 194 to ptr)"},
		{"ringbuf reserve dynptr",
			`  %1 = call i64 @main.bpfRingbufReserveDynptr(ptr %rb, i32 %size, i64 0, ptr %dynptr, ptr undef) #7`,
			"inttoptr (i64 198 to ptr)"},
		{"user ringbuf drain",
			`  %1 = call i64 @main.bpfUserRingbufDrain(ptr %rb, ptr %cb, ptr %ctx, i64 0, ptr undef) #7`,
			"inttoptr (i64 209 to ptr)"},
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
			if strings.Contains(text, "@main.bpf") {
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

	t.Run("core function skipped", func(t *testing.T) {
		input := []string{`  %5 = call i32 @main.bpfCoreFieldExists(ptr nonnull %4, ptr undef) #7`}
		got, err := rewriteHelpers(input)
		if err != nil {
			t.Fatal(err)
		}
		if got[0] != input[0] {
			t.Errorf("CO-RE call should be left untouched for core rewrite pass, got: %q", got[0])
		}
	})

	t.Run("core type exists skipped", func(t *testing.T) {
		input := []string{`  %1 = call i32 @main.bpfCoreTypeExists(ptr %type, ptr undef) #7`}
		got, err := rewriteHelpers(input)
		if err != nil {
			t.Fatal(err)
		}
		if got[0] != input[0] {
			t.Errorf("CO-RE call should be left untouched for core rewrite pass, got: %q", got[0])
		}
	})

	t.Run("non-helper line unchanged", func(t *testing.T) {
		input := []string{`  %1 = add i32 %a, %b`}
		got, err := rewriteHelpers(input)
		if err != nil {
			t.Fatal(err)
		}
		if got[0] != input[0] {
			t.Errorf("line changed: %q", got[0])
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
