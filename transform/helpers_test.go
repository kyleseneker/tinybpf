package transform

import "testing"

func TestSnakeToCamel(t *testing.T) {
	tests := []struct {
		in, want string
	}{
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
		{"trailing_", "trailing"},
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
	tests := []struct {
		in, want string
	}{
		{"ptr undef", ""},
		{"ptr nonnull %sa, i32 16, ptr %5, ptr undef", "ptr nonnull %sa, i32 16, ptr %5"},
		{
			"ptr nonnull @main.events, ptr nonnull %ev, i64 16, i64 0, ptr undef",
			"ptr nonnull @main.events, ptr nonnull %ev, i64 16, i64 0",
		},
		{"i32 42", "i32 42"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := stripTrailingUndef(tt.in); got != tt.want {
			t.Errorf("stripTrailingUndef(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
