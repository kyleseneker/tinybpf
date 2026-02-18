target triple = "bpf"

define i64 @xdp_prog(ptr %ctx) section "xdp" {
entry:
  ret i64 2
}
