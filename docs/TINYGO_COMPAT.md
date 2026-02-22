# Writing Go for eBPF

## BPF in a nutshell

BPF programs run inside a kernel sandbox. Before loading, the **verifier** statically analyzes every execution path to guarantee:

- **Memory safety** — no out-of-bounds access, no uninitialized reads, no null dereference without a prior check
- **Bounded execution** — all loops must have a provable upper bound (kernel 5.3+)
- **Valid helper calls** — only whitelisted kernel functions, with correct argument types
- **Stack limits** — 512 bytes total across all frames
- **Static call graph** — no function pointers, indirect calls, or recursion

If the verifier rejects a program, it won't load.

### Why TinyGo?

Standard Go's compiler (`gc`) emits native machine code via its own backend — there is no LLVM IR to retarget to BPF. Its runtime (GC, goroutines, channels) also cannot run in the kernel.

TinyGo compiles through LLVM and supports bare-metal mode (`-gc=none -scheduler=none -panic=trap`) with no runtime. This is the same mode used for microcontrollers and WebAssembly — BPF is another constrained target.

TinyGo 0.40.x does not include a BPF backend. A prior effort to add one ([miekg/bpf](https://github.com/miekg/bpf)) hit LLVM errors and was [archived](https://miek.nl/2024/august/29/ebpf-from-go-first-steps/). `tinybpf` takes a different approach: compile for the host, then retarget to BPF during IR transformation. This works with stock toolchain releases.

### Program lifecycle

1. **Compile** — TinyGo produces LLVM IR; `tinybpf` transforms and links it into a BPF ELF (`.o`).
2. **Load** — a userspace loader ([`cilium/ebpf`](https://github.com/cilium/ebpf), [`libbpf`](https://github.com/libbpf/libbpf), [`bpftool`](https://github.com/libbpf/bpftool)) parses the ELF, creates maps, and submits programs to the kernel.
3. **Verify** — the kernel verifier analyzes each program.
4. **Attach** — the loader attaches programs to kernel hooks (tracepoints, kprobes, XDP, cgroup, etc.) based on ELF section names.
5. **Execute** — the kernel runs the program on each event.
6. **Communicate** — BPF maps share data between kernel and userspace.

## Language constraints

Only a subset of Go is compatible with the BPF sandbox.

### Supported

- Integer types (`uint8`–`uint64`, `int8`–`int64`)
- Structs with fixed-size layouts
- Pointers and `unsafe.Pointer`
- Control flow: `if`/`else`, `for` with bounded iterations
- `unsafe.Sizeof`, `unsafe.Offsetof`
- Constants and `const` blocks

### Unsupported features

| Feature | Why |
|---------|-----|
| Heap allocation (`new`, `make`, `append`) | No heap in BPF; `tinybpf` rewrites `runtime.alloc` to stack, but explicit heap use fails |
| Strings | Use `[N]byte` arrays |
| Interfaces | Require runtime type dispatch |
| Goroutines and channels | No concurrency in BPF |
| Maps and dynamic slices | Require heap |
| Standard library (`fmt`, `os`, etc.) | Depends on runtime and syscalls |
| Floating point | Not supported by BPF instruction set |
| Unbounded loops | Rejected by verifier |

## Program structure

A BPF program needs three things: a map definition, helper declarations, and an exported entry point.

```go
//go:build tinygo

package main

import "unsafe"

type bpfMapDef struct {
    Type       uint32
    KeySize    uint32
    ValueSize  uint32
    MaxEntries uint32
    MapFlags   uint32
    Pinning    uint32 // optional: 0 = none, 1 = LIBBPF_PIN_BY_NAME
}

var events = bpfMapDef{Type: 27, MaxEntries: 1 << 24} // BPF_MAP_TYPE_RINGBUF

//go:extern bpf_get_current_pid_tgid
func bpfGetCurrentPidTgid() uint64

//export my_program
func my_program(ctx unsafe.Pointer) int32 {
    return 0
}

func main() {}
```

### Conventions

| Convention | Details |
|------------|---------|
| Build tag | `//go:build tinygo` — add a `_stub.go` with `//go:build !tinygo` for IDE compatibility |
| Entry points | `//export funcname` (not `//go:export`) |
| Helpers | `//go:extern kernel_helper_name` |
| Compilation | `tinygo build -gc=none -scheduler=none -panic=trap -opt=1` |

### TinyGo features used

| Feature | Purpose |
|---------|---------|
| `//export` | Prevents dead code elimination of entry points |
| `//go:extern` | Creates external declarations rewritten to BPF helper calls |
| `-gc=none -scheduler=none` | Eliminates runtime; produces clean IR |

## Map types

`Type` field values for `bpfMapDef` (from `include/uapi/linux/bpf.h`):

| Constant | Value | Use |
|----------|-------|-----|
| `BPF_MAP_TYPE_HASH` | 1 | Key-value store |
| `BPF_MAP_TYPE_ARRAY` | 2 | Fixed-size integer-indexed array |
| `BPF_MAP_TYPE_PROG_ARRAY` | 3 | Tail call program array |
| `BPF_MAP_TYPE_PERF_EVENT_ARRAY` | 4 | Per-CPU perf event output |
| `BPF_MAP_TYPE_PERCPU_HASH` | 5 | Per-CPU hash map |
| `BPF_MAP_TYPE_PERCPU_ARRAY` | 6 | Per-CPU array |
| `BPF_MAP_TYPE_LRU_HASH` | 9 | LRU hash map |
| `BPF_MAP_TYPE_LRU_PERCPU_HASH` | 10 | Per-CPU LRU hash |
| `BPF_MAP_TYPE_LPM_TRIE` | 11 | Longest prefix match (IP routing) |
| `BPF_MAP_TYPE_ARRAY_OF_MAPS` | 12 | Array of inner maps |
| `BPF_MAP_TYPE_HASH_OF_MAPS` | 13 | Hash of inner maps |
| `BPF_MAP_TYPE_RINGBUF` | 27 | Lock-free ring buffer |

## Supported BPF helpers

IDs from `__BPF_FUNC_MAPPER` in `include/uapi/linux/bpf.h`. Unrecognized helpers produce an error during transformation.

### Map operations

| Go name | Kernel name | ID |
|---------|-------------|---:|
| `bpfMapLookupElem` | `bpf_map_lookup_elem` | 1 |
| `bpfMapUpdateElem` | `bpf_map_update_elem` | 2 |
| `bpfMapDeleteElem` | `bpf_map_delete_elem` | 3 |
| `bpfMapPushElem` | `bpf_map_push_elem` | 87 |
| `bpfMapPopElem` | `bpf_map_pop_elem` | 88 |
| `bpfMapPeekElem` | `bpf_map_peek_elem` | 89 |
| `bpfMapLookupAndDeleteElem` | `bpf_map_lookup_and_delete_elem` | 110 |

### Time

| Go name | Kernel name | ID |
|---------|-------------|---:|
| `bpfKtimeGetNs` | `bpf_ktime_get_ns` | 5 |
| `bpfKtimeGetBootNs` | `bpf_ktime_get_boot_ns` | 125 |
| `bpfKtimeGetCoarseNs` | `bpf_ktime_get_coarse_ns` | 160 |

### Print / trace

| Go name | Kernel name | ID |
|---------|-------------|---:|
| `bpfTracePrintk` | `bpf_trace_printk` | 6 |
| `bpfSnprintf` | `bpf_snprintf` | 165 |

### Random

| Go name | Kernel name | ID |
|---------|-------------|---:|
| `bpfGetPrandomU32` | `bpf_get_prandom_u32` | 7 |

### Process info

| Go name | Kernel name | ID |
|---------|-------------|---:|
| `bpfGetCurrentPidTgid` | `bpf_get_current_pid_tgid` | 14 |
| `bpfGetCurrentUidGid` | `bpf_get_current_uid_gid` | 15 |
| `bpfGetCurrentComm` | `bpf_get_current_comm` | 16 |
| `bpfGetCurrentTask` | `bpf_get_current_task` | 35 |
| `bpfGetCurrentTaskBtf` | `bpf_get_current_task_btf` | 158 |
| `bpfGetCurrentCgroupId` | `bpf_get_current_cgroup_id` | 80 |

### CPU info

| Go name | Kernel name | ID |
|---------|-------------|---:|
| `bpfGetSmpProcessorId` | `bpf_get_smp_processor_id` | 8 |
| `bpfGetNumaNodeId` | `bpf_get_numa_node_id` | 42 |

### Perf event

| Go name | Kernel name | ID |
|---------|-------------|---:|
| `bpfPerfEventOutput` | `bpf_perf_event_output` | 25 |
| `bpfPerfEventReadValue` | `bpf_perf_event_read_value` | 55 |

### Ring buffer

| Go name | Kernel name | ID |
|---------|-------------|---:|
| `bpfRingbufOutput` | `bpf_ringbuf_output` | 130 |
| `bpfRingbufReserve` | `bpf_ringbuf_reserve` | 131 |
| `bpfRingbufSubmit` | `bpf_ringbuf_submit` | 132 |
| `bpfRingbufDiscard` | `bpf_ringbuf_discard` | 133 |
| `bpfRingbufQuery` | `bpf_ringbuf_query` | 134 |

### Probe / memory read

| Go name | Kernel name | ID |
|---------|-------------|---:|
| `bpfProbeRead` | `bpf_probe_read` | 4 |
| `bpfProbeReadUser` | `bpf_probe_read_user` | 112 |
| `bpfProbeReadUserStr` | `bpf_probe_read_user_str` | 114 |
| `bpfProbeReadKernel` | `bpf_probe_read_kernel` | 113 |
| `bpfProbeReadKernelStr` | `bpf_probe_read_kernel_str` | 115 |

### Tracing

| Go name | Kernel name | ID |
|---------|-------------|---:|
| `bpfGetStack` | `bpf_get_stack` | 67 |
| `bpfGetFuncIp` | `bpf_get_func_ip` | 173 |
| `bpfGetAttachCookie` | `bpf_get_attach_cookie` | 174 |

### Networking / skb

| Go name | Kernel name | ID |
|---------|-------------|---:|
| `bpfSkbStoreBytes` | `bpf_skb_store_bytes` | 9 |
| `bpfSkbLoadBytes` | `bpf_skb_load_bytes` | 26 |
| `bpfL3CsumReplace` | `bpf_l3_csum_replace` | 10 |
| `bpfL4CsumReplace` | `bpf_l4_csum_replace` | 11 |
| `bpfCloneRedirect` | `bpf_clone_redirect` | 13 |
| `bpfSkbVlanPush` | `bpf_skb_vlan_push` | 18 |
| `bpfSkbVlanPop` | `bpf_skb_vlan_pop` | 19 |
| `bpfSkbGetTunnelKey` | `bpf_skb_get_tunnel_key` | 20 |
| `bpfSkbSetTunnelKey` | `bpf_skb_set_tunnel_key` | 21 |
| `bpfRedirect` | `bpf_redirect` | 23 |
| `bpfCsumDiff` | `bpf_csum_diff` | 28 |
| `bpfSkbChangeProto` | `bpf_skb_change_proto` | 31 |
| `bpfSkbChangeType` | `bpf_skb_change_type` | 32 |
| `bpfSkbUnderCgroup` | `bpf_skb_under_cgroup` | 33 |
| `bpfSkbChangeTail` | `bpf_skb_change_tail` | 38 |
| `bpfSkbPullData` | `bpf_skb_pull_data` | 39 |
| `bpfSetHash` | `bpf_set_hash` | 48 |
| `bpfSetsockopt` | `bpf_setsockopt` | 49 |
| `bpfGetsockopt` | `bpf_getsockopt` | 50 |
| `bpfRedirectMap` | `bpf_redirect_map` | 51 |
| `bpfFibLookup` | `bpf_fib_lookup` | 69 |
| `bpfCsumLevel` | `bpf_csum_level` | 183 |

### XDP

| Go name | Kernel name | ID |
|---------|-------------|---:|
| `bpfXdpAdjustHead` | `bpf_xdp_adjust_head` | 44 |
| `bpfXdpAdjustMeta` | `bpf_xdp_adjust_meta` | 54 |
| `bpfXdpAdjustTail` | `bpf_xdp_adjust_tail` | 65 |

### Socket

| Go name | Kernel name | ID |
|---------|-------------|---:|
| `bpfGetSocketCookie` | `bpf_get_socket_cookie` | 46 |
| `bpfSkLookupTcp` | `bpf_sk_lookup_tcp` | 84 |
| `bpfSkLookupUdp` | `bpf_sk_lookup_udp` | 85 |
| `bpfSkRelease` | `bpf_sk_release` | 86 |
| `bpfSkcLookupTcp` | `bpf_skc_lookup_tcp` | 99 |

### Tail call

| Go name | Kernel name | ID |
|---------|-------------|---:|
| `bpfTailCall` | `bpf_tail_call` | 12 |

### Task storage (kernel 5.11+)

| Go name | Kernel name | ID |
|---------|-------------|---:|
| `bpfTaskStorageGet` | `bpf_task_storage_get` | 169 |
| `bpfTaskStorageDelete` | `bpf_task_storage_delete` | 170 |

## Common patterns

### Bounded loops

```go
var buf [16]byte
for i := 0; i < 16; i++ {
    buf[i] = 0
}
```

Runtime-variable bounds (`for i := 0; i < n; i++`) are rejected by the verifier.

### Fixed-size arrays instead of slices

```go
type event struct {
    Comm [16]byte
    PID  uint32
}
```

### Struct field access from context

The struct layout must exactly match the kernel's tracepoint or kprobe context. Check with `cat /sys/kernel/tracing/events/<category>/<event>/format`.

```go
type tpArgs struct {
    _         [16]byte // padding to match kernel layout
    Fd        int64
    Uservaddr uint64
}

//export my_program
func my_program(ctx unsafe.Pointer) int32 {
    args := (*tpArgs)(ctx)
    _ = args.Fd
    return 0
}
```

### Reading user memory

Direct dereference of userspace pointers is rejected. Use `bpf_probe_read_user`:

```go
//go:extern bpf_probe_read_user
func bpfProbeReadUser(dst unsafe.Pointer, size uint32, src unsafe.Pointer) int64

var sa sockaddrIn
bpfProbeReadUser(unsafe.Pointer(&sa), uint32(unsafe.Sizeof(sa)), unsafe.Pointer(uintptr(args.Addr)))
```

### Map operations

Always nil-check the return of `bpf_map_lookup_elem` before dereferencing:

```go
var counters = bpfMapDef{Type: 2, KeySize: 4, ValueSize: 8, MaxEntries: 256}

func incrementCounter(idx uint32) {
    valPtr := bpfMapLookupElem(unsafe.Pointer(&counters), unsafe.Pointer(&idx))
    if valPtr != nil {
        val := (*uint64)(valPtr)
        *val++
    }
}
```

### Pinned maps

Add a `Pinning` field set to `1` (`LIBBPF_PIN_BY_NAME`) to persist a map at `/sys/fs/bpf/<name>`:

```go
var shared_state = bpfMapDef{
    Type: 1, KeySize: 4, ValueSize: 8, MaxEntries: 1024,
    Pinning: 1,
}
```

## Known limitations

- **`ld.lld` does not support BPF relocatable linking.** The pipeline uses `llvm-link` at the IR level instead.
- **LLVM version must be >= TinyGo's bundled LLVM.** TinyGo 0.40.x bundles LLVM 20. Ubuntu 24.04 defaults to LLVM 18; install 20+ from [apt.llvm.org](https://apt.llvm.org).
- **macOS development only.** The pipeline through `llc` works on macOS. Kernel loading requires Linux.

## FAQ

**Why not standard Go?**
`gc` has no LLVM IR output to retarget, and its runtime can't run in the kernel. See [Why TinyGo?](#why-tinygo) above.

**What does the verifier do?**
It statically proves every execution path is safe before the kernel runs your program. See [BPF in a nutshell](#bpf-in-a-nutshell) above.

**How do I load the `.o` into the kernel?**
Use any BPF loader: [`cilium/ebpf`](https://github.com/cilium/ebpf) (Go), [`libbpf`](https://github.com/libbpf/libbpf) (C), or [`bpftool`](https://github.com/libbpf/bpftool) (CLI). The loader parses ELF sections, creates maps, loads programs, and attaches them to hooks.

**What program types are supported?**
Any type the kernel supports: tracepoints, kprobes, XDP, cgroup, socket filters, TC classifiers, etc. The type is determined by the ELF section name set via `--section`.

**How does this compare to writing BPF in C?**
C with `libbpf`/`clang` has the broadest ecosystem. `tinybpf` trades that maturity for Go's type safety and the ability to write kernel-side and userspace code in the same language. The generated bytecode is equivalent.

**Can I use `go test` on BPF code?**
Not directly — BPF helpers are kernel-only symbols. Test logic in pure Go with `go test`, then integration-test the compiled `.o` with a loader on a real kernel or VM.

**What does `tinybpf` actually do to the IR?**
It runs an 11-step transformation: retarget to BPF, strip runtime, rewrite helpers, replace allocations, inject metadata. See [Architecture](ARCHITECTURE.md) for the full breakdown.

## Further reading

- [Architecture](ARCHITECTURE.md) — pipeline design and IR transformation details
- [Support Matrix](SUPPORT_MATRIX.md) — tested toolchain versions and platforms
- [Troubleshooting](TROUBLESHOOTING.md) — setup issues, pipeline errors, and verifier debugging
