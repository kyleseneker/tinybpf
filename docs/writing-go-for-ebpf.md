# Writing Go for eBPF

The BPF verifier statically analyzes every execution path before load and
rejects programs that violate memory safety, exceed the 512-byte stack, use
unbounded loops, or call disallowed helpers. The constraints below reflect
those rules plus the subset of Go that TinyGo can compile with
`-gc=none -scheduler=none -panic=trap`.

## Language constraints

Only a subset of Go is compatible with the BPF sandbox.

### Supported

- Integer types (`uint8`--`uint64`, `int8`--`int64`)
- Structs with fixed-size layouts
- Pointers and `unsafe.Pointer`
- Control flow: `if`/`else`, `for` with bounded iterations
- `unsafe.Sizeof`, `unsafe.Offsetof`
- Constants and `const` blocks

### Unsupported

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
| Build tag | `//go:build tinygo` -- add a `_stub.go` with `//go:build !tinygo` for IDE compatibility |
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

IDs from `___BPF_FUNC_MAPPER` in `include/uapi/linux/bpf.h`, auto-generated via `go generate` (pinned to kernel v6.18). The helper list is frozen at 211 entries; new kernel extensions use kfuncs instead. Unrecognized helpers produce an error during transformation with fuzzy-match suggestions.

### Map operations

| Go name | Kernel name | ID |
|---------|-------------|---:|
| `bpfMapLookupElem` | `bpf_map_lookup_elem` | 1 |
| `bpfMapUpdateElem` | `bpf_map_update_elem` | 2 |
| `bpfMapDeleteElem` | `bpf_map_delete_elem` | 3 |
| `bpfMapPushElem` | `bpf_map_push_elem` | 87 |
| `bpfMapPopElem` | `bpf_map_pop_elem` | 88 |
| `bpfMapPeekElem` | `bpf_map_peek_elem` | 89 |
| `bpfMapLookupPercpuElem` | `bpf_map_lookup_percpu_elem` | 195 |
| `bpfForEachMapElem` | `bpf_for_each_map_elem` | 164 |

### Time

| Go name | Kernel name | ID |
|---------|-------------|---:|
| `bpfKtimeGetNs` | `bpf_ktime_get_ns` | 5 |
| `bpfKtimeGetBootNs` | `bpf_ktime_get_boot_ns` | 125 |
| `bpfKtimeGetCoarseNs` | `bpf_ktime_get_coarse_ns` | 160 |
| `bpfKtimeGetTaiNs` | `bpf_ktime_get_tai_ns` | 208 |
| `bpfJiffies64` | `bpf_jiffies64` | 118 |

### Print / trace

| Go name | Kernel name | ID |
|---------|-------------|---:|
| `bpfTracePrintk` | `bpf_trace_printk` | 6 |
| `bpfTraceVprintk` | `bpf_trace_vprintk` | 177 |
| `bpfSnprintf` | `bpf_snprintf` | 165 |

### Process / task info

| Go name | Kernel name | ID |
|---------|-------------|---:|
| `bpfGetCurrentPidTgid` | `bpf_get_current_pid_tgid` | 14 |
| `bpfGetCurrentUidGid` | `bpf_get_current_uid_gid` | 15 |
| `bpfGetCurrentComm` | `bpf_get_current_comm` | 16 |
| `bpfGetCurrentTask` | `bpf_get_current_task` | 35 |
| `bpfGetCurrentTaskBtf` | `bpf_get_current_task_btf` | 158 |
| `bpfGetCurrentCgroupId` | `bpf_get_current_cgroup_id` | 80 |
| `bpfGetCurrentAncestorCgroupId` | `bpf_get_current_ancestor_cgroup_id` | 123 |
| `bpfGetNsCurrentPidTgid` | `bpf_get_ns_current_pid_tgid` | 120 |
| `bpfCurrentTaskUnderCgroup` | `bpf_current_task_under_cgroup` | 37 |
| `bpfTaskPtRegs` | `bpf_task_pt_regs` | 175 |
| `bpfCopyFromUser` | `bpf_copy_from_user` | 148 |

### Ring buffer

| Go name | Kernel name | ID |
|---------|-------------|---:|
| `bpfRingbufOutput` | `bpf_ringbuf_output` | 130 |
| `bpfRingbufReserve` | `bpf_ringbuf_reserve` | 131 |
| `bpfRingbufSubmit` | `bpf_ringbuf_submit` | 132 |
| `bpfRingbufDiscard` | `bpf_ringbuf_discard` | 133 |
| `bpfRingbufQuery` | `bpf_ringbuf_query` | 134 |

### Perf event

| Go name | Kernel name | ID |
|---------|-------------|---:|
| `bpfPerfEventOutput` | `bpf_perf_event_output` | 25 |
| `bpfPerfEventReadValue` | `bpf_perf_event_read_value` | 55 |

### Probe / memory access

| Go name | Kernel name | ID |
|---------|-------------|---:|
| `bpfProbeRead` | `bpf_probe_read` | 4 |
| `bpfProbeReadStr` | `bpf_probe_read_str` | 45 |
| `bpfProbeWriteUser` | `bpf_probe_write_user` | 36 |
| `bpfProbeReadUser` | `bpf_probe_read_user` | 112 |
| `bpfProbeReadUserStr` | `bpf_probe_read_user_str` | 114 |
| `bpfProbeReadKernel` | `bpf_probe_read_kernel` | 113 |
| `bpfProbeReadKernelStr` | `bpf_probe_read_kernel_str` | 115 |

### Networking / skb

| Go name | Kernel name | ID |
|---------|-------------|---:|
| `bpfSkbStoreBytes` | `bpf_skb_store_bytes` | 9 |
| `bpfSkbLoadBytes` | `bpf_skb_load_bytes` | 26 |
| `bpfSkbLoadBytesRelative` | `bpf_skb_load_bytes_relative` | 68 |
| `bpfL3CsumReplace` | `bpf_l3_csum_replace` | 10 |
| `bpfL4CsumReplace` | `bpf_l4_csum_replace` | 11 |
| `bpfCsumDiff` | `bpf_csum_diff` | 28 |
| `bpfCsumUpdate` | `bpf_csum_update` | 40 |
| `bpfCsumLevel` | `bpf_csum_level` | 135 |
| `bpfCloneRedirect` | `bpf_clone_redirect` | 13 |
| `bpfRedirect` | `bpf_redirect` | 23 |
| `bpfRedirectMap` | `bpf_redirect_map` | 51 |
| `bpfSkRedirectMap` | `bpf_sk_redirect_map` | 52 |
| `bpfRedirectNeigh` | `bpf_redirect_neigh` | 152 |
| `bpfRedirectPeer` | `bpf_redirect_peer` | 155 |
| `bpfFibLookup` | `bpf_fib_lookup` | 69 |
| `bpfCheckMtu` | `bpf_check_mtu` | 163 |

### XDP

| Go name | Kernel name | ID |
|---------|-------------|---:|
| `bpfXdpAdjustHead` | `bpf_xdp_adjust_head` | 44 |
| `bpfXdpAdjustMeta` | `bpf_xdp_adjust_meta` | 54 |
| `bpfXdpAdjustTail` | `bpf_xdp_adjust_tail` | 65 |
| `bpfXdpOutput` | `bpf_xdp_output` | 121 |

### Socket

| Go name | Kernel name | ID |
|---------|-------------|---:|
| `bpfGetSocketCookie` | `bpf_get_socket_cookie` | 46 |
| `bpfGetSocketUid` | `bpf_get_socket_uid` | 47 |
| `bpfSetsockopt` | `bpf_setsockopt` | 49 |
| `bpfGetsockopt` | `bpf_getsockopt` | 57 |
| `bpfBind` | `bpf_bind` | 64 |
| `bpfSkLookupTcp` | `bpf_sk_lookup_tcp` | 84 |
| `bpfSkLookupUdp` | `bpf_sk_lookup_udp` | 85 |
| `bpfSkRelease` | `bpf_sk_release` | 86 |

### Spin lock

| Go name | Kernel name | ID |
|---------|-------------|---:|
| `bpfSpinLock` | `bpf_spin_lock` | 93 |
| `bpfSpinUnlock` | `bpf_spin_unlock` | 94 |

### Storage

| Go name | Kernel name | ID |
|---------|-------------|---:|
| `bpfGetLocalStorage` | `bpf_get_local_storage` | 81 |
| `bpfSkStorageGet` | `bpf_sk_storage_get` | 107 |
| `bpfSkStorageDelete` | `bpf_sk_storage_delete` | 108 |
| `bpfTaskStorageGet` | `bpf_task_storage_get` | 156 |
| `bpfTaskStorageDelete` | `bpf_task_storage_delete` | 157 |
| `bpfCgrpStorageGet` | `bpf_cgrp_storage_get` | 210 |
| `bpfCgrpStorageDelete` | `bpf_cgrp_storage_delete` | 211 |

### Timer

| Go name | Kernel name | ID |
|---------|-------------|---:|
| `bpfTimerInit` | `bpf_timer_init` | 169 |
| `bpfTimerSetCallback` | `bpf_timer_set_callback` | 170 |
| `bpfTimerStart` | `bpf_timer_start` | 171 |
| `bpfTimerCancel` | `bpf_timer_cancel` | 172 |

### Tracing

| Go name | Kernel name | ID |
|---------|-------------|---:|
| `bpfGetStackid` | `bpf_get_stackid` | 27 |
| `bpfGetStack` | `bpf_get_stack` | 67 |
| `bpfGetFuncIp` | `bpf_get_func_ip` | 173 |
| `bpfGetAttachCookie` | `bpf_get_attach_cookie` | 174 |

### Tail call

| Go name | Kernel name | ID |
|---------|-------------|---:|
| `bpfTailCall` | `bpf_tail_call` | 12 |

The full list of 211 helpers is generated from `include/uapi/linux/bpf.h`. Only commonly used helpers are shown above. See the [kernel BPF header](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h) for the complete set.

## CO-RE (Compile Once -- Run Everywhere)

CO-RE enables BPF programs to work across kernel versions without recompilation. Field offsets are resolved at load time via BTF relocations rather than hardcoded at compile time.

### Portable struct access

Declare a Go struct with the `bpfCore` prefix. Field offsets in the compiled ELF are resolved by the BPF loader against the running kernel's BTF:

```go
type bpfCoreTaskStruct struct {
    Pid  int32
    Tgid int32
}
```

Use the struct normally in your program:

```go
var core bpfCoreTaskStruct
bpfProbeReadKernel(unsafe.Pointer(&core), uint32(unsafe.Sizeof(core)), task)
pid := core.Pid
```

`tinybpf` automatically detects `bpfCore*` types and emits `llvm.preserve.struct.access.index` intrinsics that the BPF loader uses to resolve field offsets at load time.

### Field naming convention

Go struct fields use CamelCase (`Pid`, `LoginUid`), but kernel structs use snake_case (`pid`, `login_uid`). The transform automatically converts field names in BTF metadata:

| Go field | Kernel BTF |
|----------|-----------|
| `Pid` | `pid` |
| `Tgid` | `tgid` |
| `LoginUid` | `login_uid` |

The struct type name is also converted: `bpfCoreTaskStruct` becomes `task_struct` in BTF (the `bpfCore` prefix is stripped and the remainder is converted to snake_case).

### Field and type existence checks

Check whether a field or type exists in the running kernel's BTF before accessing it:

```go
//go:extern bpf_core_field_exists
func bpfCoreFieldExists(field unsafe.Pointer) int32

//go:extern bpf_core_type_exists
func bpfCoreTypeExists(typePtr unsafe.Pointer) int32
```

Usage:

```go
if bpfCoreFieldExists(unsafe.Pointer(&core.Tgid)) != 0 {
    ev.Tgid = uint32(core.Tgid)
}
```

These are compile-time relocation markers, not kernel helpers. `tinybpf` rewrites them to `llvm.bpf.preserve.field.info` and `llvm.bpf.preserve.type.info` intrinsics. The BPF loader resolves them to 0 or 1 at load time.

### CO-RE conventions

| Convention | Details |
|------------|---------|
| Struct prefix | `bpfCore` -- e.g. `bpfCoreTaskStruct`, `bpfCoreCredStruct` |
| Field names | CamelCase in Go, automatically converted to snake_case for kernel BTF |
| Activation | Automatic -- no flag needed, transforms are no-ops without `bpfCore*` types |
| Field exists | `bpfCoreFieldExists(unsafe.Pointer(&s.Field))` returns 1 if the field exists |
| Type exists | `bpfCoreTypeExists(unsafe.Pointer(&s))` returns 1 if the type exists |

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

## kfuncs (kernel functions)

Modern kernel extensions beyond the 211-helper set use **kfuncs** -- kernel functions resolved via BTF at load time. tinybpf provides basic kfunc support through a naming convention.

Declare a kfunc with the `bpfKfunc` prefix:

```go
//go:extern bpf_cast_to_kern_ctx
func bpfKfuncBpfCastToKernCtx(ctx unsafe.Pointer) unsafe.Pointer
```

The transform pipeline preserves kfunc extern declarations (instead of rewriting them to helper IDs). The BPF loader resolves them via BTF at load time.

| Convention | Details |
|------------|---------|
| Prefix | `bpfKfunc` -- e.g. `bpfKfuncBpfCastToKernCtx` |
| Declaration | `//go:extern kernel_kfunc_name` |
| Resolution | Handled by the BPF loader (cilium/ebpf, libbpf) via kernel BTF |

**Note:** kfunc support is basic -- extern preservation and prefix stripping. The loader must support BTF-based kfunc resolution.

## Known limitations

- **LLVM version must be >= TinyGo's bundled LLVM.** TinyGo 0.40.x bundles LLVM 20. Ubuntu 24.04 defaults to LLVM 18; install 20+ from [apt.llvm.org](https://apt.llvm.org).
- **macOS: compile only.** The build pipeline works on macOS, but loading programs into the kernel requires Linux.
- **struct_ops programs are not supported.** BPF struct_ops require function pointers as struct members, which Go/TinyGo cannot express. This is a fundamental language limitation.
- **Iterator programs (`iter/`) are not supported.** BPF iterators rely on iterator-specific context struct handling and `bpf_iter_*` kfunc sequencing that tinybpf does not implement. Passing `--program-type iter` or an `iter/` section is rejected with an explicit error. This is not on the v1.0 roadmap -- use C + libbpf for iterators.
- **Stack usage is estimated, not exact.** tinybpf warns when `alloca` instructions approach the 512-byte BPF stack limit, but the estimate does not account for register spills or call frame overhead. The kernel verifier is the authoritative check.

