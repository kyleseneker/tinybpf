# Writing eBPF programs in Go

A guide to structuring Go code for eBPF programs compiled with TinyGo and linked with `tinybpf`.

## Language constraints

The Linux kernel's BPF verifier enforces strict safety guarantees on loaded programs. Only a subset of Go is compatible with these constraints.

### Supported features

- Integer types: `uint8` through `uint64`, `int8` through `int64`
- Structs with fixed-size layouts
- Pointers and `unsafe.Pointer`
- Control flow: `if`/`else`, `for` with bounded iterations
- `unsafe.Sizeof`, `unsafe.Offsetof`
- Constants and `const` blocks

### Unsupported features

| Feature | Reason |
|---------|--------|
| Heap allocation (`new`, `make`, `append`) | BPF has no heap; `tinybpf` rewrites `runtime.alloc` to stack allocation, but explicit heap use is unsupported |
| Strings | Use fixed-size byte arrays instead |
| Interfaces | Require runtime type dispatch |
| Goroutines and channels | No concurrency in BPF |
| Maps and dynamic slices | Require heap allocation |
| Standard library (`fmt`, `log`, etc.) | Depends on runtime features unavailable in BPF |
| Floating point | Not supported by the BPF instruction set |
| Unbounded loops | Rejected by the BPF verifier |

## Program structure

A BPF program file requires three components: a map definition, helper declarations, and an exported entry point.

```go
//go:build tinygo

package main

import "unsafe"

// Map definition -- tinybpf rewrites this to BTF-compatible encoding.
type bpfMapDef struct {
    Type       uint32
    KeySize    uint32
    ValueSize  uint32
    MaxEntries uint32
    MapFlags   uint32
}

var events = bpfMapDef{Type: 27, MaxEntries: 1 << 24} // BPF_MAP_TYPE_RINGBUF

// BPF helper declaration -- tinybpf rewrites to kernel helper call ID.
//go:extern bpf_get_current_pid_tgid
func bpfGetCurrentPidTgid() uint64

// Program entry point -- //export prevents TinyGo from eliminating the function.
// tinybpf assigns the ELF section based on the --section flag.
//export my_program
func my_program(ctx unsafe.Pointer) int32 {
    // program logic using supported Go features
    return 0
}

func main() {}
```

### Key conventions

| Convention | Details |
|------------|---------|
| Build tag | Use `//go:build tinygo` so standard Go tooling ignores the file. Add a `program_stub.go` with `//go:build !tinygo` for IDE compatibility. |
| Entry points | Mark with `//export` (not `//go:export`). |
| Helper declarations | Declare with `//go:extern`. |
| Compilation flags | `tinygo build -gc=none -scheduler=none -panic=trap -opt=1` |

See [`examples/network-sidecar/bpf/probe.go`](../examples/network-sidecar/bpf/probe.go) for a complete working example.

## Supported BPF helpers

IDs are from the `__BPF_FUNC_MAPPER` enum in `include/uapi/linux/bpf.h`.

### Map operations

| Go declaration name | Kernel helper | Helper ID |
|---------------------|--------------|-----------|
| `bpfMapLookupElem` | `bpf_map_lookup_elem` | 1 |
| `bpfMapUpdateElem` | `bpf_map_update_elem` | 2 |
| `bpfMapDeleteElem` | `bpf_map_delete_elem` | 3 |
| `bpfMapPushElem` | `bpf_map_push_elem` | 87 |
| `bpfMapPopElem` | `bpf_map_pop_elem` | 88 |
| `bpfMapPeekElem` | `bpf_map_peek_elem` | 89 |

### Time

| Go declaration name | Kernel helper | Helper ID |
|---------------------|--------------|-----------|
| `bpfKtimeGetNs` | `bpf_ktime_get_ns` | 5 |
| `bpfKtimeGetBootNs` | `bpf_ktime_get_boot_ns` | 125 |

### Print / trace

| Go declaration name | Kernel helper | Helper ID |
|---------------------|--------------|-----------|
| `bpfTracePrintk` | `bpf_trace_printk` | 6 |

### Process info

| Go declaration name | Kernel helper | Helper ID |
|---------------------|--------------|-----------|
| `bpfGetCurrentPidTgid` | `bpf_get_current_pid_tgid` | 14 |
| `bpfGetCurrentComm` | `bpf_get_current_comm` | 16 |
| `bpfGetCurrentTask` | `bpf_get_current_task` | 35 |
| `bpfGetCurrentTaskBtf` | `bpf_get_current_task_btf` | 158 |
| `bpfGetCurrentCgroupId` | `bpf_get_current_cgroup_id` | 80 |

### CPU info

| Go declaration name | Kernel helper | Helper ID |
|---------------------|--------------|-----------|
| `bpfGetSmpProcessorId` | `bpf_get_smp_processor_id` | 8 |
| `bpfGetNumaNodeId` | `bpf_get_numa_node_id` | 42 |

### Perf event

| Go declaration name | Kernel helper | Helper ID |
|---------------------|--------------|-----------|
| `bpfPerfEventOutput` | `bpf_perf_event_output` | 25 |
| `bpfPerfEventReadValue` | `bpf_perf_event_read_value` | 55 |

### Ring buffer

| Go declaration name | Kernel helper | Helper ID |
|---------------------|--------------|-----------|
| `bpfRingbufOutput` | `bpf_ringbuf_output` | 130 |
| `bpfRingbufReserve` | `bpf_ringbuf_reserve` | 131 |
| `bpfRingbufSubmit` | `bpf_ringbuf_submit` | 132 |
| `bpfRingbufDiscard` | `bpf_ringbuf_discard` | 133 |
| `bpfRingbufQuery` | `bpf_ringbuf_query` | 134 |

### Probe / memory read

| Go declaration name | Kernel helper | Helper ID |
|---------------------|--------------|-----------|
| `bpfProbeReadUser` | `bpf_probe_read_user` | 112 |
| `bpfProbeReadKernel` | `bpf_probe_read_kernel` | 113 |
| `bpfProbeReadKernelStr` | `bpf_probe_read_kernel_str` | 115 |

### Tracing

| Go declaration name | Kernel helper | Helper ID |
|---------------------|--------------|-----------|
| `bpfGetStack` | `bpf_get_stack` | 67 |
| `bpfGetFuncIp` | `bpf_get_func_ip` | 173 |
| `bpfGetAttachCookie` | `bpf_get_attach_cookie` | 174 |

### Networking / skb

| Go declaration name | Kernel helper | Helper ID |
|---------------------|--------------|-----------|
| `bpfSkbStoreBytes` | `bpf_skb_store_bytes` | 9 |
| `bpfSkbLoadBytes` | `bpf_skb_load_bytes` | 26 |
| `bpfL3CsumReplace` | `bpf_l3_csum_replace` | 10 |
| `bpfL4CsumReplace` | `bpf_l4_csum_replace` | 11 |
| `bpfRedirect` | `bpf_redirect` | 23 |
| `bpfRedirectMap` | `bpf_redirect_map` | 51 |
| `bpfFibLookup` | `bpf_fib_lookup` | 69 |

### XDP

| Go declaration name | Kernel helper | Helper ID |
|---------------------|--------------|-----------|
| `bpfXdpAdjustHead` | `bpf_xdp_adjust_head` | 44 |
| `bpfXdpAdjustTail` | `bpf_xdp_adjust_tail` | 65 |

### Socket

| Go declaration name | Kernel helper | Helper ID |
|---------------------|--------------|-----------|
| `bpfSkLookupTcp` | `bpf_sk_lookup_tcp` | 84 |
| `bpfSkLookupUdp` | `bpf_sk_lookup_udp` | 85 |
| `bpfGetSocketCookie` | `bpf_get_socket_cookie` | 46 |

### Tail call

| Go declaration name | Kernel helper | Helper ID |
|---------------------|--------------|-----------|
| `bpfTailCall` | `bpf_tail_call` | 12 |

Unrecognized helpers produce an explicit error during transformation rather than silently emitting invalid IR.

## Common patterns

Concrete examples of Go code patterns that work in BPF programs.

### Bounded loops

The BPF verifier requires loops to have a provably finite iteration count. Use fixed-bound `for` loops:

```go
// OK: bounded iteration
var buf [16]byte
for i := 0; i < 16; i++ {
    buf[i] = 0
}

// NOT OK: verifier rejects unbounded loops
// for i := 0; i < n; i++ { ... }  // n is runtime-variable
```

### Fixed-size arrays instead of slices

BPF has no heap, so slices and dynamic arrays cannot be used. Use fixed-size arrays:

```go
// OK: fixed-size array
type event struct {
    Comm [16]byte
    PID  uint32
}

// NOT OK: slices require heap allocation
// comm := make([]byte, 16)
```

### Struct field access from context

Program context pointers must be cast to typed struct pointers for field access:

```go
type tpArgs struct {
    _         [16]byte // padding to match kernel layout
    Fd        int64
    Uservaddr uint64
}

//export my_program
func my_program(ctx unsafe.Pointer) int32 {
    args := (*tpArgs)(ctx)
    fd := args.Fd
    _ = fd
    return 0
}
```

The struct layout must exactly match the kernel's tracepoint or kprobe context. Check the format with:

```bash
cat /sys/kernel/tracing/events/<category>/<event>/format
```

### Reading user memory

Use `bpf_probe_read_user` to safely copy data from userspace pointers:

```go
//go:extern bpf_probe_read_user
func bpfProbeReadUser(dst unsafe.Pointer, size uint32, src unsafe.Pointer) int64

var sa sockaddrIn
bpfProbeReadUser(unsafe.Pointer(&sa), uint32(unsafe.Sizeof(sa)), unsafe.Pointer(uintptr(args.Addr)))
```

Direct dereference of userspace pointers is rejected by the verifier.

### Map operations

BPF maps are declared as globals with `bpfMapDef` and operated on via helpers:

```go
//go:extern bpf_map_lookup_elem
func bpfMapLookupElem(mapPtr unsafe.Pointer, key unsafe.Pointer) unsafe.Pointer

//go:extern bpf_map_update_elem
func bpfMapUpdateElem(mapPtr unsafe.Pointer, key unsafe.Pointer, value unsafe.Pointer, flags uint64) int64

var counters = bpfMapDef{
    Type:       2, // BPF_MAP_TYPE_ARRAY
    KeySize:    4,
    ValueSize:  8,
    MaxEntries: 256,
}

func incrementCounter(idx uint32) {
    valPtr := bpfMapLookupElem(unsafe.Pointer(&counters), unsafe.Pointer(&idx))
    if valPtr != nil {
        val := (*uint64)(valPtr)
        *val++
    }
}
```

Always check the return value of `bpf_map_lookup_elem` for `nil` before dereferencing.

## What tinybpf does to the IR

The workflow is: compile with TinyGo targeting the host architecture, then run `tinybpf` to transform and retarget the IR into a valid eBPF ELF object. TinyGo 0.40.x does not include a BPF backend, so the tool handles retargeting during transformation.

All 11 transformations run automatically between `llvm-link` and `opt`. See [Architecture](ARCHITECTURE.md) for the complete pipeline.

### 1. Strip TinyGo runtime

TinyGo emits runtime functions even with `-gc=none -scheduler=none` (`__dynamic_loader`, `tinygo_signal_handler`, `runtime.runMain`, etc.). These use constructs the BPF backend rejects. The transform extracts only program functions and their dependencies, discarding everything else.

Programs are auto-detected from non-runtime `define` blocks, or specified explicitly with `--program`.

### 2. Replace heap allocation with stack allocation

TinyGo heap-allocates local variables via `@runtime.alloc`. BPF has no heap. These calls are replaced with `alloca` in the function's entry block (required by the BPF backend) plus `llvm.memset.p0.i64` for zero-initialization.

### 3. Rewrite BPF helper calls

TinyGo mangles `//go:extern` names with a `main.` prefix and appends a trailing `ptr undef` context argument:

```llvm
; TinyGo emits:
call i64 @main.bpfProbeReadUser(ptr %dst, i32 %size, ptr %src, ptr undef)

; tinybpf rewrites to:
call i64 inttoptr (i64 112 to ptr)(ptr %dst, i32 %size, ptr %src)
```

### 4. Retarget triple and datalayout

```llvm
; Before (host architecture):
target datalayout = "e-m:o-p270:32:32-p271:32:32-..."
target triple = "arm64-apple-macosx11.0.0"

; After:
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"
```

### 5. Strip host-specific attributes

Removes `target-cpu`, `target-features`, `allockind`, `allocsize`, and `alloc-family` from all function attribute groups.

### 6. Assign ELF sections

Maps program functions to BPF ELF sections and globals to `.maps`. Configurable via `--section`:

```bash
tinybpf --section handle_connect=tracepoint/syscalls/sys_enter_connect ...
```

When no mapping is provided, programs are placed in a section matching the function name.

### 7. Strip map prefix

TinyGo produces Go package-qualified names for map globals (e.g., `@main.events`). BPF loaders like cilium/ebpf and libbpf expect unqualified names (e.g., `@events`). This step renames all `.maps`-section globals by stripping the package prefix.

### 8. Rewrite map BTF

libbpf-based loaders require BTF-defined maps to use pointer-to-array fields matching C's `__uint()` convention. TinyGo's Go struct uses plain `uint32` fields, producing incompatible BTF. The transform rewrites globals and their DWARF metadata to the expected encoding.

### 9. Sanitize BTF names

The kernel BTF validator rejects type names containing `.`, which TinyGo generates for Go packages (`unsafe.Pointer`, `main.bpfMapDef`). Dots are replaced with underscores. Names are stripped from `DW_TAG_pointer_type` nodes, which must be anonymous in kernel BTF.

### 10. Add GPL license

BPF programs calling GPL-restricted helpers (`bpf_probe_read_user`, `bpf_ringbuf_output`, etc.) require a `license` section containing `"GPL"`. TinyGo does not emit one, so the transform injects it automatically.

### 11. Cleanup

Removes orphaned `declare` statements, unreferenced globals (except those with explicit section attributes), stale attribute groups, and leftover comments to produce minimal IR.

## TinyGo capabilities used

| Feature | Usage |
|---------|-------|
| `//export funcname` | Prevents dead code elimination of program entry points |
| `//go:extern symbolname` | Creates external declarations for BPF helpers (mangled by TinyGo; rewritten by `tinybpf`) |
| `-gc=none -scheduler=none` | Produces clean function bodies: struct access, pointer arithmetic, conditionals, and calls as straightforward LLVM IR |

## Known limitations

- **`ld.lld` does not support BPF relocatable linking.** `ld.lld -r` rejects BPF ELF objects. The pipeline uses `llc` output directly; multi-module linking uses `llvm-link` at the IR level.

- **LLVM version must match TinyGo.** TinyGo 0.40.x bundles LLVM 20. System LLVM tools must be version 20 or later. Ubuntu 24.04 defaults to LLVM 18; install LLVM 20+ from [apt.llvm.org](https://apt.llvm.org).

- **macOS development workflow.** The pipeline through `llc` works on macOS for development and testing. Kernel loading and verifier validation require a Linux host.

## Background

TinyGo 0.40.x does not include an LLVM BPF backend. Its bundled LLVM targets ARM, x86, AVR, RISC-V, WebAssembly, and similar platforms -- there is no `-target bpf` option.

A prior effort to fork TinyGo and add BPF to its LLVM build ([miekg/bpf](https://github.com/miekg/bpf)) encountered fundamental LLVM errors in TinyGo's runtime code and was [archived](https://miek.nl/2024/august/29/ebpf-from-go-first-steps/).

`tinybpf` takes a different approach: compile for the host architecture, then retarget to BPF during the IR transformation stage.

## Further reading

- [Troubleshooting](TROUBLESHOOTING.md) — setup issues, pipeline errors, and verifier debugging
- [Architecture](ARCHITECTURE.md) — full pipeline design and IR transformation details
- [Support Matrix](SUPPORT_MATRIX.md) — tested toolchain versions and platforms
