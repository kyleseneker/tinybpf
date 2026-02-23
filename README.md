<p align="center">
  <img src="icon.png" alt="tinybpf" width="200">
</p>

<h1 align="center">tinybpf</h1>

<p align="center">
  Write eBPF programs in Go. Compile with TinyGo. Run in the Linux kernel.
</p>

<p align="center">
  <a href="https://github.com/kyleseneker/tinybpf/actions"><img src="https://github.com/kyleseneker/tinybpf/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://goreportcard.com/report/github.com/kyleseneker/tinybpf"><img src="https://goreportcard.com/badge/github.com/kyleseneker/tinybpf" alt="Go Report Card"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
</p>

---

## Overview

[eBPF](https://ebpf.io/) lets sandboxed programs run inside the Linux kernel. Today those programs must be written in C or Rust. `tinybpf` lets you write them in Go instead.

```mermaid
graph LR
    A["Go source"] --> B["TinyGo"]
    B --> C["LLVM IR"]
    C --> D["tinybpf"]
    D --> E["bpf.o"]
```

The output is a standard BPF ELF object compatible with [`cilium/ebpf`](https://github.com/cilium/ebpf), [`libbpf`](https://github.com/libbpf/libbpf), and [`bpftool`](https://github.com/libbpf/bpftool).

### Why TinyGo?

Standard Go compiles to native machine code via its own backend — there is no LLVM IR to retarget to BPF, and its runtime (GC, goroutines, channels) cannot run in the kernel. TinyGo compiles through LLVM and supports bare-metal mode (`-gc=none -scheduler=none -panic=trap`) with no runtime, producing IR that `tinybpf` transforms into verifier-friendly BPF bytecode.

### How it works

`tinybpf` sits between TinyGo's LLVM IR output and the final BPF ELF. It retargets the IR to BPF, strips the TinyGo runtime, rewrites helper calls to kernel form, and injects the metadata that loaders expect. See [Architecture](docs/ARCHITECTURE.md) for the full pipeline.

## Quick start

### Install

```bash
go install github.com/kyleseneker/tinybpf/cmd/tinybpf@latest
```

### Prerequisites

| Dependency | Version | Required |
|------------|---------|----------|
| Go | 1.24+ | Yes |
| TinyGo | 0.40+ | Yes |
| LLVM (`llvm-link`, `opt`, `llc`) | 20+ (>= TinyGo's bundled LLVM) | Yes |
| `llvm-ar`, `llvm-objcopy` | 20+ | For `.a` / `.o` inputs |
| `pahole` | | For BTF injection |

```bash
make setup    # install everything
make doctor   # verify toolchain
```

### Example

A tracepoint probe that captures outbound TCP connections, written entirely in Go:

```go
//go:extern bpf_get_current_pid_tgid
func bpfGetCurrentPidTgid() uint64

//go:extern bpf_probe_read_user
func bpfProbeReadUser(dst unsafe.Pointer, size uint32, src unsafe.Pointer) int64

//go:extern bpf_ringbuf_output
func bpfRingbufOutput(mapPtr unsafe.Pointer, data unsafe.Pointer, size uint64, flags uint64) int64

//export handle_connect
func handle_connect(ctx unsafe.Pointer) int32 {
    args := (*tpConnectArgs)(ctx)
    var sa sockaddrIn
    bpfProbeReadUser(unsafe.Pointer(&sa), uint32(unsafe.Sizeof(sa)), unsafe.Pointer(uintptr(args.Uservaddr)))
    if sa.Family != afINET {
        return 0
    }
    pid := uint32(bpfGetCurrentPidTgid() >> 32)
    ev := connectEvent{PID: pid, DstAddrBE: sa.AddrBE, DstPortBE: sa.PortBE, Proto: ipProtoTCP}
    bpfRingbufOutput(unsafe.Pointer(&events), unsafe.Pointer(&ev), uint64(unsafe.Sizeof(ev)), 0)
    return 0
}
```

Build:

```bash
tinybpf build --output program.o \
  --section handle_connect=tracepoint/syscalls/sys_enter_connect \
  ./bpf
```

### Examples

- [`tracepoint-connect/`](examples/tracepoint-connect/) — tracepoint + ring buffer + `cilium/ebpf` loader
- [`xdp-filter/`](examples/xdp-filter/) — XDP packet filter with hash map blocklist
- [`kprobe-openat/`](examples/kprobe-openat/) — kprobe tracing `openat` with ring buffer
- [`tc-filter/`](examples/tc-filter/) — TC classifier that drops packets by port
- [`cgroup-connect/`](examples/cgroup-connect/) — cgroup/connect4 connection blocker
- [`fentry-open/`](examples/fentry-open/) — fentry tracing `openat2` with ring buffer
- [`rawtp-sched/`](examples/rawtp-sched/) — raw tracepoint exec tracer with CO-RE portable struct access

### Scaffold a new project

```bash
tinybpf init xdp_filter
```

Generates a BPF source file, stub file for IDE compatibility, and a Makefile.

## CLI reference

Run `tinybpf --help` or `tinybpf <command> --help`.

### Subcommands

| Subcommand | Description |
|------------|-------------|
| `build [flags] <package>` | Compile Go source to BPF ELF in one step |
| `link --input <file> [flags]` | Link pre-compiled LLVM IR into a BPF ELF |
| `init <name>` | Scaffold a new BPF project |
| `doctor` | Check toolchain installation |
| `version` | Print version |

### Shared flags (build and link)

| Flag | Default | Description |
|------|---------|-------------|
| `--output`, `-o` | `bpf.o` | Output ELF path |
| `--program` | *(auto-detect)* | Program function to keep (repeatable) |
| `--section` | | Program-to-section mapping `name=section` (repeatable) |
| `--cpu` | `v3` | BPF CPU version for `llc -mcpu` |
| `--opt-profile` | `default` | `conservative`, `default`, `aggressive`, or `verifier-safe` |
| `--pass-pipeline` | | Explicit `opt` pass pipeline (overrides profile) |
| `--btf` | `false` | Inject BTF via `pahole` |
| `--verbose`, `-v` | `false` | Print each pipeline stage |
| `--timeout` | `30s` | Per-stage timeout |
| `--dump-ir` | `false` | Write intermediate IR after each transform stage |
| `--program-type` | | Validate sections match a BPF program type (e.g. `kprobe`, `xdp`) |
| `--core` | `false` | Enable CO-RE portable struct access (experimental) |
| `--keep-temp` | `false` | Preserve intermediate files |
| `--tmpdir` | | Directory for intermediate files |

### build-only flags

| Flag | Default | Description |
|------|---------|-------------|
| `--tinygo` | *(PATH)* | Path to tinygo binary |

### link-only flags

| Flag | Default | Description |
|------|---------|-------------|
| `--input` | *(required)* | Input file `.ll`, `.bc`, `.o`, `.a` (repeatable) |
| `--config` | | Path to `linker-config.json` for custom passes |
| `--jobs`, `-j` | `1` | Parallel input normalization workers |

### Tool path overrides

| Flag | Description |
|------|-------------|
| `--llvm-link` | Override `llvm-link` |
| `--opt` | Override `opt` |
| `--llc` | Override `llc` |
| `--llvm-ar` | Override `llvm-ar` |
| `--llvm-objcopy` | Override `llvm-objcopy` |
| `--pahole` | Override `pahole` |

## Documentation

| Document | Description |
|----------|-------------|
| [Writing Go for eBPF](docs/TINYGO_COMPAT.md) | Language constraints, BPF concepts, helpers, patterns, and FAQ |
| [Architecture](docs/ARCHITECTURE.md) | Pipeline design and the 13-step IR transformation |
| [Support Matrix](docs/SUPPORT_MATRIX.md) | Tested toolchain versions and platforms |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Setup issues, pipeline errors, and verifier debugging |
| [Contributing](CONTRIBUTING.md) | Development setup, testing, and PR process |

## Related projects

| Project | Relationship |
|---------|-------------|
| [cilium/ebpf](https://github.com/cilium/ebpf) | Go library for loading eBPF programs; loads `tinybpf` output |
| [bpf2go](https://pkg.go.dev/github.com/cilium/ebpf/cmd/bpf2go) | Compiles C eBPF and generates Go bindings; replaced when the program is Go |
| [libbpf](https://github.com/libbpf/libbpf) | C loader library; compatible with `tinybpf` output |
| [TinyGo](https://tinygo.org/) | Go compiler targeting LLVM; provides the IR that `tinybpf` transforms |
| [Aya](https://aya-rs.dev/) | eBPF in Rust; similar goal, different language |
| [miekg/bpf](https://github.com/miekg/bpf) | Prior effort to add BPF to TinyGo's LLVM; archived |

## License

[MIT](LICENSE)
