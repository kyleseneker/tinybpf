<p align="center">
  <strong>tinybpf</strong><br>
  Write eBPF programs in Go. Compile with TinyGo. Run in the Linux kernel.
</p>

<p align="center">
  <a href="https://github.com/kyleseneker/tinybpf/actions"><img src="https://github.com/kyleseneker/tinybpf/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://goreportcard.com/report/github.com/kyleseneker/tinybpf"><img src="https://goreportcard.com/badge/github.com/kyleseneker/tinybpf" alt="Go Report Card"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
</p>

---

## Overview

[eBPF](https://ebpf.io/) allows sandboxed programs to run inside the Linux kernel without modifying kernel source or loading kernel modules. Today, eBPF programs must be written in C or [Rust](https://aya-rs.dev/) and compiled to BPF bytecode that passes the kernel verifier.

The Go ecosystem provides mature userspace eBPF tooling ([`cilium/ebpf`](https://github.com/cilium/ebpf) for program loading and [`bpf2go`](https://pkg.go.dev/github.com/cilium/ebpf/cmd/bpf2go) for generating Go bindings) but the kernel-side program itself has always required C.

`tinybpf` removes that requirement. Write the BPF program in Go, compile it with [TinyGo](https://tinygo.org/), and `tinybpf` produces a valid eBPF ELF object that the kernel accepts.

```mermaid
graph LR
    A["Go source"] --> B["TinyGo"]
    B --> C["LLVM IR"]
    C --> D["tinybpf"]
    D --> E["bpf.o"]
```

The output is compatible with [`cilium/ebpf`](https://github.com/cilium/ebpf), [`libbpf`](https://github.com/libbpf/libbpf), and [`bpftool`](https://github.com/libbpf/bpftool).

## How it works

`tinybpf` sits between TinyGo's LLVM IR output and the final BPF ELF object. It performs a multi-step IR transformation that retargets the IR from the host architecture to BPF, strips the TinyGo runtime, rewrites helper calls to kernel-compatible form, and injects the metadata that loaders like `cilium/ebpf` and `libbpf` expect.

See [Architecture](docs/ARCHITECTURE.md) for the full pipeline design.

## Quick start

### Installation

```bash
go install github.com/kyleseneker/tinybpf/cmd/tinybpf@latest
```

Or build from source:

```bash
git clone https://github.com/kyleseneker/tinybpf.git
cd tinybpf
make build
```

### Prerequisites

| Dependency | Version | Required |
|------------|---------|----------|
| Go | 1.24+ | Yes |
| TinyGo | 0.40+ | Yes |
| LLVM (`llvm-link`, `opt`, `llc`) | 20+ (>= TinyGo's bundled LLVM) | Yes |
| `llvm-ar`, `llvm-objcopy` | 20+ | For `.a` / `.o` inputs |
| `pahole` | | For BTF injection |

Install everything with one command:

```bash
make setup
```

Run `make doctor` to verify your toolchain.

### Example

A tracepoint probe that captures outbound TCP connections, written entirely in Go:

```go
// tpConnectArgs mirrors the tracepoint context for syscalls/sys_enter_connect.
type tpConnectArgs struct {
    _         [24]byte
    Uservaddr uint64
}

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

Compile and link in one step:

```bash
tinybpf build --output program.o \
  --section handle_connect=tracepoint/syscalls/sys_enter_connect \
  ./bpf
```

Or, if you prefer the two-step workflow:

```bash
tinygo build -o program.ll -gc=none -scheduler=none -panic=trap -opt=1 ./bpf

tinybpf link --input program.ll --output program.o \
  --section handle_connect=tracepoint/syscalls/sys_enter_connect
```

See the [`examples/`](examples/) directory for complete working projects:

- [`network-sidecar/`](examples/network-sidecar/) — tracepoint probe with ring buffer and `cilium/ebpf` userspace loader
- [`xdp-filter/`](examples/xdp-filter/) — XDP packet filter with hash map blocklist
- [`kprobe-openat/`](examples/kprobe-openat/) — kprobe tracing `openat` syscalls with ring buffer events

### Scaffold a new project

```bash
tinybpf init xdp_filter
```

This generates `bpf/xdp_filter.go` with build tags and an empty entry point, `bpf/xdp_filter_stub.go` for IDE compatibility, and a `Makefile` with TinyGo and tinybpf build commands. Fill in the ELF section type and program logic to match your use case.

## CLI reference

Run `tinybpf --help` for a quick overview, or `tinybpf <command> --help` for details on a specific command.

### Subcommands

| Subcommand | Description |
|------------|-------------|
| `build [flags] <package>` | Compile Go source to BPF ELF in one step (runs TinyGo + link pipeline) |
| `link --input <file> [flags]` | Link TinyGo LLVM IR into a BPF ELF object |
| `init <name>` | Scaffold a new BPF project in the current directory |
| `doctor` | Check toolchain installation and version compatibility |
| `version` | Print version information |
| `help` | Show usage overview (also `--help`, `-h`) |

The bare-flag form `tinybpf --input <file> [flags]` still works as an alias for `link`.

### Shared flags (build and link)

| Flag | Default | Description |
|------|---------|-------------|
| `--output`, `-o` | `bpf.o` | Output ELF path. |
| `--program` | *(auto-detect)* | Program function to keep. Repeatable. |
| `--section` | | Program-to-section mapping (`name=section`). Repeatable. |
| `--cpu` | `v3` | BPF CPU version for `llc -mcpu`. |
| `--opt-profile` | `default` | `conservative`, `default`, `aggressive`, or `verifier-safe`. |
| `--pass-pipeline` | | Explicit `opt` pass pipeline (overrides profile). |
| `--btf` | `false` | Inject BTF via `pahole`. |
| `--verbose`, `-v` | `false` | Print each pipeline stage. |
| `--timeout` | `30s` | Per-stage timeout. |
| `--dump-ir` | `false` | Write intermediate IR after each transform stage. |
| `--keep-temp` | `false` | Preserve intermediate files for debugging. |
| `--tmpdir` | | Directory for intermediate files. |

### build-only flags

| Flag | Default | Description |
|------|---------|-------------|
| `--tinygo` | *(PATH)* | Path to tinygo binary. |

### link-only flags

| Flag | Default | Description |
|------|---------|-------------|
| `--input` | *(required)* | Input file (`.ll`, `.bc`, `.o`, `.a`). Repeatable. |
| `--config` | | Path to `linker-config.json` for custom passes. |
| `--jobs`, `-j` | `1` | Parallel input normalization workers. |

### Tool path overrides (build and link)

| Flag | Description |
|------|-------------|
| `--llvm-link` | Override path to `llvm-link`. |
| `--opt` | Override path to `opt`. |
| `--llc` | Override path to `llc`. |
| `--llvm-ar` | Override path to `llvm-ar`. |
| `--llvm-objcopy` | Override path to `llvm-objcopy`. |
| `--pahole` | Override path to `pahole`. |

## Documentation

| Document | Description |
|----------|-------------|
| [Writing Go for eBPF](docs/TINYGO_COMPAT.md) | Language constraints, program structure, and supported BPF helpers |
| [Architecture](docs/ARCHITECTURE.md) | Pipeline design and the 11-step IR transformation |
| [Support Matrix](docs/SUPPORT_MATRIX.md) | Tested toolchain versions and platforms |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Setup issues, pipeline errors, and verifier debugging |
| [Contributing](CONTRIBUTING.md) | Development setup, guidelines, and PR process |

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
