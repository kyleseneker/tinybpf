# Examples Guide

The `examples/` directory contains complete, working BPF programs that demonstrate different hook types and patterns. Each example includes a BPF program in Go, a userspace loader, build scripts, and a README with specifics.

## Learning tracks

### Tracing

Start here if you want to observe kernel events.

| Order | Example | Hook type | Concepts |
|-------|---------|-----------|----------|
| 1 | [tracepoint-connect](../examples/tracepoint-connect/) | Tracepoint | Ring buffer, event struct, `cilium/ebpf` loader |
| 2 | [kprobe-openat](../examples/kprobe-openat/) | Kprobe | Function tracing, `pt_regs`, architecture-specific offsets |
| 3 | [fentry-open](../examples/fentry-open/) | Fentry | BTF-based tracing, requires kernel 5.5+ |
| 4 | [rawtp-sched](../examples/rawtp-sched/) | Raw tracepoint | CO-RE portable structs, perf event array, `bpfCoreFieldExists` |

### Networking and policy

Start here if you want to filter or control traffic.

| Order | Example | Hook type | Concepts |
|-------|---------|-----------|----------|
| 1 | [cgroup-connect](../examples/cgroup-connect/) | Cgroup | Hash map blocklist, connection allow/deny |
| 2 | [xdp-filter](../examples/xdp-filter/) | XDP | Packet parsing, source IP blocklist, `XDP_DROP`/`XDP_PASS` |
| 3 | [tc-filter](../examples/tc-filter/) | TC classifier | Port-based filtering, TC ingress attachment |

## How to build any example

From the repo root, `make example` builds the `tinybpf` binary, compiles the BPF object, and builds the Go loader in one command:

```bash
make example NAME=tracepoint-connect
```

Alternatively, each example has a standalone `scripts/build.sh`:

```bash
cd examples/<name>
./scripts/build.sh
```

Both methods:
1. Build a local `tinybpf` binary (unless `TINYBPF_BIN` is set).
2. Run `tinybpf build --verbose ./bpf`.
3. Produce a BPF ELF object and loader binary in `build/`.

### Build environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TINYBPF_BIN` | *(built from repo root)* | Path to a pre-built `tinybpf` binary |
| `BPF_CPU` | `v3` | BPF CPU version passed to `llc -mcpu` |

## How to run any example

Most examples include `scripts/run.sh`:

```bash
sudo ./scripts/run.sh
```

Running requires:
- **Linux** with kernel BPF support
- **Root** or appropriate capabilities (varies by hook type)

### Required capabilities by hook type

| Hook type | Capabilities |
|-----------|-------------|
| Tracepoint, kprobe, fentry, raw tracepoint | `CAP_BPF` + `CAP_PERFMON` |
| XDP, TC, cgroup | `CAP_BPF` + `CAP_NET_ADMIN` |

On macOS, build the BPF object locally and use a Linux VM for loading. See [Contributing](../CONTRIBUTING.md#vm-workflow) for the VM workflow.

## Example structure

All examples follow the same layout:

```
bpf/
  <program>.go           BPF program source (//go:build tinygo)
  <program>_stub.go      Build tag stub for standard Go tooling
cmd/<loader>/
  main.go                Userspace entry point
internal/
  loader/                ELF loading and attachment (cilium/ebpf)
  reader/                Event read loop (when applicable)
  event/                 Event struct and decoding (when applicable)
tinybpf.json             Build configuration
scripts/
  build.sh               Build pipeline
  run.sh                 Build and run (when present)
```

## Troubleshooting examples

| Symptom | Resolution |
|---------|------------|
| Build fails | Run `tinybpf doctor` to check your toolchain |
| Permission denied at load/attach | Run as root or grant the required capabilities |
| No events after attaching | Generate the expected traffic or syscall (each example README explains how) |
| Attach failure | Check kernel version and hook availability (each example README lists its requirements) |

For general troubleshooting, see [Troubleshooting](troubleshooting.md).
