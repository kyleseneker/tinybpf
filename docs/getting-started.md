# Getting Started

For the build flow (scaffold -> build -> generate -> load) see the
[README quickstart](../README.md#quick-start). This page covers toolchain
installation only.

## Prerequisites

| Dependency | Version | Required | Purpose |
|------------|---------|----------|---------|
| Go | 1.24+ | Yes | Build `tinybpf` and userspace loaders |
| TinyGo | 0.40+ | Yes | Compile Go to LLVM IR |
| `llvm-link` | 20+ | Yes | Link IR modules |
| `opt` | 20+ | Yes | Optimization pass pipeline |
| `llc` | 20+ | Yes | BPF code generation |
| `llvm-ar` | 20+ | For `.a` inputs | Expand archive inputs |
| `llvm-objcopy` | 20+ | For `.o` inputs | Extract embedded bitcode |
| `pahole` | | For `--btf` | BTF metadata injection |

System LLVM must be >= the major version bundled with TinyGo (TinyGo 0.40.x
bundles LLVM 20).

- **Linux**: full support -- compile and load BPF programs.
- **macOS**: compile only. Loading into the kernel requires Linux; use a QEMU
  VM (see [CONTRIBUTING.md#vm-workflow](../CONTRIBUTING.md#vm-workflow)).

## Install

### Automated

```bash
git clone https://github.com/kyleseneker/tinybpf.git
cd tinybpf
make setup    # installs Go, TinyGo, LLVM, and tools for your OS
make doctor   # verify everything is working
```

### CLI only

```bash
go install github.com/kyleseneker/tinybpf/cmd/tinybpf@latest
```

### Verify

```bash
tinybpf doctor
```

`doctor` resolves each LLVM tool, prints its path and version, and warns if
anything is missing or too old.
