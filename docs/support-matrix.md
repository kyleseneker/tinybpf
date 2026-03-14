# Support Matrix

Tested toolchain versions and platforms for `tinybpf`.

## Toolchain versions

| Dependency | Tested versions | Notes |
|------------|-----------------|-------|
| Go | 1.24.x, 1.25.x | |
| TinyGo | 0.40.1 | Bundles LLVM 20.1.1 |
| LLVM | 20, 21, 22 | System LLVM must be >= TinyGo's bundled LLVM major version |
| bpftool | 7.4.0 | Used for verifier validation on Linux |

### LLVM version compatibility

TinyGo 0.40.x emits LLVM 20 IR. System LLVM tools (`llvm-link`, `opt`, `llc`) must be version 20 or later to parse it.

| System LLVM | Compatible | Notes |
|-------------|------------|-------|
| 18 | No | Cannot parse LLVM 20 IR (`#dbg_value` syntax, `nuw` on GEP) |
| 19 | No | Cannot parse LLVM 20 IR (`nuw` on GEP, unsupported attributes) |
| 20 | Yes | Matches TinyGo 0.40.x |
| 21 | Yes | Forward-compatible with LLVM 20 IR |
| 22 | Yes | Forward-compatible with LLVM 20 IR |

## Required LLVM binaries

| Binary | Purpose |
|--------|---------|
| `llvm-link` | IR module linking |
| `opt` | Optimization pass pipeline |
| `llc` | BPF code generation |

## Optional binaries

| Binary | Purpose |
|--------|---------|
| `llvm-ar` | Expanding `.a` archive inputs |
| `llvm-objcopy` | Extracting embedded bitcode from `.o` inputs |
| `pahole` | BTF injection (`--btf` flag) |

## CI matrix

CI runs on Ubuntu 24.04 with the following matrix:

| Dimension | Values |
|-----------|--------|
| Go | 1.24.x, 1.25.x |
| LLVM | 20, 21, 22 |
| Primary lane | Go 1.25.x + LLVM 20 |

The primary lane enforces:
- 90% coverage threshold
- Binary size limit (15 MiB)
- Fuzz smoke tests (10s per target)

## Kernel validation

| Kernel | Distribution | Architecture | Result |
|--------|-------------|--------------|--------|
| 6.8.0-100 | Ubuntu 24.04 | arm64 | Verifier accepted, tracepoint attached, events captured |

## CO-RE kernel matrix

CO-RE relocations are tested across active LTS kernel versions via the `kernel-matrix` CI workflow (weekly, using the `rawtp-sched` example):

| Kernel | LTS EOL | CO-RE status |
|--------|---------|-------------|
| 5.15 | Dec 2026 | Tested |
| 6.1 | Dec 2027 | Tested |
| 6.6 | Dec 2027 | Tested |
| 6.12 | Dec 2028 | Tested |
| 6.18 | Dec 2028 | Tested |

CO-RE requires a kernel with BTF support (`CONFIG_DEBUG_INFO_BTF=y`), which is enabled by default on most distributions since kernel 5.4+.

## Platform support

| OS | Architecture | Compilation | Kernel loading |
|----|-------------|-------------|----------------|
| Linux | amd64 | Yes | Yes |
| Linux | arm64 | Yes | Yes (validated) |
| macOS | arm64 | Yes (through `llc`) | No (requires Linux) |

See [Troubleshooting](troubleshooting.md#debugging-flags-summary) for debugging flags and [Contributing](../CONTRIBUTING.md#running-tests) for testing details.
