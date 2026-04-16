# Support Matrix

Tested versions for `tinybpf`.

## Toolchain

| Dependency | Versions | Notes |
|------------|----------|-------|
| Go | 1.24.x, 1.25.x | |
| TinyGo | 0.40.1 | Bundles LLVM 20.1.1 |
| LLVM | 20, 21, 22 | System LLVM must be >= TinyGo's bundled major |
| bpftool | 7.4.0 | Used for verifier validation on Linux |

TinyGo 0.40.x emits LLVM 20 IR; LLVM 18/19 cannot parse it. LLVM 20, 21, and
22 are forward-compatible.

## Platforms

| OS | Arch | Compile | Load |
|----|------|---------|------|
| Linux | amd64 | Yes | Yes |
| Linux | arm64 | Yes | Yes |
| macOS | arm64 | Yes | No (use QEMU VM) |

## Kernels

CO-RE relocations are exercised weekly via the `kernel-matrix` CI job using
the `rawtp-sched` example.

| Kernel | LTS EOL |
|--------|---------|
| 5.15 | Dec 2026 |
| 6.1 | Dec 2027 |
| 6.6 | Dec 2027 |
| 6.12 | Dec 2028 |
| 6.18 | Dec 2028 |

CO-RE requires `CONFIG_DEBUG_INFO_BTF=y` (default on most distros since 5.4).
