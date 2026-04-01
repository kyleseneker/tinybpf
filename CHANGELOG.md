# Changelog

All notable changes to tinybpf are documented in this file. Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- `tinybpf generate` command for type-safe Go loader codegen from BPF ELF objects
- `Result.Programs` and `Result.Maps` fields populated from output ELF
- `lsm-file-open` example (LSM security audit hook with ring buffer)
- `percpu-counter` example (per-CPU array map with syscall counting)
- kfunc support via `bpfKfunc` naming convention (extern preservation for BTF-based resolution)
- Stack usage warnings when `alloca` instructions approach the 512-byte BPF limit
- `COMPATIBILITY.md` defining the v1.0 semver contract
- `CHANGELOG.md`
- `GOVERNANCE.md`
- Example test functions for pkg.go.dev documentation
- Comprehensive godoc on `diag` package fields, methods, and stage constants
- Table-driven tests for codegen and generate CLI (97.5% coverage)

### Changed
- All 9 examples converted to `LoadAndAssign` with typed `Objects`/`Programs`/`Maps` structs
- All example READMEs standardized (mermaid diagrams, prerequisites, troubleshooting tables)
- All example `cmd/main.go` files use context-based signal handling
- README rewritten with "Why tinybpf?" value proposition, comparison table, and grouped examples
- Getting-started guide restructured as numbered steps with complete end-to-end workflow
- Scaffold Makefile includes `generate` target
- `docs/examples.md` updated with Security track and all 9 examples

### Fixed
- Makefile `bench` target path (`./transform/` → `./internal/transform/`)
- `docs/config-reference.md` BTF and Cache field types documented as optional
- `docs/project-layout.md` updated with `codegen/` package and new examples
- Committed example binaries removed and added to `.gitignore`

### Removed
- `struct_ops` from supported program types (incompatible with Go — requires function pointers as struct members)

## [0.7.0] - 2026-04-01

### Added
- Test coverage for per-CPU maps, map-in-map, ring buffer reserve/submit, tail calls, spinlocks, LSM sections, and multi-program extraction
- kfunc extern preservation in helper rewriting pass
- Stack usage analysis warning pass
- LSM and LSM-sleepable program type validation tests
- btfmap tests for per-CPU hash, per-CPU array, LRU hash, prog array, array-of-maps, and LPM trie

### Fixed
- Release workflow restored with binary smoke tests and SBOM generation

### Removed
- `struct_ops` from `knownProgramTypes` (fundamentally incompatible with Go)

## [0.6.0] - 2026-03-14

### Added
- Public library API: `tinybpf.Build()` facade for programmatic compilation
- Pure Go LLVM IR parser replacing 15 line-based stages with 8 AST-based passes
- Content-addressed build cache for pipeline stages
- `tinybpf.json` project config replacing `linker-config.json`
- `tinybpf verify` command for offline ELF validation
- CO-RE `bpfCoreFieldExists` and `bpfCoreTypeExists` intrinsics
- BPF helper table auto-generated from kernel `bpf.h` (pinned to kernel v6.18)
- Go workspace and `make example` target
- Multi-error diagnostics with fuzzy helper name suggestions

### Changed
- All implementation packages moved under `internal/`
- Config package produces `tinybpf.Request` directly

## [0.5.0] - 2026-02-23

### Added
- CO-RE exists intrinsics for compile-time field probing
- `--program-type` flag for section validation
- 211 BPF helpers (up from 68)
- Data section transform (`.data`, `.bss`, `.rodata`)
- `tc-filter`, `cgroup-connect`, and `fentry-open` examples
- Release artifact smoke testing
- Multi-kernel CI matrix for CO-RE validation

### Changed
- Scaffold uses `tinybpf build` instead of two-step workflow
- `network-sidecar` example renamed to `tracepoint-connect`

## [0.4.0] - 2026-02-22

### Added
- `xdp-filter` and `kprobe-openat` examples
- `--dump-ir` flag for intermediate IR stage snapshots
- Diagnostic errors with IR line numbers and snippets
- 5/6-field map BTF with pinning and zeroinitializer support
- Pahole discovery and version check in doctor
- `.maps` section executable flag validation
- BPF helper coverage expanded to 68

### Changed
- All tests migrated to table-driven style
- Cyclomatic complexity reduced across production code

## [0.3.0] - 2026-02-21

### Added
- Transform benchmarks (`BenchmarkTransformLines`)
- CI benchmark gate and LLVM matrix

### Changed
- 3.67x faster transform pipeline (hot-path regex eliminated)
- CI upgraded to Go 1.24/1.25, LLVM 20/21

## [0.2.0] - 2026-02-18

### Added
- `tinybpf build` command (compile Go source to BPF ELF in one step)
- `tinybpf init` command for project scaffolding
- `--help` support with consistent usage formatting
- 44 BPF helpers with fuzz tests
- Troubleshooting guide and enhanced doctor diagnostics
- Coverage gate, fuzz smoke tests, govulncheck, SBOM, security policy

## [0.1.0] - 2026-02-17

### Added
- Initial release: `tinybpf link` command for linking pre-compiled LLVM IR to BPF ELF
- 8-pass IR transformation pipeline
- CI with GoReleaser, linting, and tests
- `tracepoint-connect` example
