# Changelog

All notable changes to tinybpf are documented in this file. Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- `tinybpf generate` with `//go:embed` loader when BPF object is reachable from output directory
- Scaffold generates `gen.go` with `//go:generate` directives
- Age-based cache eviction (30-day default, automatic on cache open)
- Auto-detection warning when multiple programs found without `--programs`
- `lsm-file-open` and `percpu-counter` examples
- `kfunc-task` example: end-to-end validation of the kfunc path via `bpf_task_from_pid` + `bpf_task_release`
- kfunc support, stack usage warnings
- Auto-infer `--program-type` from `--section` values when omitted
- Scheduled `helper-table-update` workflow: monthly refresh of the BPF helper table from the latest stable kernel tag on kernel.org; opens a PR when the upstream table changes

### Changed
- Bumped `github.com/cilium/ebpf` from v0.20.0 to v0.21.0 across all example modules
- Split monolithic `stages.go` (1813 lines) into 8 per-pass files (`pass_*.go`), merged `core.go` and `btfmap.go` into their respective pass files
- Transform passes use structured AST instead of regex on raw IR lines
- Cache keys include tool version fingerprints (in-place LLVM upgrades invalidate cache)
- `consumeLinkage` refactored to token-based scanner
- `copyFile` streams with `io.Copy` instead of buffering entire file
- All examples use `LoadAndAssign` with typed structs; READMEs standardized
- Documented iterator programs as unsupported; `--program-type iter` and `iter/` sections now produce an explicit error
- CI shrunk to a single PR-gating lane (Linux amd64, Go 1.25, LLVM 20) plus lint and examples; the full compatibility matrix (Go 1.24/1.25 × LLVM 20/21/22 × amd64/arm64, macOS, fuzz, bench) moved to a new weekly `compat.yml` workflow

### Fixed
- CO-RE field offset computation accounts for struct alignment padding
- Misc docs and Makefile path fixes
- Attribute groups emptied by stripping now retain `nounwind` so `opt` accepts them
- Strip `call void @abort()` from TinyGo panic paths; `unreachable` terminator preserves semantics and avoids BPF llc rejecting `abort`
- CO-RE offset discovery skips GEPs with non-integer trailing operands instead of aborting the whole transform

### Removed
- `struct_ops` program type (incompatible with Go)
- `iter/` program type from `knownProgramTypes`; iterator programs are now rejected with an explicit error and documented as unsupported
- `docs/examples.md` (duplicated README tables and per-example READMEs)
- Verbose FAQ, "BPF in a nutshell", and "Why TinyGo" intro from `writing-go-for-ebpf.md`
- Expanded prose in architecture "Design decisions"; collapsed to a bullet list
- `getting-started.md` trimmed to toolchain prerequisites + install (build flow lives in README)
- `CONTRIBUTING.md` trimmed to dev setup + VM workflow (no imagined-contributor PR process)
- `support-matrix.md` trimmed (CI matrix section redundant with workflow file)
- `GOVERNANCE.md` and `COMPATIBILITY.md` -- premature v1.0-style governance and semver commitments for a solo-maintained 0.x project with no users to make promises to

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
