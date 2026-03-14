# Project Layout

Package map for contributors working on `tinybpf` internals.

```
cmd/tinybpf/               CLI entrypoint (main package)
internal/
  cli/                     Flag parsing, subcommand dispatch, config/CLI merge
  testutil/                Test helpers (fake LLVM tools, sample IR fixtures)
```

## Core pipeline

```
pipeline/                  Orchestration: normalize -> link -> transform -> opt -> codegen -> BTF -> validate
  normalize.go             Input normalization (.a expansion, .o bitcode extraction)
  pipeline.go              Stage sequencing, caching, verbose logging, artifact management
```

## IR processing

```
ir/                        LLVM IR parser, AST, serializer, and index
  parser.go                Parses LLVM IR text into *ir.Module AST
  serialize.go             Serializes AST back to IR text (round-trip safe)
  ast.go                   AST node types (Module, Function, Global, BasicBlock, etc.)
  testdata/                IR fixture files for parser/serializer tests

transform/                 TinyGo IR -> BPF IR rewriting (8 passes)
  stages.go                Pass registration, sequencing, and most pass implementations
  core.go                  CO-RE struct access, exists intrinsics, field names
  btfmap.go                map prefix strip, BTF encoding, name sanitization
  helpers.go               BPF helper name-to-ID mapping
  bpfhelpers_gen.go        Generated helper table (from kernel bpf.h)
  suggest.go               Fuzzy-match suggestions for unknown helper names
  irutil.go                IR utility functions shared across passes
  transform.go             Transform interface and types
```

## LLVM tooling

```
llvm/                      Tool discovery, optimization profiles, process execution
  runner.go                Binary validation, environment sanitization, exec with timeout
  passes.go                Named optimization profiles and custom pass validation
  discover.go              Tool path resolution (PATH, config, versioned names)
```

## Validation and diagnostics

```
elfcheck/                  Post-link ELF validation (class, machine, sections, symbols)
diag/                      Structured error types with stage context, hints, and snippets
```

## Build infrastructure

```
cache/                     Content-addressed build cache for pipeline artifacts
  cache.go                 SHA-256 keying, shard storage, atomic writes
config/                    Project config loading (tinybpf.json), validation, and merge
  config.go                Config struct, file parsing, field defaults
  convert.go               Config-to-pipeline conversion, tool resolution
doctor/                    Toolchain diagnostic subcommand (tool discovery, version checks)
scaffold/                  Project scaffolding (tinybpf init)
```

## Examples

```
examples/
  tracepoint-connect/      Tracepoint + ring buffer + cilium/ebpf loader
  kprobe-openat/           Kprobe tracing with pt_regs context
  fentry-open/             Fentry BTF-based tracing
  rawtp-sched/             Raw tracepoint + CO-RE + perf event array
  cgroup-connect/          Cgroup connect4 + hash map policy
  xdp-filter/              XDP packet filter + hash map blocklist
  tc-filter/               TC classifier + port-based filtering
```

Examples are unified under a Go workspace (`go.work`) for IDE navigation and cross-module refactoring. Each example retains its own `go.mod` for independent dependency management. Build any example with `make example NAME=<name>`.

## Scripts

```
scripts/
  setup.sh                 Install all development dependencies (macOS + Linux)
  create-vm.sh             Create and boot an Ubuntu 24.04 QEMU VM for testing
  e2e.sh                   End-to-end validation (TinyGo -> pipeline -> verifier -> attach)
  kernel-matrix.sh         CO-RE validation across kernel versions (used by CI)
```

## Key files for common tasks

| Task | Start here |
|------|-----------|
| Add a CLI flag | `internal/cli/root.go` (shared flags), `internal/cli/build.go` or `link.go` (command-specific) |
| Add a config field | `config/config.go` (struct), `internal/cli/root.go` (merge logic) |
| Add a transform pass | `transform/stages.go` (registration), new file in `transform/` |
| Change optimization profiles | `llvm/passes.go` |
| Change ELF validation | `elfcheck/validate.go` |
| Change doctor checks | `doctor/doctor.go` |
| Change scaffolded output | `scaffold/scaffold.go` |
| Add a new example | Copy an existing `examples/` directory and adapt |
