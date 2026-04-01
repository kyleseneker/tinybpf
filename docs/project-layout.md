# Project Layout

Package map for contributors working on `tinybpf` internals.

## Public API

```
tinybpf.go                 Request, Result, Toolchain types — the stable SDK surface
build.go                   Build() entrypoint — validates, compiles, and orchestrates the pipeline
```

Import as:

```go
import "github.com/kyleseneker/tinybpf"
```

## Supporting public packages

```
config/                    Project config loading (tinybpf.json), validation, and merge
  config.go                Config struct, file parsing, field defaults
  convert.go               Config-to-Request conversion, tool resolution

diag/                      Structured error types with stage context, hints, and snippets

elfcheck/                  Post-link ELF validation (class, machine, sections, symbols)
```

## CLI

```
cmd/tinybpf/               CLI entrypoint (main package)
internal/
  cli/                     Flag parsing, subcommand dispatch, config/CLI merge
```

## Internal implementation

Everything below `internal/` is hidden from external consumers.

### Core pipeline

```
internal/
  pipeline/                Orchestration: normalize -> link -> transform -> opt -> codegen -> BTF -> validate
    pipeline.go            Stage sequencing, caching, verbose logging, BTF injection
    normalize.go           Input normalization (.a expansion, .o bitcode extraction)
    progtype.go            BPF program type validation and section name mapping
```

### IR processing

```
internal/
  ir/                      LLVM IR parser, AST, and serializer
    ast.go                 AST node types (Module, Function, Global, BasicBlock, etc.)
    parse.go               Parses LLVM IR text into *ir.Module AST
    parse_inst.go          Instruction-level parsing
    parse_meta.go          Metadata and attribute parsing
    serialize.go           Serializes AST back to IR text (round-trip safe)
    testdata/              IR fixture files for parser/serializer tests

  transform/               TinyGo IR -> BPF IR rewriting (8 passes)
    transform.go           Transform interface and types
    stages.go              Pass registration, sequencing, and most pass implementations
    core.go                CO-RE struct access, exists intrinsics, field names
    btfmap.go              map prefix strip, BTF encoding, name sanitization
    helpers.go             BPF helper name-to-ID mapping
    bpfhelpers_gen.go      Generated helper table (from kernel bpf.h)
    gen.go                 Code generation tooling for bpfhelpers_gen.go
    suggest.go             Fuzzy-match suggestions for unknown helper names
    irutil.go              IR utility functions shared across passes
```

### LLVM tooling

```
internal/
  llvm/                    Tool discovery, optimization profiles, process execution
    runner.go              Tool resolution, binary validation, environment sanitization, exec with timeout
    passes.go              Named optimization profiles and custom pass validation
```

### Other internal packages

```
internal/
  cache/                   Content-addressed build cache for pipeline artifacts
  codegen/                 Go loader code generation from BPF ELF objects (tinybpf generate)
  doctor/                  Toolchain diagnostic subcommand (tool discovery, version checks)
  scaffold/                Project scaffolding (tinybpf init)
  testutil/                Test helpers (fake LLVM tools, sample IR fixtures)
```

## Examples

```
examples/
  tracepoint-connect/      Tracepoint + ring buffer + cilium/ebpf loader
  kprobe-openat/           Kprobe tracing with pt_regs context
  fentry-open/             Fentry BTF-based tracing
  rawtp-sched/             Raw tracepoint + CO-RE + perf event array
  lsm-file-open/           LSM security audit hook + ring buffer
  percpu-counter/          Per-CPU array map + syscall counting
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
| Use tinybpf as a library | `tinybpf.go` (types), `build.go` (Build function) |
| Add a CLI flag | `internal/cli/root.go` (shared flags), `internal/cli/build.go` or `link.go` (command-specific) |
| Add a config field | `config/config.go` (struct), `config/convert.go` (to Request), `internal/cli/root.go` (merge logic) |
| Add a transform pass | `internal/transform/stages.go` (registration), new file in `internal/transform/` |
| Change optimization profiles | `internal/llvm/passes.go` |
| Change ELF validation | `elfcheck/validate.go` |
| Change doctor checks | `internal/doctor/doctor.go` |
| Change scaffolded output | `internal/scaffold/scaffold.go` |
| Add a new example | Copy an existing `examples/` directory and adapt |
