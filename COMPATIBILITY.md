# Compatibility

This document defines what the v1.0 semver contract covers. Once `tinybpf` reaches v1.0, breaking changes to the items below require a v2 module path.

## Covered by semver

### Public Go API

The exported types, functions, methods, and constants in these packages:

- **`tinybpf`** — `Request`, `Result`, `Toolchain`, `Build()`
- **`config`** — `Config`, `Build`, `Toolchain`, `Filename`, `Load()`, `Find()`, `ParseTimeout()`, `ToRequest()`, `ResolveToolchain()`
- **`diag`** — `Stage`, all `Stage*` constants, `Error`, `Errors`, `IsStage()`, `Wrap()`, `WrapCmd()`, `WrapErrors()`
- **`elfcheck`** — `Validate()`

New types, functions, fields, and constants may be added. Existing symbols will not be removed or have their signatures changed.

### CLI flags and exit codes

- Flag names, default values, and semantics for all commands (`build`, `link`, `init`, `verify`, `generate`, `doctor`, `clean-cache`, `version`)
- Exit codes: 0 (success), 1 (runtime error), 2 (usage error)

New flags may be added. Existing flags will not be removed or change meaning.

### Config file schema

- The `tinybpf.json` structure: `build` and `toolchain` sections with their current field names and types
- Auto-discovery behavior (walking parent directories for `tinybpf.json`)

New fields may be added with zero-value defaults. Existing fields will not be removed or change semantics.

### ELF output format

- BPF ELF objects produced by `tinybpf` will remain loadable by `cilium/ebpf`, `libbpf`, and `bpftool`
- ELF section naming conventions for program types (e.g. `kprobe/`, `xdp`, `lsm/`)
- Map definitions in `.maps` section with BTF encoding
- GPL license section

### Generated code shape

- `tinybpf generate` output follows the `Objects`/`Programs`/`Maps` struct pattern with `ebpf:"tag"` struct tags
- Generated `Load()` function uses `CollectionSpec.LoadAndAssign()`
- Generated `Close()` methods on all three structs

## Not covered by semver

These may change between minor versions without notice:

- **Internal packages** (`internal/pipeline`, `internal/transform`, `internal/ir`, `internal/llvm`, `internal/cache`, `internal/codegen`, `internal/cli`, `internal/doctor`, `internal/scaffold`, `internal/testutil`)
- **LLVM IR intermediate format** — the IR between pipeline stages
- **Cache key format** — content-addressed cache structure and key computation
- **Diagnostic message text** — the exact wording of error messages, hints, and warnings
- **Generated code formatting** — whitespace, import ordering, and comment style in `tinybpf generate` output
- **Build artifact paths** — intermediate file naming within temp directories
