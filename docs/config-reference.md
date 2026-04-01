# Config Reference

`tinybpf.json` stores project-level build settings. The CLI auto-discovers this file by walking parent directories from the current working directory (like `go.mod`). CLI flags override config values for one-off invocations.

## Auto-discovery

When `--config` is not set, `tinybpf` searches for `tinybpf.json` starting from the working directory and walking upward. If no file is found, built-in defaults and CLI flags apply.

To use a specific config file:

```bash
tinybpf build --config path/to/tinybpf.json ./bpf
```

## Schema

```json
{
  "build": {
    "output": "build/probe.bpf.o",
    "cpu": "v3",
    "opt_profile": "verifier-safe",
    "btf": true,
    "cache": true,
    "timeout": "30s",
    "programs": {
      "handle_connect": "tracepoint/syscalls/sys_enter_connect"
    },
    "custom_passes": ["inline", "dce"]
  },
  "toolchain": {
    "llvm_dir": "/usr/lib/llvm-20/bin",
    "tinygo": "/usr/local/bin/tinygo"
  }
}
```

All fields are optional.

## Build fields

| Field | JSON key | Type | Default | Description |
|-------|----------|------|---------|-------------|
| Output | `output` | string | `"bpf.o"` | Output ELF path |
| CPU | `cpu` | string | `"v3"` | BPF CPU version for `llc -mcpu` |
| Optimization profile | `opt_profile` | string | `"default"` | Named optimization profile |
| BTF | `btf` | bool (optional) | `false` | Enable BTF injection via `pahole`. Omit to inherit CLI default. |
| Cache | `cache` | bool (optional) | `true` | Enable content-addressed build cache. Omit to inherit CLI default. |
| Timeout | `timeout` | string | `"30s"` | Per-stage timeout (Go duration format) |
| Programs | `programs` | map[string]string | | Program function name to ELF section mapping |
| Custom passes | `custom_passes` | []string | | Additional LLVM opt passes to append |

### Programs

Maps exported Go function names to ELF section names. The section name determines the BPF program type and kernel attachment point.

```json
{
  "build": {
    "programs": {
      "handle_connect": "tracepoint/syscalls/sys_enter_connect",
      "xdp_filter": "xdp"
    }
  }
}
```

When omitted, programs are auto-detected from exported functions.

### Custom passes

Additional LLVM opt passes appended to the optimization pipeline. Each pass name is validated against a strict pattern (`^-?[a-zA-Z][a-zA-Z0-9-]*(<...>)?$`) to prevent command injection.

```json
{
  "build": {
    "custom_passes": ["inline", "instcombine"]
  }
}
```

Custom passes are appended regardless of `opt_profile`. To replace the entire pipeline, use the `--pass-pipeline` CLI flag instead.

### Optimization profiles

| Profile | LLVM pipeline | Description |
|---------|--------------|-------------|
| `conservative` | `default<O1>` | Minimal optimization; preserves IR structure |
| `default` | `default<Os>` | Size-optimized; fits BPF instruction count budgets |
| `aggressive` | `default<O2>` | Maximum optimization |
| `verifier-safe` | *(hand-tuned)* | Excludes loop unrolling and vectorization |

## Toolchain fields

| Field | JSON key | Type | Default | Description |
|-------|----------|------|---------|-------------|
| LLVM directory | `llvm_dir` | string | | Common directory for all LLVM tools |
| llvm-link | `llvm_link` | string | | Path to `llvm-link` |
| opt | `opt` | string | | Path to `opt` |
| llc | `llc` | string | | Path to `llc` |
| llvm-ar | `llvm_ar` | string | | Path to `llvm-ar` |
| llvm-objcopy | `llvm_objcopy` | string | | Path to `llvm-objcopy` |
| pahole | `pahole` | string | | Path to `pahole` |
| TinyGo | `tinygo` | string | | Path to `tinygo` |

### Tool resolution

For each LLVM tool, the resolution order is:

1. Explicit tool field (e.g. `toolchain.llvm_link`)
2. `toolchain.llvm_dir` + tool basename (e.g. `/usr/lib/llvm-20/bin/llvm-link`)
3. `PATH` lookup

TinyGo resolution: `toolchain.tinygo` > `tinygo` on `PATH`.

## Precedence

CLI flags always override config file values. For each field, the config value is only used when the corresponding CLI flag is not set.

| Config field | CLI flag | Behavior |
|-------------|----------|----------|
| `build.output` | `--output` / `-o` | Flag wins if set |
| `build.cpu` | `--cpu` | Flag wins if set |
| `build.opt_profile` | `--opt-profile` | Flag wins if set |
| `build.btf` | `--btf` | Flag wins if set |
| `build.cache` | `--cache` | Flag wins if set |
| `build.timeout` | `--timeout` | Flag wins if set |
| `build.programs` | `--program` + `--section` | Flags win if set |
| `toolchain.*` | `--llvm-link`, `--opt`, etc. | Flag wins if set |

`build.custom_passes` is always applied from config when present; there is no flag-based override for custom passes.

## Validation

- **Timeout**: Must be a valid Go duration string and non-negative.
- **Custom passes**: Each pass is validated against a strict pattern. Prohibited characters: `/ \ $ \` | ; & ( ) { } [ ] ! ~`.
- **Section format**: When using `--section` flags, the format must be `name=section` with both sides non-empty.
