# Troubleshooting

Common issues and solutions when using `tinybpf`. Run `tinybpf --help` for a quick overview of available commands and flags.

## Setup issues

### LLVM version mismatch

**Symptom:** `tinybpf` fails at the `llvm-link` or `opt` stage with parse errors, or `tinybpf doctor` reports a version warning.

**Cause:** System LLVM tools must match the LLVM version bundled with TinyGo. TinyGo 0.40.x bundles LLVM 20; system tools must be version 20 or later.

**Fix:**

```bash
# Check your LLVM version:
llvm-link --version

# On Ubuntu 24.04 (defaults to LLVM 18), install LLVM 20+:
wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | sudo tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc > /dev/null
echo "deb http://apt.llvm.org/noble/ llvm-toolchain-noble-20 main" | sudo tee /etc/apt/sources.list.d/llvm-20.list
sudo apt-get update && sudo apt-get install -y llvm-20

# Point tinybpf to the correct tools:
tinybpf --llvm-link llvm-link-20 --opt opt-20 --llc llc-20 ...
```

On macOS with Homebrew, `brew install llvm@20` and add the LLVM bin directory to your `PATH`.

### TinyGo not found

**Symptom:** `tinybpf doctor` reports `tinygo: (not found)`.

**Fix:** Install TinyGo from [tinygo.org/getting-started/install](https://tinygo.org/getting-started/install/). Verify with:

```bash
tinygo version
```

### `tinybpf doctor` reports failures

Run `tinybpf doctor` to diagnose your toolchain. Each tool is listed with its resolved path and version. Failures appear as `[FAIL]` with an error message, and warnings appear at the end with remediation guidance.

```bash
tinybpf doctor
```

If a required tool (`llvm-link`, `opt`, `llc`) is missing, install LLVM or pass the tool path explicitly with `--llvm-link`, `--opt`, or `--llc`.

## Pipeline errors

`tinybpf` reports errors as structured diagnostics with a stage name, error code, and remediation hint. The stage tells you where in the pipeline the failure occurred.

### Stage `discover-tools` — TOOL_NOT_FOUND

One or more required LLVM binaries could not be found on `PATH`.

```
stage "discover-tools" failed [TOOL_NOT_FOUND]: llvm-link: ...
--- hint ---
install LLVM tools or pass --llvm-link explicitly
```

**Fix:** Install LLVM or provide explicit paths. See [LLVM version mismatch](#llvm-version-mismatch) above.

### Stage `llvm-link` — TOOL_EXECUTION_FAILED

The input IR modules could not be linked together.

**Common causes:**
- Input file is not valid LLVM IR (wrong file passed to `--input`)
- LLVM version mismatch (IR uses syntax the system LLVM cannot parse)
- Corrupt or truncated `.ll` / `.bc` file

**Fix:** Verify the input was produced by TinyGo (`tinygo build -o program.ll ...`), and check LLVM version compatibility.

### Stage `transform` — TOOL_EXECUTION_FAILED

The IR rewrite step failed. This is the `tinybpf`-specific transformation that converts TinyGo IR to BPF-compatible IR.

**Common causes:**
- Input IR was not produced by TinyGo (or was compiled without `-gc=none -scheduler=none`)
- Input uses an unrecognized BPF helper name
- IR structure does not match expected TinyGo output patterns

**Fix:**
1. Ensure your TinyGo compilation uses the correct flags:
   ```bash
   tinygo build -gc=none -scheduler=none -panic=trap -opt=1 -o program.ll ./bpf
   ```
2. Check that BPF helper declarations use recognized names (see [TINYGO_COMPAT.md](TINYGO_COMPAT.md#supported-bpf-helpers)).
3. Use `--keep-temp` to inspect the linked IR before transformation.

### Stage `opt` — TOOL_EXECUTION_FAILED

The LLVM optimization pass failed.

**Fix:** Try a less aggressive optimization profile:

```bash
tinybpf --opt-profile conservative ...
```

Or inspect the intermediate IR with `--keep-temp` and `--tmpdir ./debug`.

### Stage `llc` — TOOL_EXECUTION_FAILED

BPF code generation failed.

**Common causes:**
- The IR contains constructs the BPF backend cannot lower (floating point, unsupported instructions)
- The transform step did not fully clean up non-BPF constructs

**Fix:** Inspect the optimized IR (`03-optimized.ll` in the temp directory) and check for constructs listed in [unsupported features](TINYGO_COMPAT.md#unsupported-features). File an issue if the IR looks correct but `llc` rejects it.

### Stage `elf-validate` — ELF_VALIDATION_FAILED

The output file is not a valid BPF ELF object.

**Fix:** This usually indicates a problem in an earlier stage. Use `--keep-temp --verbose` and inspect each intermediate file. The output should be `ELF 64-bit LSB relocatable, eBPF`.

## Verifier issues

After `tinybpf` produces a `.o` file, the Linux kernel's BPF verifier must accept it at load time. Verifier rejections are independent of `tinybpf` and depend on kernel version, program type, and the specific instructions in the program.

### Debugging verifier failures

1. **Load with verbose output:**
   ```bash
   bpftool prog load program.o /sys/fs/bpf/test 2>&1
   ```

2. **Inspect with detailed verifier log:**
   ```bash
   bpftool -d prog load program.o /sys/fs/bpf/test
   ```

3. **Inspect intermediates:** Use `--keep-temp --tmpdir ./debug` to preserve all pipeline artifacts and examine the IR at each stage.

### Common verifier rejections

| Rejection | Likely cause | Fix |
|-----------|-------------|-----|
| `unreachable insn` | Dead code after a return | Simplify control flow; avoid unreachable paths |
| `invalid mem access` | Dereferencing a pointer without null check | Add bounds/null checks before pointer use |
| `back-edge from insn` | Unbounded loop | Use bounded `for` loops with a fixed iteration count |
| `R0 !read_ok` | Missing return value | Ensure all paths return `int32` |
| `helper call not allowed` | Helper requires GPL license | Ensure `tinybpf` injects the GPL license section (default behavior) |

### BPF CPU version

If the verifier rejects instructions, try a different BPF CPU version:

```bash
tinybpf --cpu v2 ...   # more conservative instruction set
tinybpf --cpu v3 ...   # default; ALU32, JMP32
tinybpf --cpu v4 ...   # latest features (requires newer kernel)
```

## Platform-specific

### macOS

The `tinybpf` pipeline (through `llc`) works on macOS for development and testing. However, loading BPF programs into the kernel requires Linux. Use the QEMU VM workflow for end-to-end validation:

```bash
make vm          # create and boot Ubuntu VM
make sync        # sync repo into VM
# inside VM:
make e2e         # full validation
```

### Ubuntu 24.04

Ubuntu 24.04 ships LLVM 18 by default. TinyGo 0.40.x requires LLVM 20+. See [LLVM version mismatch](#llvm-version-mismatch) for installation instructions.
