# Contributing

Thank you for your interest in contributing to `tinybpf`. This document covers how to set up a development environment, run tests, and submit changes.

## Development setup

```bash
make setup
```

This detects your OS and installs everything:

- **macOS**: Go, TinyGo, LLVM, golangci-lint, QEMU (via Homebrew)
- **Linux**: Go 1.24, TinyGo 0.40, LLVM 20, build tools (via apt; requires `sudo`)

Verify the toolchain:

```bash
make doctor
```

### Manual setup

Install the [prerequisites](docs/getting-started.md#prerequisites) yourself and ensure `golangci-lint` is available for `make lint`.

## Running tests

```bash
make test       # unit tests (go test ./...)
make check      # lint + tests
make cover      # tests with coverage report
make bench      # transform benchmarks
```

Tests that require LLVM tools skip automatically when the tools are not on `PATH`.

CI enforces a 90% coverage threshold on the primary test lane.

## End-to-end testing

E2E tests require a Linux environment with kernel BPF support. On macOS, use a QEMU VM.

### VM workflow

```bash
make vm         # create and boot an Ubuntu 24.04 QEMU VM
                # wait ~60s for cloud-init, then:
ssh -p 2222 ubuntu@localhost

make sync       # sync repo into the VM

# inside the VM:
cd ~/tinybpf
sudo make setup  # install toolchain
sudo make e2e    # run full validation
```

The E2E validation runs the complete lifecycle using the `tracepoint-connect` example: TinyGo compile, `tinybpf` pipeline, ELF validation, kernel verifier load, tracepoint attach, and event capture. Use `--skip-attach` to stop after verifier load.

### Re-syncing after changes

```bash
make sync       # from your Mac
# inside the VM:
cd ~/tinybpf
make e2e
```

## Makefile targets

| Target | Description |
|--------|-------------|
| `make build` | Build the `tinybpf` binary |
| `make test` | Run unit tests |
| `make bench` | Run transform benchmarks |
| `make cover` | Run tests with coverage report |
| `make vet` | Run `go vet ./...` |
| `make lint` | Run `go vet` + `golangci-lint` |
| `make check` | Run lint + tests |
| `make fmt` | Format code with `gofmt` |
| `make doctor` | Build and run toolchain diagnostic |
| `make setup` | Install dev dependencies (detects OS) |
| `make vm` | Create and boot a QEMU VM |
| `make sync` | Sync repo to VM |
| `make e2e` | Run E2E validation (Linux, requires root) |
| `make clean` | Remove build artifacts |

## Project structure

See [Project Layout](docs/project-layout.md) for the full package map and [Architecture](docs/architecture.md) for how the pipeline and IR transforms work.

## Submitting changes

### Guidelines

- **Keep PRs focused.** One logical change per pull request.
- **Include tests** for any functional change.
- **Update documentation** when flags or user-visible behavior change.
- **Run checks before pushing:**

```bash
make check
```

### Commit messages

Use imperative mood. Keep the subject line under 72 characters.

```
Add --foo flag for bar support

Longer explanation of the change and its motivation, if needed.
```

### Pull request process

1. Fork the repository and create a feature branch.
2. Make your changes, ensuring `make check` passes locally.
3. Open a pull request with a clear description of what changed, why, and how to test it.
4. CI must pass before merge.
5. Maintainers may request changes or suggest alternatives.

## Reporting bugs

Open an issue using the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md) and include:

- The exact command and its full output
- Go version (`go version`)
- LLVM version (`llvm-link --version`)
- `tinybpf` version (`tinybpf version`)
- A minimal reproducer (`.ll` or `.bc` file) if possible

## Requesting features

Open an issue using the [feature request template](.github/ISSUE_TEMPLATE/feature_request.md) describing the problem, your proposed solution, and any alternatives you considered.
