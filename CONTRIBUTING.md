# Development

Notes for hacking on `tinybpf` itself.

## Setup

```bash
make setup     # installs Go, TinyGo, LLVM, golangci-lint, QEMU
make doctor    # verify the toolchain
```

macOS installs via Homebrew. Linux installs via apt (requires `sudo`).

## Running tests

```bash
make test      # unit tests
make check     # lint + tests
make cover     # tests with coverage
make bench     # transform benchmarks
```

Tests that require LLVM tools skip when the tools are not on `PATH`.

## VM workflow

E2E tests require a Linux kernel. On macOS, use a QEMU VM:

```bash
make vm        # create and boot Ubuntu 24.04 QEMU VM (wait ~60s for cloud-init)
make sync      # sync repo into the VM

# inside the VM:
cd ~/tinybpf
sudo make setup
sudo make e2e  # full TinyGo -> pipeline -> verifier -> attach validation
```

After local changes, re-run `make sync` and `make e2e` inside the VM.

## Makefile targets

| Target | Description |
|--------|-------------|
| `make build` | Build the `tinybpf` binary |
| `make test` | Run unit tests |
| `make bench` | Run transform benchmarks |
| `make cover` | Run tests with coverage report |
| `make lint` | Run `go vet` + `golangci-lint` |
| `make check` | Run lint + tests |
| `make fmt` | Format code with `gofmt` |
| `make doctor` | Build and run toolchain diagnostic |
| `make setup` | Install dev dependencies |
| `make vm` | Create and boot a QEMU VM |
| `make sync` | Sync repo to VM |
| `make e2e` | Run E2E validation (Linux, requires root) |
| `make example NAME=<name>` | Build a specific example |
| `make clean` | Remove build artifacts |

See [docs/project-layout.md](docs/project-layout.md) for the package map and
[docs/architecture.md](docs/architecture.md) for the pipeline design.
