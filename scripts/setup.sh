#!/usr/bin/env bash
# Install tinybpf development dependencies.
#
# Detects the OS and runs the appropriate setup:
#   macOS  — Homebrew (Go, TinyGo, LLVM, golangci-lint, QEMU)
#   Linux  — apt (Go, TinyGo, LLVM, bpftool); requires sudo
#
# Usage: ./scripts/setup.sh          (macOS)
#        sudo ./scripts/setup.sh     (Linux)
#
# Idempotent — safe to re-run.
set -euo pipefail

OS="$(uname -s)"

# ---------------------------------------------------------------------------
# macOS
# ---------------------------------------------------------------------------
setup_macos() {
  if ! command -v brew >/dev/null 2>&1; then
    echo "error: Homebrew is required. Install from https://brew.sh" >&2
    exit 1
  fi

  echo "=== tinybpf setup (macOS) ==="
  echo ""

  echo "[1/5] Go..."
  brew list go &>/dev/null || brew install go
  echo "  $(go version)"

  echo "[2/5] TinyGo..."
  brew list tinygo &>/dev/null || brew install tinygo
  echo "  $(tinygo version)"

  echo "[3/5] LLVM..."
  brew list llvm &>/dev/null || brew install llvm
  LLVM_PREFIX="$(brew --prefix llvm)"
  export PATH="${LLVM_PREFIX}/bin:${PATH}"
  echo "  $(llvm-link --version 2>&1 | head -1)"

  # Ensure LLVM is on PATH in the user's shell.
  SHELL_RC=""
  case "${SHELL}" in
    */zsh)  SHELL_RC="${HOME}/.zshrc" ;;
    */bash) SHELL_RC="${HOME}/.bashrc" ;;
  esac
  if [[ -n "${SHELL_RC}" ]] && ! grep -q "llvm/bin" "${SHELL_RC}" 2>/dev/null; then
    echo "" >> "${SHELL_RC}"
    echo "# LLVM (required by tinybpf)" >> "${SHELL_RC}"
    echo "export PATH=\"${LLVM_PREFIX}/bin:\$PATH\"" >> "${SHELL_RC}"
    echo "  added LLVM to ${SHELL_RC}"
  fi

  echo "[4/5] Dev tools (golangci-lint)..."
  brew list golangci-lint &>/dev/null || brew install golangci-lint
  echo "  golangci-lint: $(golangci-lint --version 2>&1 | head -1)"

  echo "[5/5] QEMU (for Linux VM testing)..."
  brew list qemu &>/dev/null || brew install qemu
  echo "  $(qemu-system-aarch64 --version 2>&1 | head -1)"

  echo ""
  echo "=== setup complete ==="
  echo ""
  echo "Verify:      make doctor"
  echo "Run tests:   make test"
  echo "Run lint:    make lint"
  echo ""
  echo "For E2E testing on a Linux VM:"
  echo "  make vm       # create and boot a QEMU VM"
  echo "  make sync     # sync repo into the VM"
  echo "  make e2e      # run full validation (inside VM)"
}

# ---------------------------------------------------------------------------
# Linux
# ---------------------------------------------------------------------------
setup_linux() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "error: Linux setup requires root. Run: sudo ./scripts/setup.sh" >&2
    exit 1
  fi

  ARCH="$(dpkg --print-architecture 2>/dev/null || uname -m)"
  case "$ARCH" in
    amd64|x86_64)  ARCH_LABEL="amd64" ;;
    arm64|aarch64) ARCH_LABEL="arm64" ;;
    *) echo "error: unsupported architecture: $ARCH" >&2; exit 1 ;;
  esac

  GO_VERSION="1.24.5"
  TINYGO_VERSION="0.40.1"
  # Must be >= TinyGo's bundled LLVM major version. TinyGo 0.40.x ships LLVM 20.
  LLVM_VERSION="20"

  echo "=== tinybpf setup (Linux) ==="
  echo "arch:   $ARCH_LABEL"
  echo "go:     $GO_VERSION"
  echo "tinygo: $TINYGO_VERSION"
  echo "llvm:   $LLVM_VERSION"
  echo ""

  # --- System packages ---
  echo "[1/5] System packages..."
  apt-get update -qq
  apt-get install -y -qq \
    build-essential \
    curl \
    git \
    wget \
    linux-tools-common \
    "linux-tools-$(uname -r)" \
    linux-headers-"$(uname -r)" \
    ca-certificates

  # LLVM 20 is not in Ubuntu 24.04's default repos; add apt.llvm.org.
  if [[ ! -f /etc/apt/sources.list.d/llvm-${LLVM_VERSION}.list ]]; then
    echo "  adding apt.llvm.org for LLVM ${LLVM_VERSION}..."
    wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key \
      | tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc > /dev/null
    echo "deb http://apt.llvm.org/noble/ llvm-toolchain-noble-${LLVM_VERSION} main" \
      > "/etc/apt/sources.list.d/llvm-${LLVM_VERSION}.list"
    apt-get update -qq
  fi
  apt-get install -y -qq "llvm-${LLVM_VERSION}" "lld-${LLVM_VERSION}"

  # Put LLVM on PATH for this script and future shells.
  LLVM_BIN="/usr/lib/llvm-${LLVM_VERSION}/bin"
  if ! grep -q "$LLVM_BIN" /etc/environment 2>/dev/null; then
    echo "PATH=\"${LLVM_BIN}:\$PATH\"" >> /etc/environment
  fi
  export PATH="${LLVM_BIN}:${PATH}"

  # --- Go ---
  echo "[2/5] Go ${GO_VERSION}..."
  if command -v go >/dev/null 2>&1 && go version | grep -q "go${GO_VERSION}"; then
    echo "  already installed"
  else
    GO_TAR="go${GO_VERSION}.linux-${ARCH_LABEL}.tar.gz"
    curl -fsSL "https://go.dev/dl/${GO_TAR}" -o "/tmp/${GO_TAR}"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "/tmp/${GO_TAR}"
    rm -f "/tmp/${GO_TAR}"
  fi
  export PATH="/usr/local/go/bin:${PATH}"

  if [[ ! -f /etc/profile.d/go.sh ]]; then
    echo 'export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"' > /etc/profile.d/go.sh
  fi

  # --- TinyGo ---
  echo "[3/5] TinyGo ${TINYGO_VERSION}..."
  if command -v tinygo >/dev/null 2>&1 && tinygo version | grep -q "${TINYGO_VERSION}"; then
    echo "  already installed"
  else
    TINYGO_DEB="tinygo_${TINYGO_VERSION}_${ARCH_LABEL}.deb"
    curl -fsSL "https://github.com/tinygo-org/tinygo/releases/download/v${TINYGO_VERSION}/${TINYGO_DEB}" \
      -o "/tmp/${TINYGO_DEB}"
    dpkg -i "/tmp/${TINYGO_DEB}" || apt-get install -f -y -qq
    rm -f "/tmp/${TINYGO_DEB}"
  fi

  # --- Verify ---
  echo "[4/5] Verifying toolchain..."
  echo "  go:        $(go version)"
  echo "  tinygo:    $(tinygo version)"
  echo "  llvm-link: $(llvm-link --version 2>&1 | head -1)"
  echo "  opt:       $(opt --version 2>&1 | head -1)"
  echo "  llc:       $(llc --version 2>&1 | head -1)"
  echo "  bpftool:   $(bpftool version 2>&1 | head -1)"

  # --- Kernel BPF support ---
  echo "[5/5] Kernel BPF support..."
  echo "  kernel: $(uname -r)"
  if [[ -d /sys/fs/bpf ]]; then
    echo "  /sys/fs/bpf: mounted"
  else
    mount -t bpf bpf /sys/fs/bpf 2>/dev/null || echo "  warning: could not mount /sys/fs/bpf"
  fi
  if [[ -f /sys/kernel/btf/vmlinux ]]; then
    echo "  BTF: available"
  else
    echo "  BTF: not available (CO-RE may not work)"
  fi

  echo ""
  echo "=== setup complete ==="
  echo ""
  echo "Verify:    make doctor"
  echo "Run tests: make test"
  echo "Run E2E:   make e2e"
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
case "$OS" in
  Darwin) setup_macos ;;
  Linux)  setup_linux ;;
  *)
    echo "error: unsupported OS: $OS (supported: macOS, Linux)" >&2
    exit 1
    ;;
esac
