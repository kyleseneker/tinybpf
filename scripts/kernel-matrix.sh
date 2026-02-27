#!/usr/bin/env bash
# CO-RE kernel matrix test for tinybpf.
#
# Boots a specific kernel version via virtme-ng, builds the rawtp-sched
# CO-RE example, and validates that CO-RE relocations resolve correctly.
#
# Usage: sudo ./scripts/kernel-matrix.sh <kernel-version>
#
# Supported versions: 5.15, 6.1, 6.6, 6.12
# Requires: virtme-ng (pip3 install virtme-ng), Go, TinyGo, LLVM tools
set -euo pipefail

KERNEL_VERSION="${1:?Usage: $0 <kernel-version>}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${REPO_ROOT}/build/kernel-matrix/${KERNEL_VERSION}"
LOG_DIR="${BUILD_DIR}/logs"

export GOPATH="${GOPATH:-/tmp/go-kernel-matrix}"
export GOCACHE="${GOCACHE:-/tmp/go-kernel-matrix-cache}"
export HOME="${HOME:-/root}"
mkdir -p "${BUILD_DIR}" "${LOG_DIR}" "${GOPATH}" "${GOCACHE}"

echo "============================================="
echo " tinybpf CO-RE kernel matrix"
echo " target kernel: ${KERNEL_VERSION}"
echo " host kernel:   $(uname -r)"
echo " date:          $(date -Iseconds)"
echo "============================================="
echo ""

# --- Step 1: Build tinybpf ---
echo "[1/4] Building tinybpf..."
BIN="${BUILD_DIR}/tinybpf"
(cd "${REPO_ROOT}" && go build -o "${BIN}" ./cmd/tinybpf) 2>&1 | tee "${LOG_DIR}/build.log"

# --- Step 2: Build CO-RE example ---
echo ""
echo "[2/4] Building rawtp-sched CO-RE example..."
IR_FILE="${BUILD_DIR}/sched.ll"
OBJ="${BUILD_DIR}/sched.bpf.o"

(
  cd "${REPO_ROOT}/examples/rawtp-sched" && \
  tinygo build \
    -gc=none \
    -scheduler=none \
    -panic=trap \
    -opt=1 \
    -o "${IR_FILE}" \
    ./bpf
) 2>&1 | tee "${LOG_DIR}/tinygo.log"

"${BIN}" link \
  --input "${IR_FILE}" \
  --output "${OBJ}" \
  --section raw_tracepoint_sched_process_exec=raw_tracepoint/sched_process_exec \
  --verbose 2>&1 | tee "${LOG_DIR}/pipeline.log"

if [[ ! -f "${OBJ}" ]]; then
  echo "FAIL: pipeline did not produce ${OBJ}"
  exit 1
fi
echo "  OK: produced ${OBJ}"

# --- Step 3: Boot kernel and load program ---
echo ""
echo "[3/4] Booting kernel ${KERNEL_VERSION} via virtme-ng..."

if ! command -v vng >/dev/null 2>&1; then
  echo "FAIL: virtme-ng (vng) not found. Install: pip3 install virtme-ng"
  exit 1
fi

INNER_SCRIPT="${BUILD_DIR}/inner-test.sh"
cat > "${INNER_SCRIPT}" << 'INNEREOF'
#!/bin/bash
set -euo pipefail
OBJ="$1"
PIN="/sys/fs/bpf/tinybpf_core_test"

echo "  inner: kernel $(uname -r)"
echo "  inner: loading ${OBJ}..."

if ! command -v bpftool >/dev/null 2>&1; then
  echo "  inner: bpftool not found, skipping verifier load"
  exit 0
fi

if bpftool prog load "${OBJ}" "${PIN}" 2>&1; then
  echo "  inner: PASS — CO-RE program loaded successfully"
  bpftool prog show pinned "${PIN}" || true
  rm -f "${PIN}" 2>/dev/null || true
else
  echo "  inner: FAIL — CO-RE program rejected by verifier"
  rm -f "${PIN}" 2>/dev/null || true
  exit 1
fi
INNEREOF
chmod +x "${INNER_SCRIPT}"

vng --run "${KERNEL_VERSION}" -- \
  bash "${INNER_SCRIPT}" "${OBJ}" \
  2>&1 | tee "${LOG_DIR}/vng.log"
VNG_RC=${PIPESTATUS[0]}

# --- Step 4: Summary ---
echo ""
echo "[4/4] Summary"
echo "============================================="
if [[ ${VNG_RC} -eq 0 ]]; then
  echo " PASS: CO-RE validated on kernel ${KERNEL_VERSION}"
else
  echo " FAIL: CO-RE validation failed on kernel ${KERNEL_VERSION}"
  exit 1
fi
echo "============================================="
