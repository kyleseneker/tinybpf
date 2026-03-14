#!/usr/bin/env bash
# CO-RE kernel matrix test for tinybpf.
#
# Boots a target kernel via virtme-ng, builds the rawtp-sched CO-RE
# example, and validates that the BPF verifier accepts the relocated
# program.
#
# Usage: sudo ./scripts/kernel-matrix.sh <kernel-version>
#
# Environment:
#   TINYBPF_BIN  Path to a pre-built tinybpf binary (skips rebuild).
#
# Supported versions: 5.15, 6.1, 6.6, 6.12, 6.18
# Requires: virtme-ng, qemu-system-x86_64, Go, TinyGo, LLVM tools
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

die() { echo "FAIL: $1" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Preflight: verify required tools are available.
# ---------------------------------------------------------------------------
preflight() {
  local missing=()
  command -v vng              >/dev/null 2>&1 || missing+=(virtme-ng)
  command -v qemu-system-x86_64 >/dev/null 2>&1 || missing+=(qemu-system-x86_64)
  command -v tinygo           >/dev/null 2>&1 || missing+=(tinygo)
  if (( ${#missing[@]} )); then
    die "missing required tools: ${missing[*]}"
  fi
}

# ---------------------------------------------------------------------------
# Normalize a kernel version string for vng (e.g. "6.12" -> "v6.12").
# Sets: RESOLVED_KERNEL
# ---------------------------------------------------------------------------
resolve_kernel() {
  if [[ "${KERNEL_VERSION}" =~ ^v ]]; then
    RESOLVED_KERNEL="${KERNEL_VERSION}"
  else
    RESOLVED_KERNEL="v${KERNEL_VERSION}"
  fi
}

# ===========================================================================
echo "============================================="
echo " tinybpf CO-RE kernel matrix"
echo " target kernel: ${KERNEL_VERSION}"
echo " host kernel:   $(uname -r)"
echo " date:          $(date -Iseconds)"
echo "============================================="
echo ""

preflight

# --- 1. Build tinybpf -------------------------------------------------------
echo "[1/4] Building tinybpf..."
BIN="${TINYBPF_BIN:-}"
if [[ -n "${BIN}" ]]; then
  echo "  using pre-built binary: ${BIN}"
else
  BIN="${BUILD_DIR}/tinybpf"
  (cd "${REPO_ROOT}" && go build -o "${BIN}" ./cmd/tinybpf) 2>&1 | tee "${LOG_DIR}/build.log"
fi

# --- 2. Build CO-RE example -------------------------------------------------
echo ""
echo "[2/4] Building rawtp-sched CO-RE example..."
IR_FILE="${BUILD_DIR}/sched.ll"
OBJ="${BUILD_DIR}/sched.bpf.o"

(
  cd "${REPO_ROOT}/examples/rawtp-sched" &&
  tinygo build -gc=none -scheduler=none -panic=trap -opt=1 -o "${IR_FILE}" ./bpf
) 2>&1 | tee "${LOG_DIR}/tinygo.log"

"${BIN}" link \
  --input "${IR_FILE}" \
  --output "${OBJ}" \
  --section raw_tracepoint_sched_process_exec=raw_tracepoint/sched_process_exec \
  --verbose 2>&1 | tee "${LOG_DIR}/pipeline.log"

[[ -f "${OBJ}" ]] || die "pipeline did not produce ${OBJ}"
echo "  OK: produced ${OBJ}"

# --- 3. Boot kernel and load program ----------------------------------------
echo ""
echo "[3/4] Booting kernel ${KERNEL_VERSION} via virtme-ng..."

resolve_kernel
echo "  kernel tag: ${RESOLVED_KERNEL}"

# Prefer a standalone bpftool (e.g. built from source at /usr/local/sbin)
# over Ubuntu's /usr/sbin/bpftool wrapper, which dispatches via uname -r
# and breaks inside guests running a different kernel.
BPFTOOL=""
for p in /usr/local/sbin/bpftool /usr/local/bin/bpftool; do
  [[ -x "${p}" ]] && BPFTOOL="${p}" && break
done
if [[ -z "${BPFTOOL}" ]]; then
  BPFTOOL="$(command -v bpftool 2>/dev/null || true)"
fi
if [[ -n "${BPFTOOL}" ]]; then
  echo "  bpftool: ${BPFTOOL}"
else
  echo "  WARNING: bpftool not found on host"
fi

vng --run "${RESOLVED_KERNEL}" -- \
  bash "${SCRIPT_DIR}/inner-test.sh" "${OBJ}" "${BPFTOOL}" \
  2>&1 | tee "${LOG_DIR}/vng.log"
VNG_RC=${PIPESTATUS[0]}

# --- 4. Summary -------------------------------------------------------------
echo ""
echo "[4/4] Summary"
echo "============================================="
if [[ ${VNG_RC} -eq 0 ]]; then
  echo " PASS: CO-RE validated on kernel ${RESOLVED_KERNEL}"
else
  echo " FAIL: CO-RE validation failed on kernel ${RESOLVED_KERNEL}"
  exit 1
fi
echo "============================================="
