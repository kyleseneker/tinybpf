#!/usr/bin/env bash
# End-to-end Linux validation for tinybpf.
#
# Runs the full lifecycle: TinyGo compile -> tinybpf -> ELF validate ->
# bpftool prog load (verifier) -> tracepoint attach -> traffic -> event capture.
#
# Usage: sudo ./scripts/e2e.sh [--skip-attach]
#
# --skip-attach  Stop after verifier load (skip tracepoint attach and event capture).
#                Useful in CI where network traffic generation may be unreliable.
set -euo pipefail

SKIP_ATTACH=false
for arg in "$@"; do
  case "$arg" in
    --skip-attach) SKIP_ATTACH=true ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "error: this script requires Linux" >&2
  exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "error: run as root (sudo ./scripts/e2e.sh)" >&2
  exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${REPO_ROOT}/build/validate"

# Ensure Go and TinyGo build caches are writable when running as root.
export GOPATH="${GOPATH:-/tmp/go-validate}"
export GOCACHE="${GOCACHE:-/tmp/go-validate-cache}"
export HOME="${HOME:-/root}"
mkdir -p "${GOPATH}" "${GOCACHE}"
LOG_DIR="${BUILD_DIR}/logs"
PIN_PATH="/sys/fs/bpf/tinybpf_validate"
PASSED=0
FAILED=0
SKIPPED=0
LOAD_RC=0

mkdir -p "${BUILD_DIR}" "${LOG_DIR}"

pass() { echo "  PASS: $1"; PASSED=$((PASSED + 1)); }
fail() { echo "  FAIL: $1"; FAILED=$((FAILED + 1)); }
skip() { echo "  SKIP: $1"; SKIPPED=$((SKIPPED + 1)); }

cleanup() {
  rm -f "${PIN_PATH}" 2>/dev/null || true
}
trap cleanup EXIT

echo "============================================="
echo " tinybpf Linux validation"
echo " kernel: $(uname -r)"
echo " date:   $(date -Iseconds)"
echo "============================================="
echo ""

# --- Step 1: Build tinybpf ---
echo "[1/7] Building tinybpf..."
BIN="${BUILD_DIR}/tinybpf"
(cd "${REPO_ROOT}" && go build -o "${BIN}" ./cmd/tinybpf) 2>&1 | tee "${LOG_DIR}/build.log"
if [[ -x "${BIN}" ]]; then
  pass "tinybpf built"
else
  fail "tinybpf build failed"
  exit 1
fi

# --- Step 2: TinyGo compile ---
echo ""
echo "[2/7] Compiling tracepoint-connect with TinyGo..."
IR_FILE="${BUILD_DIR}/connect.ll"
(
  cd "${REPO_ROOT}/examples/tracepoint-connect" && \
  tinygo build \
    -gc=none \
    -scheduler=none \
    -panic=trap \
    -opt=1 \
    -o "${IR_FILE}" \
    ./bpf
) 2>&1 | tee "${LOG_DIR}/tinygo.log"
if [[ -f "${IR_FILE}" ]]; then
  pass "TinyGo produced IR ($(wc -l < "${IR_FILE}") lines)"
else
  fail "TinyGo did not produce IR"
  exit 1
fi

# --- Step 3: tinybpf full pipeline ---
echo ""
echo "[3/7] Running tinybpf pipeline..."
OBJ="${BUILD_DIR}/connect.bpf.o"
"${BIN}" link \
  --input "${IR_FILE}" \
  --output "${OBJ}" \
  --section handle_connect=tracepoint/syscalls/sys_enter_connect \
  --keep-temp \
  --tmpdir "${BUILD_DIR}/intermediates" \
  --verbose 2>&1 | tee "${LOG_DIR}/pipeline.log"
if [[ -f "${OBJ}" ]]; then
  pass "pipeline produced ${OBJ}"
else
  fail "pipeline did not produce output"
  exit 1
fi

# --- Step 4: ELF structure validation ---
echo ""
echo "[4/7] Validating ELF structure..."

FILE_OUT=$(file "${OBJ}")
echo "  file: ${FILE_OUT}"
if echo "${FILE_OUT}" | grep -q "ELF 64-bit LSB relocatable.*eBPF"; then
  pass "ELF type is eBPF relocatable"
else
  fail "unexpected ELF type"
fi

readelf -h "${OBJ}" > "${LOG_DIR}/readelf-header.log" 2>&1
MACHINE=$(grep "Machine:" "${LOG_DIR}/readelf-header.log" | head -1)
echo "  ${MACHINE}"
if echo "${MACHINE}" | grep -qi "bpf\|247"; then
  pass "ELF machine is EM_BPF"
else
  fail "wrong ELF machine type"
fi

readelf -SW "${OBJ}" > "${LOG_DIR}/readelf-sections.log" 2>&1
echo "  sections:"
grep -E 'tracepoint|\.maps|\.text' "${LOG_DIR}/readelf-sections.log" | while read -r line; do
  echo "    ${line}"
done

if grep -q "tracepoint/syscalls/sys_enter_connect" "${LOG_DIR}/readelf-sections.log"; then
  pass "tracepoint/syscalls/sys_enter_connect section present"
else
  fail "tracepoint/syscalls/sys_enter_connect section missing"
fi

if grep -q "\.maps" "${LOG_DIR}/readelf-sections.log"; then
  pass ".maps section present"
else
  fail ".maps section missing"
fi

# --- Step 5: bpftool prog load (verifier) ---
echo ""
echo "[5/7] Loading BPF program (verifier check)..."

if ! command -v bpftool >/dev/null 2>&1; then
  skip "bpftool not found"
else
  # Capture verifier log regardless of success/failure.
  VERIFIER_LOG="${LOG_DIR}/verifier.log"
  set +e
  bpftool prog load "${OBJ}" "${PIN_PATH}" 2>&1 | tee "${VERIFIER_LOG}"
  LOAD_RC=$?
  set -e

  if [[ $LOAD_RC -eq 0 ]]; then
    pass "bpftool prog load succeeded (verifier accepted)"
    bpftool prog show pinned "${PIN_PATH}" > "${LOG_DIR}/prog-show.log" 2>&1 || true
    echo "  $(head -1 "${LOG_DIR}/prog-show.log")"
  else
    fail "bpftool prog load failed (verifier rejected)"
    echo ""
    echo "--- verifier log ---"
    cat "${VERIFIER_LOG}"
    echo "--- end verifier log ---"
    echo ""
    echo "Try: bpftool prog load ${OBJ} ${PIN_PATH} 2>&1"
    echo "Intermediates preserved in: ${BUILD_DIR}/intermediates/"
  fi

  # Try verbose verifier log for diagnostics.
  VERIFIER_VERBOSE="${LOG_DIR}/verifier-verbose.log"
  bpftool -d prog load "${OBJ}" "${PIN_PATH}_verbose" > "${VERIFIER_VERBOSE}" 2>&1 || true
  rm -f "${PIN_PATH}_verbose" 2>/dev/null || true
fi

# --- Step 6: Attach tracepoint and capture events ---
echo ""
if [[ "${SKIP_ATTACH}" == "true" ]]; then
  echo "[6/7] Skipping tracepoint attach (--skip-attach)"
  skip "tracepoint attach (--skip-attach)"
  skip "event capture (--skip-attach)"
elif [[ $LOAD_RC -ne 0 ]] 2>/dev/null; then
  echo "[6/7] Skipping tracepoint attach (load failed)"
  skip "tracepoint attach (load failed)"
  skip "event capture (load failed)"
else
  echo "[6/7] Running tracer with tracepoint attach..."
  TRACER_LOG="${LOG_DIR}/tracer.log"

  (
    cd "${REPO_ROOT}/examples/tracepoint-connect" && \
    timeout 15 go run ./cmd/tracer --object "${OBJ}"
  ) > "${TRACER_LOG}" 2>&1 &
  TRACER_PID=$!

  sleep 3

  # Generate outbound IPv4 TCP traffic.
  curl -4 -m 5 -sS http://example.com > /dev/null 2>&1 || true
  curl -4 -m 5 -sS http://one.one.one.one > /dev/null 2>&1 || true

  sleep 3
  kill "${TRACER_PID}" 2>/dev/null || true
  wait "${TRACER_PID}" 2>/dev/null || true

  echo "  tracer log:"
  head -20 "${TRACER_LOG}" | while read -r line; do echo "    ${line}"; done

  if grep -q "dst=" "${TRACER_LOG}"; then
    pass "connection events captured from ring buffer"
    EVENT_COUNT=$(grep -c "dst=" "${TRACER_LOG}" || echo 0)
    echo "  events: ${EVENT_COUNT}"
  else
    fail "no connection events observed"
    echo "  full log:"
    cat "${TRACER_LOG}" | while read -r line; do echo "    ${line}"; done
  fi
fi

# --- Step 7: Summary ---
echo ""
echo "[7/7] Cleanup and summary..."
cleanup

echo ""
echo "============================================="
echo " Results: ${PASSED} passed, ${FAILED} failed, ${SKIPPED} skipped"
echo " Logs:    ${LOG_DIR}/"
echo " Kernel:  $(uname -r)"
echo "============================================="

if [[ ${FAILED} -gt 0 ]]; then
  echo ""
  echo "VALIDATION FAILED"
  exit 1
fi

echo ""
echo "VALIDATION PASSED"
