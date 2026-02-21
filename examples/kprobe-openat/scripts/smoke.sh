#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLE_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
LOG_FILE="${EXAMPLE_DIR}/build/tracer.log"

if [[ "${EUID}" -ne 0 ]]; then
  echo "smoke test needs root privileges" >&2
  exit 1
fi

"${SCRIPT_DIR}/build.sh"

echo "starting tracer..."
(
  cd "${EXAMPLE_DIR}" && \
  go run ./cmd/tracer --object ./build/openat.bpf.o
) >"${LOG_FILE}" 2>&1 &
TRACER_PID=$!

cleanup() {
  kill "${TRACER_PID}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

sleep 2
cat /dev/null >/dev/null || true
sleep 2

if rg -q "file=" "${LOG_FILE}"; then
  echo "smoke passed"
  exit 0
fi

echo "smoke failed, no open events observed" >&2
echo "--- tracer log ---" >&2
sed -n '1,120p' "${LOG_FILE}" >&2
exit 1
