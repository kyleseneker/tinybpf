#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLE_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
LOG_FILE="${EXAMPLE_DIR}/build/sidecar.log"

if [[ "${EUID}" -ne 0 ]]; then
  echo "smoke test needs root privileges" >&2
  exit 1
fi

"${SCRIPT_DIR}/build.sh"

echo "starting sidecar..."
(
  cd "${EXAMPLE_DIR}" && \
  go run ./cmd/sidecar --object ./build/probe.bpf.o
) >"${LOG_FILE}" 2>&1 &
SIDECAR_PID=$!

cleanup() {
  kill "${SIDECAR_PID}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

sleep 2
curl -m 2 -sS https://example.com >/dev/null || true
sleep 2

if rg -q "dst=" "${LOG_FILE}"; then
  echo "smoke passed"
  exit 0
fi

echo "smoke failed, no connection events observed" >&2
echo "--- sidecar log ---" >&2
sed -n '1,120p' "${LOG_FILE}" >&2
exit 1
