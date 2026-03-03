#!/usr/bin/env bash
# Guest-side BPF program load test, executed inside a virtme-ng VM.
#
# Usage: inner-test.sh <bpf-object> [bpftool-path]
set -euo pipefail

OBJ="${1:?Usage: $0 <bpf-object> [bpftool-path]}"
BPFTOOL="${2:-bpftool}"

cleanup() { rm -f "${PIN}" 2>/dev/null || true; }

PIN="/sys/fs/bpf/tinybpf_core_test"
trap cleanup EXIT

echo "  guest: kernel $(uname -r)"
echo "  guest: loading ${OBJ}..."

if [[ ! -x "${BPFTOOL}" ]] && ! command -v "${BPFTOOL}" >/dev/null 2>&1; then
  echo "  guest: FAIL — bpftool not available (tried: ${BPFTOOL})"
  exit 1
fi

if "${BPFTOOL}" prog load "${OBJ}" "${PIN}" 2>&1; then
  echo "  guest: PASS — CO-RE program loaded successfully"
  "${BPFTOOL}" prog show pinned "${PIN}" || true
else
  echo "  guest: FAIL — CO-RE program rejected by verifier"
  exit 1
fi
