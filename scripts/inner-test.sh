#!/usr/bin/env bash
# Guest-side BPF program load test, executed inside a virtme-ng VM.
set -euo pipefail

OBJ="${1:?Usage: $0 <bpf-object>}"
PIN="/sys/fs/bpf/tinybpf_core_test"

cleanup() { rm -f "${PIN}" 2>/dev/null || true; }
trap cleanup EXIT

echo "  guest: kernel $(uname -r)"
echo "  guest: loading ${OBJ}..."

if ! command -v bpftool >/dev/null 2>&1 || ! bpftool version >/dev/null 2>&1; then
  echo "  guest: WARNING — bpftool not available, skipping verifier load"
  exit 0
fi

if bpftool prog load "${OBJ}" "${PIN}" 2>&1; then
  echo "  guest: PASS — CO-RE program loaded successfully"
  bpftool prog show pinned "${PIN}" || true
else
  echo "  guest: FAIL — CO-RE program rejected by verifier"
  exit 1
fi
