#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLE_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "xdp-filter requires Linux" >&2
  exit 1
fi

"${SCRIPT_DIR}/build.sh"

if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root (or with sudo) to load and attach BPF programs" >&2
  exit 1
fi

IFACE="${IFACE:-lo}"
BLOCK_IP="${BLOCK_IP:-}"

ARGS=(--object ./build/filter.bpf.o --iface "${IFACE}")
if [[ -n "${BLOCK_IP}" ]]; then
  ARGS+=(--block "${BLOCK_IP}")
fi

cd "${EXAMPLE_DIR}"
go run ./cmd/loader "${ARGS[@]}"
