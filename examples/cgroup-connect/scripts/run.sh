#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLE_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "cgroup-connect requires Linux" >&2
  exit 1
fi

"${SCRIPT_DIR}/build.sh"

if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root (or with sudo) to load and attach BPF programs" >&2
  exit 1
fi

BLOCK_IP="${BLOCK_IP:-93.184.216.34}"

cd "${EXAMPLE_DIR}"
go run ./cmd/blocker --object ./build/connect.bpf.o --block-ip "${BLOCK_IP}"
