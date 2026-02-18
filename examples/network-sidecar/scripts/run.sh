#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLE_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "network-sidecar requires Linux" >&2
  exit 1
fi

"${SCRIPT_DIR}/build.sh"

if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root (or with sudo) to load and attach BPF programs" >&2
  exit 1
fi

cd "${EXAMPLE_DIR}"
go run ./cmd/sidecar --object ./build/probe.bpf.o
