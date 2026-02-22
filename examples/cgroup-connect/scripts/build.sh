#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLE_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd -- "${EXAMPLE_DIR}/../.." && pwd)"
BUILD_DIR="${EXAMPLE_DIR}/build"

TINYBPF_BIN="${TINYBPF_BIN:-}"
CPU="${BPF_CPU:-v3}"

mkdir -p "${BUILD_DIR}"

if [[ -z "${TINYBPF_BIN}" ]]; then
  TINYBPF_BIN="${BUILD_DIR}/tinybpf"
  echo "[1/2] build tinybpf -> ${TINYBPF_BIN}"
  (cd "${REPO_ROOT}" && go build -o "${TINYBPF_BIN}" ./cmd/tinybpf)
else
  echo "[1/2] using tinybpf -> ${TINYBPF_BIN}"
fi

echo "[2/2] tinybpf build -> ${BUILD_DIR}/connect.bpf.o"
(
  cd "${EXAMPLE_DIR}" && \
  "${TINYBPF_BIN}" build \
    --output "${BUILD_DIR}/connect.bpf.o" \
    --section check_connect4=cgroup/connect4 \
    --cpu "${CPU}" \
    --verbose \
    ./bpf
)

echo "built object: ${BUILD_DIR}/connect.bpf.o"
