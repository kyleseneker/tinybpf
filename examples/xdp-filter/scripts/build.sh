#!/usr/bin/env bash
set -euo pipefail

# TinyGo -> LLVM IR -> tinybpf -> BPF ELF

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLE_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd -- "${EXAMPLE_DIR}/../.." && pwd)"
BUILD_DIR="${EXAMPLE_DIR}/build"

TINYGO_BIN="${TINYGO_BIN:-tinygo}"
TINYBPF_BIN="${TINYBPF_BIN:-}"
TINYGO_OUTPUT_FORMAT="${TINYGO_OUTPUT_FORMAT:-ll}"
CPU="${BPF_CPU:-v3}"

mkdir -p "${BUILD_DIR}"

if ! command -v "${TINYGO_BIN}" >/dev/null 2>&1; then
  echo "error: tinygo not found: ${TINYGO_BIN}" >&2
  echo "install: brew tap tinygo-org/tools && brew install tinygo" >&2
  exit 1
fi

if [[ "${TINYGO_OUTPUT_FORMAT}" == "ll" ]]; then
  IR_FILE="${BUILD_DIR}/filter.ll"
else
  IR_FILE="${BUILD_DIR}/filter.bc"
fi

echo "[1/3] tinygo -> ${IR_FILE}"
(
  cd "${EXAMPLE_DIR}" && \
  "${TINYGO_BIN}" build \
    -gc=none \
    -scheduler=none \
    -panic=trap \
    -opt=1 \
    -o "${IR_FILE}" \
    ./bpf
)

if [[ ! -f "${IR_FILE}" ]]; then
  echo "error: tinygo did not produce ${IR_FILE}" >&2
  exit 1
fi

if [[ -z "${TINYBPF_BIN}" ]]; then
  TINYBPF_BIN="${BUILD_DIR}/tinybpf"
  echo "[2/3] build tinybpf -> ${TINYBPF_BIN}"
  (cd "${REPO_ROOT}" && go build -o "${TINYBPF_BIN}" ./cmd/tinybpf)
else
  echo "[2/3] using tinybpf -> ${TINYBPF_BIN}"
fi

echo "[3/3] tinybpf -> ${BUILD_DIR}/filter.bpf.o"
"${TINYBPF_BIN}" \
  --input "${IR_FILE}" \
  --output "${BUILD_DIR}/filter.bpf.o" \
  --section xdp_filter=xdp \
  --cpu "${CPU}" \
  --verbose

echo "built object: ${BUILD_DIR}/filter.bpf.o"
