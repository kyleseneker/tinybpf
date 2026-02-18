#!/usr/bin/env bash
# Create and boot an Ubuntu 24.04 QEMU VM for tinybpf E2E testing.
#
# Usage: ./scripts/create-vm.sh [--start-only]
#
# Creates a VM in /tmp/bpf-vm/ with SSH on localhost:2222.
# Use --start-only to boot an existing VM without re-downloading.
#
# After the VM boots:
#   ssh -p 2222 ubuntu@localhost
#   sudo ./tinybpf/scripts/setup.sh
#   sudo ./tinybpf/scripts/e2e.sh
set -euo pipefail

VM_DIR="/tmp/bpf-vm"
SSH_PORT="2222"
DISK_SIZE="20G"
RAM="4096"
CPUS="4"
START_ONLY=false

for arg in "$@"; do
  case "$arg" in
    --start-only) START_ONLY=true ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: this script is for macOS (Apple Silicon or Intel)" >&2
  exit 1
fi

if ! command -v qemu-system-aarch64 >/dev/null 2>&1; then
  echo "error: qemu not installed. Run: brew install qemu" >&2
  exit 1
fi

ARCH="$(uname -m)"
case "$ARCH" in
  arm64)
    QEMU_BIN="qemu-system-aarch64"
    MACHINE="-M virt,highmem=on -accel hvf -cpu host"
    IMG_ARCH="arm64"
    EFI_CODE="$(brew --prefix qemu)/share/qemu/edk2-aarch64-code.fd"
    ;;
  x86_64)
    QEMU_BIN="qemu-system-x86_64"
    MACHINE="-M q35 -accel hvf -cpu host"
    IMG_ARCH="amd64"
    EFI_CODE=""
    ;;
  *)
    echo "error: unsupported host architecture: $ARCH" >&2
    exit 1
    ;;
esac

# Check for running VM.
if [[ -f "${VM_DIR}/qemu.pid" ]]; then
  OLD_PID=$(cat "${VM_DIR}/qemu.pid")
  if kill -0 "$OLD_PID" 2>/dev/null; then
    if [[ "${START_ONLY}" == "true" ]]; then
      echo "VM already running (pid ${OLD_PID}), SSH: ssh -p ${SSH_PORT} ubuntu@localhost"
      exit 0
    fi
    echo "Stopping existing VM (pid ${OLD_PID})..."
    kill "$OLD_PID" 2>/dev/null || true
    sleep 2
  fi
fi

mkdir -p "${VM_DIR}"

if [[ "${START_ONLY}" == "false" ]] && [[ ! -f "${VM_DIR}/ubuntu-24.04-server-cloudimg-${IMG_ARCH}.img" ]]; then
  echo "[1/4] Downloading Ubuntu 24.04 cloud image (${IMG_ARCH})..."
  curl -fSL \
    "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-${IMG_ARCH}.img" \
    -o "${VM_DIR}/ubuntu-24.04-server-cloudimg-${IMG_ARCH}.img"

  echo "[2/4] Resizing disk to ${DISK_SIZE}..."
  qemu-img resize "${VM_DIR}/ubuntu-24.04-server-cloudimg-${IMG_ARCH}.img" "${DISK_SIZE}"
else
  echo "[1/4] Using existing disk image"
  echo "[2/4] Skipping resize"
fi

# Cloud-init for passwordless SSH.
if [[ ! -f "${VM_DIR}/seed.iso" ]]; then
  echo "[3/4] Creating cloud-init seed..."
  mkdir -p "${VM_DIR}/seed"

  cat > "${VM_DIR}/seed/meta-data" <<EOF
instance-id: bpf-vm
local-hostname: bpf-vm
EOF

  cat > "${VM_DIR}/seed/user-data" <<EOF
#cloud-config
users:
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $(cat ~/.ssh/id_ed25519.pub 2>/dev/null || cat ~/.ssh/id_rsa.pub 2>/dev/null || echo "# no SSH key found -- add one to ~/.ssh/")
packages:
  - rsync
runcmd:
  - echo 'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"' > /etc/environment
EOF

  if command -v mkisofs >/dev/null 2>&1; then
    mkisofs -output "${VM_DIR}/seed.iso" -volid cidata -joliet -rock "${VM_DIR}/seed/" 2>/dev/null
  elif command -v hdiutil >/dev/null 2>&1; then
    hdiutil makehybrid -o "${VM_DIR}/seed.iso" "${VM_DIR}/seed/" -iso -joliet 2>/dev/null
  else
    echo "warning: cannot create seed.iso (install cdrtools: brew install cdrtools)" >&2
  fi
else
  echo "[3/4] Using existing cloud-init seed"
fi

# Build QEMU command.
echo "[4/4] Booting VM..."
QEMU_ARGS=(
  ${QEMU_BIN}
  ${MACHINE}
  -smp "${CPUS}"
  -m "${RAM}"
)

# EFI firmware (required for arm64).
if [[ -n "${EFI_CODE}" ]]; then
  cp -n "${EFI_CODE}" "${VM_DIR}/efi-code.fd" 2>/dev/null || true
  if [[ ! -f "${VM_DIR}/efi-vars.fd" ]]; then
    truncate -s 64m "${VM_DIR}/efi-vars.fd"
  fi
  QEMU_ARGS+=(
    -drive "if=pflash,format=raw,file=${VM_DIR}/efi-code.fd,readonly=on"
    -drive "if=pflash,format=raw,file=${VM_DIR}/efi-vars.fd"
  )
fi

QEMU_ARGS+=(
  -drive "if=virtio,format=qcow2,file=${VM_DIR}/ubuntu-24.04-server-cloudimg-${IMG_ARCH}.img"
  -drive "if=virtio,format=raw,file=${VM_DIR}/seed.iso"
  -device virtio-net-pci,netdev=net0
  -netdev "user,id=net0,hostfwd=tcp::${SSH_PORT}-:22"
  -nographic
)

cd "${VM_DIR}"
"${QEMU_ARGS[@]}" &
QEMU_PID=$!
echo "${QEMU_PID}" > "${VM_DIR}/qemu.pid"

echo ""
echo "=== VM booting (pid ${QEMU_PID}) ==="
echo ""
echo "Wait ~60s for cloud-init to finish, then:"
echo ""
echo "  ssh -p ${SSH_PORT} ubuntu@localhost"
echo ""
echo "From your Mac:"
echo ""
echo "  make sync      # sync repo into the VM"
echo ""
echo "Inside the VM:"
echo ""
echo "  make setup     # install toolchain"
echo "  make e2e       # run full validation"
echo ""
echo "To stop the VM:"
echo "  kill ${QEMU_PID}"
