# lsm-file-open

Audits every file open on the system using a BPF LSM (Linux Security Module) hook, demonstrating security-focused eBPF with tinybpf.

```mermaid
graph LR
    A["kernel: file_open()"] --> B["BPF LSM hook"]
    B --> C["ring buffer"]
    C --> D["userspace tracer"]
    D --> E["stdout: pid, uid, comm"]
```

## What it does

The BPF program attaches to the `file_open` LSM hook and emits an event to a ring buffer for every file open. The userspace tracer reads events and prints the process ID, user ID, and command name. The hook returns `0` (allow), so it observes without blocking.

This is the pattern used by security tools like Tetragon and Falco for file access auditing.

## Prerequisites

| Requirement | Details |
|-------------|---------|
| Kernel | 5.7+ with `CONFIG_BPF_LSM=y` and `bpf` in the `lsm=` boot parameter |
| Capabilities | `CAP_BPF` + `CAP_MAC_ADMIN` (or root) |
| Toolchain | TinyGo 0.40+, LLVM 20+, tinybpf |

### Enabling BPF LSM

Most distributions do not enable BPF LSM by default. Check and enable:

```bash
# Check current LSM list
cat /sys/kernel/security/lsm

# Add bpf to the boot parameter (GRUB)
# Edit /etc/default/grub, add to GRUB_CMDLINE_LINUX:
#   lsm=lockdown,capability,landlock,yama,bpf
sudo update-grub && sudo reboot
```

## Build

```bash
make example NAME=lsm-file-open
```

## Run

```bash
sudo ./examples/lsm-file-open/scripts/run.sh
```

Expected output:

```
attached LSM file_open hook from build/lsm.bpf.o
press Ctrl+C to stop
2025-01-15T10:30:00.123Z pid=1234 uid=1000 comm=cat
2025-01-15T10:30:00.456Z pid=1235 uid=0 comm=systemd
```

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `attach LSM: invalid argument` | Kernel lacks `CONFIG_BPF_LSM=y` or `bpf` not in `lsm=` boot parameter |
| `no programs found` | Rebuild with `make example NAME=lsm-file-open` |
| No events appear | Trigger file opens in another terminal: `cat /etc/hostname` |
