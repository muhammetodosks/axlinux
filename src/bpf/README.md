# Build instructions for the AXlinux eBPF programs

## Requirements

- `clang` 12+
- `libbpf-dev`
- Linux kernel 5.15+ (`CONFIG_BPF_LSM=y`)
- Kernel header directories

## Building

```bash
cd src/bpf
make
```

This produces the following executable object files:

- `file_open.bpf.o`
- `inode_permission.bpf.o`
- `bprm_check_security.bpf.o`
- `socket_connect.bpf.o`
- `socket_bind.bpf.o`

## Cleaning

```bash
make clean
```

## Testing

The eBPF programs can only be loaded on Linux and only with the
`CAP_BPF`/`CAP_SYS_ADMIN` privileges.

```bash
sudo bpftool prog load file_open.bpf.o /sys/fs/bpf/ax_file_open type lsm
sudo bpftool prog list
```