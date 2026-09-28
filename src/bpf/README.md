# AXlinux eBPF programları derleme talimatları

## Gereksinimler

- `clang` 12+
- `libbpf-dev`
- Linux kernel 5.15+ (`CONFIG_BPF_LSM=y`)
- Kernel başlık dizinleri

## Derleme

```bash
cd src/bpf
make
```

Bu işlem aşağıdaki çalıştırılabilir nesne dosyalarını üretir:

- `file_open.bpf.o`
- `inode_permission.bpf.o`
- `bprm_check_security.bpf.o`
- `socket_connect.bpf.o`
- `socket_bind.bpf.o`

## Temizlik

```bash
make clean
```

## Test

eBPF programları sadece Linux üzerinde ve `CAP_BPF`/`CAP_SYS_ADMIN` yetkisi ile yüklenebilir.

```bash
sudo bpftool prog load file_open.bpf.o /sys/fs/bpf/ax_file_open type lsm
sudo bpftool prog list
```
