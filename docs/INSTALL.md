# AXlinux kurulumu

## Gereksinimler

| Bileşen | Sürüm | Not |
|---------|-------|-----|
| Kernel | 5.15+ | `CONFIG_BPF_LSM=y` **ve** `lsm=bpf` |
| clang | 12+ | eBPF hedefi desteklemeli (`-target bpf`) |
| Go | 1.21+ | axdaemon ve axlog |
| Python | 3.10+ | axctl |
| libbpf | 1.0+ | `libbpf-dev` |

## 1. BPF LSM'i etkinlestir (EN ONEMLI ADIM)

BPF LSM derlenmis olsa bile, boot parametresiyle aktif LSM zincirine
eklenmedikce hicbir program baglanamaz. Bu adim atlanirsa
`axdaemon` su hatayi verir:

```
libbpf: prog 'ax_file_open': BPF program load failed: -EACCES
```

Mevcut zinciri kontrol et:

```bash
cat /sys/kernel/security/lsm
# lockdown,capability,landlock,yama,apparmor,ima,evm
#                                   ^^^^^^^^^ bpf YOK
```

`bpf` listede degilse GRUB'a ekle.

```bash
sudoedit /etc/default/grub
```

GRUB_CMDLINE_LINUX satirini su sekilde duzenle (apparmor ile birlikte
calisir, sadece bpf tek basina yazma):

```
GRUB_CMDLINE_LINUX_DEFAULT="... lsm=apparmor,bpf"
```

Sonra:

```bash
sudo update-grub
sudo reboot
```

Dogrulama:

```bash
cat /sys/kernel/security/lsm
# bpf gorunuyor olmali
```

> Not: Ubuntu'da `apparmor` MAC slotunu kaplar. `bpf`yi eklemezsen
> AXlinux baglanamaz; ikisi birlikte zincirde sirayla calisir.

## 2. Bagimliliklar

```bash
# Debian / Ubuntu
sudo apt install clang llvm libbpf-dev python3-pip make

# Fedora
sudo dnf install clang llvm libbpf-devel python3-pip make

# Arch
sudo pacman -S clang llvm libbpf python-pip make
```

## 3. Derle

```bash
git clone <repo> axlinux && cd axlinux
sudo make install
```

Ayrintili:

```bash
make            # her seyi derler
make bpf        # yalnizca eBPF (axbpf.o)
make verify     # sozlesme + bolum dogrulamasi
make test       # Go + Python testleri
make install    # /usr/local/bin ve /usr/lib/axlinux altina kurar
```

## 4. Dogrulama

```bash
axctl init
axctl policy check
sudo systemctl start axdaemon
axctl status
```

Beklenen: `eBPF Programları  5/5 yüklü` ve `LSM Kancaları  5/5 aktif`.

Bunlar `0/5` ise LSM baglanmamistir: `cat /sys/kernel/security/lsm`
ciktisinda `bpf` olmalidir.

## 5. Ilk politika

```bash
axctl policy edit
```

```yaml
version: 1
mode: enforcing
rules:
  - name: "firefox /etc/shadow okuyamaz"
    subject: firefox
    object: /etc/shadow
    action: file.read
    effect: deny
```

```bash
axctl policy check
axctl policy simulate
sudo axctl reload
axctl status
```

## Sorun giderme

**`BPF program load failed: -EACCES`**
`lsm=bpf` boot parametresi eksik. Yukariya bakin.

**`axbpf.h: No such file`**
`make` calistirin, `vmlinux.h` otomatik uretilir. Elle uretilmis
`vmlinux.h` calismazsa:

```bash
cd src/bpf && rm -f vmlinux.h && make
```

**`permission denied` (socket)**
`/run/axlinux` yok. `sudo mkdir -p /run/axlinux` ya da servisi root ile
baslatin.

**Politika yuklendi ama bir sey engellenmiyor**
Sirasiyla kontrol edin:

1. `axctl status` -> `lsm_hooks_active` 5 mi?
2. Mod `enforcing` mi? (`axctl mode enforcing`)
3. Log'da kural isabet ediyor mu? (`axctl logs --filter effect=deny`)

Yanlis `effect` degerleri sessizce hicbir seyi engellemez; bu yuzden
`go test ./internal/maps/` sozlesme testi calistirilir.
