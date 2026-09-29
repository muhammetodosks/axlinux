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

### Tam dogrulama (onerilen)

Yukaridaki kontroller LSM zincirinin dogru oldugunu gosterir ama
**engellemenin gercekten calistigini kanitlamaz**. "5/5 kanca bagli"
olmasi, kurallarin uygulandigi anlamina gelmez.

```bash
sudo bash tests/verify_all.sh
```

Bu betik sunlari yapar ve **sistemi kilitlemez**:

1. LSM zincirini dogrular
2. Daemon'u baslatir
3. Her kanca icin gercek engelleme dener (`file_open`,
   `inode_permission`, `socket_bind`, `socket_connect`, `bprm`)
4. Audit kaydinin dogru geldigini dogrular
5. Mod gecislerini (enforcing/permissive/disabled) dogrular
6. Kilitlenme korumasini kanitlar

Her adimdan sonra mod `disabled`'a cekilir, boylece bir adim takilsa
bile sonraki calistirmalarda oturum kilitlenmez.

### Dogrulama sirasinda takilirsaniz

`tests/verify_all.sh` veya `axctl set-mode disabled` **calismiyorsa**
sistem kilitlenmis olabilir. Bu durumda:

```bash
# GRUB'dan bpf'yi kaldirip yeniden baslat (acil cikis)
sudo sed -i 's/,bpf"$/"/' /etc/default/grub
sudo update-grub && sudo reboot
```

Yedek: `/etc/default/grub.axlinux-backup`

Nadiren olur: koruma (`ax_protected`) normalde `bash`, `sudo`,
`systemd`, `sshd` gibi sureclere kural uygulanmasini engeller. Bir
kuralin yanlislikla bir arac zinciri surecini hedefledigi durumlarda
bu onlem devreye girer. `tests/test_protection.py` listesin
dogru kaldigini dogrular.

Reboot sonrasi calistirilacak tek komut:

```bash
sudo bash scripts/recover-and-verify.sh
```

Derler, test eder, gercek enforcement'i dogrular ve gecerse git
commit yapar.

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

### subject icin ne secmeliyim

`subject` alanina **hedef uygulamayi** yazin. Sistem sureclerini
(`bash`, `sudo`, `systemd`, `sshd`) yazmayin: AXlinux bunlara
guvenlik geregi hicbir kural uygulamaz ve kural sessizce
etkisiz kalir.

```yaml
# Dogru: hedef uygulama
subject: firefox

# Etkisiz: korumali surec (uyari verilir)
subject: bash
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

Socket izni `0600`'dir: yalnizca root baglanabilir. Bu bilincli bir
karardir — socket uzerinden `reload_policy` gonderilebildigi icin
herkese acik olsaydi (`0666`) herhangi bir yerel kullanici sistem
genelinde politika degistirebilirdi.

Bu yuzden `axctl` komutlarini `sudo` ile calistirin:

```bash
sudo axctl status
sudo axctl mode enforcing
```

Dogrudan socket'e baglanmak da ayni sekilde `sudo` gerektirir.

**Politika yuklendi ama bir sey engellenmiyor**
Sirasiyla kontrol edin:

1. `sudo axctl status` -> `lsm_hooks_active` 5 mi?
   5 degilse `hooks_missing` hangi kancayi gosterir; enforcement
   KISMIDIR ve eksik kancalara yazilan kurallar etkisiz kalir.
2. Mod `enforcing` mi? (`sudo axctl mode enforcing`)
3. `audit_healthy` `true` mu? `false` ise kararlar kaydedilmiyor
   demektir; enforcement calisiyor olabilir ama kanit toplanmiyor.
4. Log'da kural isabet ediyor mu? (`sudo axctl logs --filter effect=deny`)

Yanlis `effect` degerleri sessizce hicbir seyi engellemez; bu yuzden
`go test ./internal/maps/` sozlesme testi calistirilir.

**Desteklenmeyen eylem reddediliyor**
`file.delete`, `file.create` ve `net.accept` icin LSM kancasi yok.
Bunlarla yazilan kurallar yukleme aninda hata verir; bu bir eksiklik
degil, sessiz basarisizligi onleme kararidir. Silme kontrolu icin
dosya sistemi izinlerini (`chmod`, ACL) kullanin.
