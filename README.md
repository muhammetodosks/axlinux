# AXlinux

**YAML yaz, AXlinux uygulasın.**

Kullanıcı odaklı, Mandatory Access Control (MAC) sistemi. Milyonlarca
satır hazır politika yok — **politika senin**, tek gerçek kaynağın
`~/.axlinux/policy.yaml`.

```yaml
# ~/.axlinux/policy.yaml
version: 1
mode: enforcing
rules:
  - id: gizli-anahtarlar
    name: "SSH ve GPG anahtarları okunamaz"
    subject: [cat, less, vim]
    object: /home/kullanici/.ssh
    action: file.read
    effect: deny
```

Tek komutla çalışır, `cat ~/.ssh/id_rsa` çıktısı `Operation not permitted` olur.

> ⚠️ **Bu yazılım yalnızca sanal makinede çalıştırılır.**
> Erişim denetimi uygular; ana makinede çalıştırılırsa sistemi kilitleyebilir.
> `axctl` bunu ayrıca denetler ve reddeder. Ayrıntı: [Güvenlik](#güvenlik).

---

## İçindekiler

- [Neden AXlinux?](#neden-axlinux)
- [Özellikler](#özellikler)
- [Gereksinimler](#gereksinimler)
- [Kurulum](#kurulum)
- [Hızlı başlangıç](#hızlı-başlangıç)
- [Nasıl çalışır](#nasıl-çalışır)
- [Fedora'ya özgü davranışlar](#fedoraya-özgü-davranışlar)
- [Doğrulanmış durum](#doğrulanmış-durum)
- [Testler](#testler)
- [Güvenlik](#güvenlik)
- [Katkı](#katkı)
- [Lisans](#lisans)

---

## Neden AXlinux?

| | SELinux | AXlinux |
|---|---|---|
| Politika kaynağı | Hazır, milyonlarca satır | **Senin YAML'ın** |
| Kim yazar? | Fedora ekibi | Sen |
| Öğrenme | `audit2allow` | `axctl learn` → gözlem → öneri |
| Uygulama | `setenforce` + reboot riski | `axctl reload` → **anında** |
| Log | `audit.log` (metin) | JSONL (yapılandırılmış, sorgulanabilir) |
| Etki alanı | Sistem geneli | Süreç, yol, eylem — sen seçersin |

SELinux kaldırılmak için değil, **tamamlanmak** için vardır. İkisi
birlikte çalışır: SELinux alan sınırını verir (`axdaemon` kendi
alanında çalışır), AXlinux içerik kurallarını yazar.

## Özellikler

- **YAML politika dili** — derlenmiş bir dil değil, okunabilir metin.
- **Dizin kuralları içeriği korur** — `object: /tmp/gizli` ise içindeki
  tüm dosyalar da korunur (derinlik 1/2/3 doğrulanmıştır).
- **Altı aksiyon türü** — `file.read`, `file.write`, `file.execute`,
  `inode_permission`, `socket_connect`, `socket_bind`.
- **Beş LSM kancası** — `file_open`, `inode_permission`,
  `bprm_check_security`, `socket_connect`, `socket_bind`.
- **Üç mod** — `enforcing` (engelle), `permissive` (yalnız logla),
  `disabled` (kısıt yok).
- **Kalıcı politikalar** — `policies.d/` altındaki dosyalar açılışta
  otomatik yüklenir.
- **Önden görme** — `axctl policy simulate` kuralların etkisini
  uygulamadan önce gösterir.
- **Öğrenme modu** — `axctl learn` gözlem toplar, politika önerir.
- **Etiketler** — süreçlere etiket atayıp kuralları etiket üzerinden yaz.
- **Yapılandırılmış denetim** — JSONL log, `--subject` / `--effect` /
  `--action` ile sorgulanır.
- **Anında uygulama** — `axctl reload`; yeniden başlatma gerekmez.

## Gereksinimler

| Bileşen | Sürüm | Not |
|---|---|---|
| İşletim sistemi | Fedora 41–44 | RHEL türevleri de çalışır |
| Çekirdek | **5.15+** | `CONFIG_BPF_LSM=y` **ve** `lsm=bpf` zincirde olmalı |
| clang | 12+ | `-target bpf` desteklemeli |
| Go | 1.21+ | yalnızca **derleme** için |
| Python | 3.9+ | `click`, `rich`, `PyYAML` |
| Kök yetkisi | — | kurulum ve `axctl` için |

## Kurulum

### RPM (Fedora)

```bash
sudo dnf install ./axlinux-1.2.0-1.x86_64.rpm
```

Paket imzalıdır:

```bash
rpm -Kv axlinux-1.2.0-1.x86_64.rpm
# Header OpenPGP V4 RSA/SHA512 signature,
#   key fingerprint: f108e5cc55806bbb4fc42afa6a2e2989448a5310: OK
```

### .deb (Debian / Ubuntu / Pardus)

```bash
sudo apt install ./axlinux_1.2.0_amd64.deb
```

### Kaynaktan

```bash
git clone https://github.com/muhammetodosks/axlinux.git
cd axlinux
sudo ./scripts/install.sh
```

### Zorunlu ön koşul: `bpf` LSM

AXlinux, kernel'in aktif LSM zincirinde `bpf` bulunmadan politika
**uygulayamaz**. `install.sh` bunu denetler ve gerekirse uyarır.

```bash
# /etc/default/grub  ->  GRUB_CMDLINE_LINUX_DEFAULT
lsm=apparmor,bpf
sudo update-grub && sudo reboot
```

Denetlemek için:

```bash
cat /sys/kernel/security/lsm
# lockdown,capability,yama,selinux,bpf,...   <- "bpf" olmalı
```

Ayrıntı: [docs/INSTALL.md](docs/INSTALL.md)

## Hızlı başlangıç

```bash
axctl init                  # ~/.axlinux/ oluştur
axctl policy edit           # YAML politikanı yaz
axctl policy check          # doğrula
axctl policy simulate       # neyi etkileyeceğini ÖNCE gör
axctl mode permissive       # loglar, engellemez
axctl reload                # uygula
axctl status                # gerçek durumu kontrol et
```

**Önerilen sıra bu.** `simulate` en önemli komuttur — kuralların neyi
etkileyeceğini uygulamadan önce gösterir.

### Örnek politikalar

Depodaki `examples/` klasöründe dört hazır örnek var; hepsi
`axctl policy check` ile doğrulanmıştır:

| Dosya | Amaç |
|---|---|
| `examples/minimal.yaml` | En küçük başlangıç örneği |
| `examples/desktop.yaml` | Masaüstü kullanımı (SSH/GPG anahtarları, tarayıcı profilleri) |
| `examples/web-server.yaml` | Web sunucusu (yapılandırma ve günlük koruması) |
| `packaging/fedora/axlinux-sample-workstation.yaml` | Kurulumla gelen örnek (kasıtlı olarak boş) |

Kopyalamak için:

```bash
sudo cp examples/desktop.yaml /etc/axlinux/policies.d/50-desktop.yaml
sudo axctl reload
```

Politika dili: [docs/policy-language.md](docs/policy-language.md)

## Nasıl çalışır?

```
  axctl (Python)                     axdaemon (Go)                çekirdek
       │                                   │                          │
  YAML ──┤ policy check / simulate         │                          │
       │                                   │                          │
  policy.yaml ─────────────────────────────►│                          │
       │                            eBPF programlarını yükle         │
       │                                   ├─────────────────────────►│
       │                                   │      LSM kancaları bağla  │
       │                                   ├─────────────────────────►│
       │                                   │      deny_map / allow_map │
       │                                   ├─────────────────────────►│
       │◄────── status (kanca, kural) ──────┤                          │
       │                                   │                          │
       │◄────── logs (JSONL) ──────────────┴──── audit perf buffer ───┤
```

`axdaemon` politikayı eBPF haritalarına yazar ve LSM kancalarını bağlar.
Çekirdek, kararı kanca anında verir — kullanıcı alanına girmez, süreç
beklemez. İhlaller JSONL olarak `/var/log/axlinux/` altına düşer.

SELinux modülü (`axlinux.pp`) `bpf()` yetkisini **yalnızca** `axdaemon`
alanına verir; sistem geneline açmaz.

## Fedora'ya özgü davranışlar

İki davranış bilinmelidir:

**1. Kök dosya sistemi btrfs alt birimidir.** `/etc`, `/var`, `/home`,
`/root` yol kuralları çalışır. `/tmp`, `/dev/shm`, `/run`,
`/run/user/N` gibi ayrı bağlama noktaları da çalışır: daemon
`mountinfo`'dan süperblok aygıtını okuyup `mount_point_map`'e yazar ve
BPF bağlama köküne ulaştığında öneki yolun altına ekler.

**2. `file.execute` kuralları sembolik bağların hedefine uygulanır.**
`/usr/bin/python3` bir bağ ise kural `python3.14` için yazılır.
Bu güvenlik için zorunludur — aksi hâlde bağ üzerinden kural atlanır.

## Doğrulanmış durum

Tüm sayılar **ölçülmüştür**. Kaynak: [`DOGRULAMA-RAPORU.md`](DOGRULAMA-RAPORU.md).

### `deep_verify.sh` — 732 kontrol

| Platform | geçti | kaldı | atlandı |
|---|---|---|---|
| **Fedora 44** | **732** | **0** | **0** |
| Fedora 43 | 732 | 1 | 1 |
| Ubuntu 24.04.5 | 731 | 0 | 1 |
| Debian 12 | 731 | 0 | 1 |
| Pardus 25.2 | 731 | 0 | 1 |

Debian ailesindeki tek atlanan kalem `SELinux yok`'tur — Debian ailesi
SELinux sağlamaz; bu eksik değil, platform farkıdır. Fedora 44'te
**hiçbir kalem atlanmaz**.

Fedora 43'teki tek kalem, o imajda SELinux kuşaklamasının eBPF yüklemeyi
engellediğini dürüstçe bildiren rapordur; enforcement çalışmaktadır
(kanca 5/5, eBPF 5/5).

### Ölçülen performans

| Ölçüm | Değer |
|---|---|
| `axdaemon` RSS | 108.236 kB (~106 MB) |
| Açık dosya tanıtıcı | 33 |
| 50.000 dosya açma (`enforcing`) | 0.559 s (~89.600 açma/sn) |
| 50.000 dosya açma (`disabled`) | 0.228 s (~220.000 açma/sn) |
| Politika sorgusu maliyeti | +5.8 µs (aralıklar çakışmıyor — ölçülebilir) |

Fark 0.33 saniye: tarayıcı açılışı gibi gerçek bir iş yükünde
algılanmayacak büyüklükte.

> Mutlak mikrosaniye değerleri tek başına ölçüt değildir — aynı ölçüm
> Ubuntu'da Fedora'ya göre ~20 kat yavaş çıkar, çünkü sanal makine ortamı
> belirleyicidir. Bu yüzden test paketi **göreli oran** uygular.

### Paketleme matrisi

Beş imajın beşinde de paketleme koşuldu: `fedora:41/42/43/44` ve
`debian:12` — her biri 8/8 içerik + 5 conffiles + SELinux modülü.

## Testler

```bash
# Yerel paket — hızlı
python3 -m pytest tests/ -q          # 179 test + 20 alt test
cd src/go/axdaemon && go test ./...  # 10 paket
cd src/go/axlog    && go test ./...  # 3 paket

# Tam doğrulama — sanal makine gerektirir
sudo bash tests/deep_verify.sh
```

`deep_verify.sh` 732 kontrolü çalıştırır ve tek rapor üretir. Fiziksel
makinede çalışmayı **reddeder** — bu bilinçli bir güvenlik sınırıdır.

Ayrıntı: [DOGRULAMA-RAPORU.md](DOGRULAMA-RAPORU.md)

## Güvenlik

### Acil çıkış

```bash
sudo axctl mode disabled
```

Her zaman çalışır ve tüm kısıtları kaldırır.

### Güvenli uygulama sırası

```
1. axctl policy check      → sözdizimi ve anlam doğrulaması
2. axctl policy simulate  → etkiyi önceden gör
3. axctl mode permissive   → loglar, engellemez
4. axctl reload            → uygula
5. axctl status            → gerçek durumu doğrula
```

### Bilinen sınır

`inode_permission` kancası kernel ABI'si gereği **yol alamaz** —
yalnızca `struct inode *` verilir, dentry'ye geri referans yoktur.
Çözüm olarak `ino` + `dev` kimliği audit kaydına eklenir; yol gerektiren
kayıtlar `file_open` ve `bprm_check_security` kancalarında kalır.

### Güvenlik açığı bildirimi

Güvenlik açığı bulursanız lütfen [SECURITY.md](SECURITY.md) içindeki
yöntemi izleyin — herkese açık issue yerine özel bildirim.

## Katkı

Katkılar memnuniyetle karşılanır:
[CONTRIBUTING.md](CONTRIBUTING.md)

## Lisans

MIT — bkz. [LICENSE](LICENSE)

## Belgeler

| Belge | İçerik |
|---|---|
| [DOGRULAMA-RAPORU.md](DOGRULAMA-RAPORU.md) | Her iddianın nasıl kanıtlandığı, bulunan gerçek hatalar |
| [DAGITIM.md](DAGITIM.md) | Kurulum yolları ve platform sonuçları |
| [SUPPORT.md](SUPPORT.md) | Desteklenen sistemler ve sınırlar |
| [FEDORA-READINESS.md](FEDORA-READINESS.md) | Fedora ölçüm tabloları |
| [CHANGELOG.md](CHANGELOG.md) | Sürüm geçmişi |
| [docs/INSTALL.md](docs/INSTALL.md) | Ayrıntılı kurulum |
| [docs/policy-language.md](docs/policy-language.md) | Politika dili |
| [docs/cli-reference.md](docs/cli-reference.md) | Tüm komutlar |
| [docs/architecture.md](docs/architecture.md) | İç mimari |