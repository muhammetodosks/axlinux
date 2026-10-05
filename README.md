# AXlinux — Sen YAML yaz, AXlinux uygulasın.

Kullanıcı odaklı, YAML tabanlı Mandatory Access Control sistemi.
Milyonlarca satır hazır politika yok: **politika senin, tek
gerçek kaynak `~/.axlinux/policy.yaml`.**

## Fedora 44 uyumlulugu

Fedora 44 (en gecerli kararli surum) SELinux **Enforcing** altinda
tam dogrulanmistir: 5/5 eBPF kanitasi, 5/5 LSM kanitasi,
enforcement aktif, 716 dogrulama kontrolu geciyor.

Fedora'ya ozgu iki davranis bilinmelidir:

- Kok dosya sistemi btrfs alt birimidir; `/etc`, `/var`, `/home`,
  `/root` yol kurallari calisir. `/tmp`, `/dev/shm`, `/run`,
  `/run/user/N` gibi **ayri mount** noktalari da calisir: daemon
  mountinfo'dan superblock cihazini okuyup `mount_point_map`'e
  yazar, BPF mount kokune ulastiginda oneki yolun altina ekler
  (`docs/policy-language.md`).
- `process.exec` / `file.execute` kurallari **sembolik baglarin
  hedefine** uygulanir: `/usr/bin/python3` bir bag ise kural
  `python3.14` icin yazilir. Bu guvenlik icin zorunludur.

Ayrinti: `DAGITIM.md` ve `CHANGELOG.md`.

## Kurulum

```bash
sudo ./scripts/install.sh
```

> **Zorunlu adım:** AXlinux, kernel'in aktif LSM zincirinde `bpf`
> bulunmadan **politika uygulayamaz**. Kurulum betiği bunu kontrol
> eder ve gerekirse açıkça uyarır.
> ```
> # /etc/default/grub  ->  GRUB_CMDLINE_LINUX_DEFAULT
> lsm=apparmor,bpf
> # sudo update-grub && sudo reboot
> ```
> Ayrıntı: [docs/INSTALL.md](docs/INSTALL.md)

## Hızlı başlangıç

```bash
axctl init                  # ~/.axlinux/ oluştur
axctl policy edit           # YAML politikanı yaz
axctl policy check          # doğrula
axctl policy simulate       # neyi etkileyeceğini gör
sudo axctl reload           # uygula
sudo axctl status           # gerçek durumu kontrol et
```

> **Neden `sudo`?** Daemon socket'i `0600` iznine sahip. Üzerinden
> `reload_policy` gönderilebildiği için herkese açık olsaydı
> (`0666`) herhangi bir yerel kullanıcı sistem genelinde politika
> değiştirebilirdi. Politika *yazma* komutları kullanıcı dizininde
> çalışır, daemon'a konuşan komutlar `sudo` ister.

Örnek politika:

```yaml
version: 1
mode: enforcing

labels:
  web:
    - nginx
    - apache2
  browsers:
    - firefox
    - chromium

rules:
  - name: "web sunucuları web içeriğini okur"
    subject: web
    object: /var/www
    action: file.read
    effect: allow

  - name: "web sunucuları shadow okuyamaz"
    subject: web
    object: /etc/shadow
    action: file.read
    effect: deny

  - name: "python dışarı çıkamaz"
    subject: python
    action: net.connect
    effect: deny
```

## Doğrulama

`5/5 kanca bağlı` **engellemenin çalıştığı anlamına gelmez.** Gerçek
test:

```bash
sudo bash tests/verify_all.sh
```

Bu betik her kancayı gerçek bir engelleme ile dener, audit kaydını
kontrol eder, mod geçişlerini doğrular ve **sistemi kilitlemez**
(kritik süreçlere kural uygulanmaz, her adımdan sonra mod kapatılır).

## Güvenlik notu: sistem kilitlenmesi

Bir kural `bash`, `sudo`, `systemd` veya `sshd` gibi **kurtarma
yolundaki** bir sürece uygulanırsa sistem kendini kilitler — oturum
kapanır ve kullanıcı sisteme erişemez. AXlinux bunu tasarım gereği
engeller:

> `bash`, `sh`, `dash`, `zsh`, `fish`, `sudo`, `su`, `doas`, `systemd`,
> `sshd`, `login`, `agetty`, `dbus-daemon`, `polkitd`,
> `NetworkManager` gibi **kurtarma yolu** süreçlerine hiçbir kural
> uygulanmaz.

Politikada bu süreçlerden birini hedeflerseniz derleme hata verir
(goşte seçilen kural hiç yazılmaz).

**Yorumlayıcılar korunmaz.** `python3`, `node`, `perl`, `ruby` gibi
süreçler listede *değildir* — çoğu gerçek uygulama bir yorumlayıcıdan
çalışır ve "python3 /etc/shadow okuyamaz" MAC'in en sık kullanılan
kuralıdır. Bunları korumak ürünü kullanılamaz hâle getirirdi ve
kilitlenmeyi önlemezdi: kullanıcı zaten korumalı bir kabuğa sahiptir.

Kuralları hedef uygulamaya uygulayın (`firefox`, `nginx`, `python3`,
`node`).
Ayrıntı: [docs/challenges-risks.md](docs/challenges-risks.md)

## Mimarî

```
~/.axlinux/policy.yaml
        │  (YAML)
        ▼
   axctl ──── axc derleyici        Python 3.10+
   (CLI)     doğrula + önceliklendir
        │  JSON-RPC / Unix socket
        ▼
   axdaemon                        Go 1.21+
        │  eBPF map'lerine yaz
        ▼
   axbpf (C) — 5 LSM kancası
        │
        ▼
   Linux çekirdek (5.15+, lsm=bpf)
        │
        ▼
   axlog (Go) — JSON audit log
```

| Bileşen | Dil | Rol |
|---------|-----|-----|
| `axctl` | Python | Kullanıcının tek arayüzü |
| `axc` | Python | YAML → doğrula → önceliklendir → JSON |
| `axdaemon` | Go | Politika yönetimi, map yazımı, RPC sunucusu |
| `axbpf` | C | 5 LSM kancası, minimum C |
| `axlog` | Go | JSON audit log servisi |

### LSM kancaları

`file_open` · `inode_permission` · `bprm_check_security` ·
`socket_connect` · `socket_bind`

## Modlar

| Mod | Davranış |
|-----|----------|
| `enforcing` | İhlal engellenir + loglanır |
| `permissive` | İhlal yalnızca loglanır |
| `disabled` | Hiçbir kısıt uygulanmaz |

## SELinux'a karşı

| | SELinux | AXlinux |
|---|---|---|
| Politika kaynağı | Hazır, milyonlarca satır | Kullanıcının YAML'ı |
| Öğrenme | `audit2allow` | `axctl learn` → 3 gün → öneri |
| Uygulama | `setenforce` + reboot riski | `axctl reload` → anında |
| Log | `audit.log` (metin) | JSON (yapılandırılmış) |
| Felsefe | Sen uyarsın | Sen yazarsın |

## Durum

Sürüm **1.0.0**. Üç dağıtımda gerçek enforcement ile uçtan uca
doğrulandı; kapsamlı test paketi 100 denetimin tamamını geçiyor.

| Bileşen | Durum | Kanıt |
|---------|-------|-------|
| eBPF LSM (5 kanca) | Çalışıyor | `bpf_programs_loaded 5/5`, `status.hooks` beşi de `true` |
| axdaemon | Çalışıyor | `tests/deep_verify.sh` D bölümü (5 kanca, gerçek engelleme) |
| axlog | Çalışıyor | `audit_healthy: true`, kalıcı JSONL (VM'lerde 6.000+ kayıt) |
| axctl | Çalışıyor | 142 birim testi + B bölümü (tüm komutlar) |
| Öğrenme modu | Çalışıyor | gözlem toplama 0 → 192, öneri YAML olarak geçerli |
| Politika dili | Çalışıyor | I ve J bölümleri: hata yolları + kenar durumlar |
| Dağıtım | Çalışıyor | tek komut kurulum, 5 paket yöneticisi, idempotent |

**Doğrulanan dağıtımlar:** Ubuntu 24.04.5 LTS · Debian 12
(bookworm) · Pardus 25.2 (yirmibes, resmî arşivden).

Kapsam dışı olanlar (bilinçli kararlar ve eklikler):
container kapsamı, GUI, imzalı politika dağıtımı, silme/oluşturma
denetimi, kullanıcı bazlı kurallar. Tam liste ve gerekçeleri
[docs/challenges-risks.md](docs/challenges-risks.md) ve
[docs/roadmap.md](docs/roadmap.md).

Kullanıcı belgeleri: [DAGITIM.md](DAGITIM.md).

## Testler

```bash
make test           # Go + Python
make test-contract  # Go↔C sabit senkronizasyonu
make verify         # ELF bölüm doğrulaması
sudo python3 tests/integration.py --daemon /usr/bin/axdaemon
```

**`test-contract` neden önemli:** Go ile C arasındaki sabitler
(aksiyon/effekt numaraları, yapı düzenleri) uyuşmazsa sistem sessizce
hiçbir şeyi engellemez. `EFFECT_DENY`in ters yazılması tüm deny
kurallarını sessizce etkisizleştirir. Testler bu yüzden `axbpf.h`'yi
ayrıştırıp Go sabitleriyle karşılaştırır.

## Güvenlik notu

Bu bir erişim kontrol aracıdır. Yanlış politika sizi kendi
sisteminizden kapatabilir. Sırayla ilerleyin:

```
axctl policy check → simulate → mode permissive → mode enforcing
```

Acil çıkış her zaman çalışır: `sudo axctl mode disabled`.
Bu komut modu `mode_map`'e yazar; yalnızca Go belleğini güncelleyen
sürümlerde acil çıkış sessizce hiçbir şey yapmıyordu.

`root` AXlinux'u baypas eder; bu kabul edilmiş bir sınırdır.

## Dokümantasyon

- [Kurulum](docs/INSTALL.md) — `lsm=bpf` adımı dahil
- [Mimari](docs/architecture.md)
- [Politika Dili](docs/policy-language.md)
- [Bileşen Tasarımı](docs/component-design.md)
- [CLI Referansı](docs/cli-reference.md)
- [Kullanıcı Senaryoları](docs/user-scenarios.md)
- [Zorluklar ve Riskler](docs/challenges-risks.md)
- [Yol Haritası](docs/roadmap.md)

## Lisans

MIT — bkz. [LICENSE](LICENSE)
