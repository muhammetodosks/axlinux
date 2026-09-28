# AXlinux — Sen YAML yaz, AXlinux uygulasın.

Kullanıcı odaklı, YAML tabanlı Mandatory Access Control sistemi.
Milyonlarca satır hazır politika yok: **politika senin, tek
gerçek kaynak `~/.axlinux/policy.yaml`.**

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
axctl status                # gerçek durumu kontrol et
```

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

| Bileşen | Durum | Kanıt |
|---------|-------|-------|
| eBPF LSM (5 kanca) | derleniyor, kernel verifier kabul ediyor | `make verify` |
| axdaemon | derleniyor, soket sunucusu çalışıyor | entegrasyon testleri |
| axlog | derleniyor | `go vet` |
| axctl | çalışıyor | birim testleri |
| Çekirdekte uygulama | `lsm=bpf` gerektirir | `axctl status` açıkça bildirir |

**v0.1 kapsamındadır.** Container/K8s, GUI, imzalama ve AI önerisi
yol haritasındaki sonraki sürümlerdedir. Bkz. [docs/roadmap.md](docs/roadmap.md).

## Testler

```bash
make test           # Go + Python
make test-contract  # Go↔C sabit senkronizasyonu
make verify         # ELF bölüm doğrulaması
sudo python3 tests/integration.py --daemon /usr/local/bin/axdaemon
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

Acil çıkış her zaman çalışır: `axctl mode disabled`.

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
