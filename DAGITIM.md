# AXlinux 1.1.0 — Dağıtım Belgesi

**Sen YAML yaz, AXlinux uygulasın.**

AXlinux, çekirdeğin LSM (Linux Security Module) zincirine eBPF kancaları
yerleştirerek **hangi sürecin hangi dosyayı okuyup yazdığını, hangi
porta bağlandığını ve neyi çalıştırdığını** gerçek zamanlı denetler.
Kural yazarsın, uygularsın. Kural yazmazsan sistem serbest kalır.

| | |
|---|---|
| Sürüm | **1.2.0** |
| Sürücü modülü | Linux LSM + eBPF (CO-RE) |
| Dağıtım | `axdaemon` (Go), `axlog` (Go), `axctl` (Python 3) |
| Doğrulanmış | Ubuntu 24.04.5, Debian 12 (bookworm), **Pardus 25.2 (yirmibes)** |
| Test sonucu | 3 dağıtımda da **99 geçen / 0 kalan / 0 atlanan**, 125 birim testi |

---

## 1. Durum

AXlinux üç dağıtımda **gerçek enforcement** ile uçtan uca doğrulandı.
Testler sanal makinede çalıştırıldı; her iki LSM kancası grubu da
gerçekten eBPF'den geçirildi.

| Doğrulanan | Sonuç |
|---|---|
| Ubuntu 24.04.5 LTS | 100/0/0 · 5/5 eBPF programı · 5/5 kanca · audit sağlıklı |
| Debian 12 (bookworm) | 100/0/0 · 5/5 · 5/5 · audit sağlıklı |
| Pardus 25.2 (yirmibes) | 100/0/0 · 5/5 · 5/5 · audit sağlıklı |

Kapsanan alanlar: tüm CLI komutları, öğrenme modu baştan sona, 5 LSM
kancası, 6 aksiyon türü, kalıcı JSONL audit, üç mod ve acil kapatma,
kilitlenme koruması, hata yolları ve politika dili kenar durumları.

---

## 2. Gereksinimler

| Bileşen | Sürüm | Not |
|---|---|---|
| Kernel | **5.15+** | `CONFIG_BPF_LSM=y` **ve** `lsm=bpf` zincirde olmalı |
| clang | 12+ | `-target bpf` desteklemeli |
| Go | 1.21+ | yalnızca **derleme** için (çalıştırmada gerekmez) |
| Python | 3.9+ | `click`, `rich`, `PyYAML` |
| Kök yetkisi | — | kurulum ve `axctl` için |

Çekirdeğin LSM desteğini doğrula:

```bash
cat /sys/kernel/security/lsm      # çıktıda 'bpf' geçmeli
```

`bpf` listede yoksa önce `/boot/config-$(uname -r)` içinde
`CONFIG_BPF_LSM=y` olduğundan emin ol. Kimlik doğrulama (authentication)
için `lockdown`, `capability`, `landlock`, `yama`, `apparmor`, `tomoyo`
gerekli değildir — AXlinux bunların yerine geçmez, **eklenir**.

---

## 3. Kurulum

```bash
tar -xzf axlinux-kaynak-<tarih>.tar.gz
cd axlinux
sudo bash install.sh
```

Betik 10 adımda ilerler ve ne yaptığını her adımda yazar. Şu anda:

```
[ 1/10] Yetki denetimi
[ 2/10] Ortam denetimi
[ 3/10] bpf LSM denetimi
[ 4/10] Bağımlılıklar
[ 5/10] Kaynak kod
[ 6/10] Derleme
[ 7/10] Kurulum
[ 8/10] Servisler
[ 9/10] Doğrulama
[10/10] İlk politika
```

Sessiz (unattended) kurulum:

```bash
sudo bash install.sh --unattended
```

Kurulum **dağıtım bağımsızdır**: `apt-get`, `dnf`/`yum`, `pacman`,
`apk` ve `zypper` desteklenir. Bulunamayan tek paket tüm kurulumu
düşürmez — paketler tek tek kurulur, olmayanlar atlanır ve raporlanır.

### Kurulum ne yapar

| Yol | İçerik |
|---|---|
| `/usr/bin/axctl` | CLI girişi |
| `/usr/bin/axdaemon` | LSM uygulayıcı (Go) |
| `/usr/bin/axlog` | Audit yazıcı (Go) |
| `/usr/lib/axlinux/` | `axbpf.o` ve Python paketi |
| `/etc/axlinux/` | Örnek politikalar |
| `/etc/systemd/system/` | `axdaemon.service`, `axlog.service` |
| `/usr/lib/tmpfiles.d/axlinux.conf` | `/run/axlinux` yönetimi |
| `~/.axlinux/policy.yaml` | Senin politikân (kullanıcı başına) |

---


## Fedora 44 (SELinux Enforcing)

Fedora AXlinux'in birincil hedef dagitimidir ve **Enforcing** SELinux
altinda dogrulanmistir. `selinux=permissive` kullanilmaz.

### Fedora'ya ozgu davranislar

Kok dosya sistemi bir **btrfs alt birimidir** (`subvolid=256`,
`mountinfo: root=/root mountpoint=/`). Bu, yol cozumlemesinde iki
ayri konuyu dogurur:

| Konum | Gorunur yol | Not |
|---|---|---|
| `/etc/...` | `/etc/...` | calisir |
| `/var/...`, `/home/...` | `/var/...`, `/home/...` | calisir |
| `/root/...` | `/root/...` | calisir |
  | `/tmp/...`, `/dev/shm/...`, `/run/...` | `/tmp/...` | calisir (mount noktasi haritasi) |

Kok dosya sistemi btrfs alt birimi: gorunmez `root` bileseni
`mount_artifact_map` ile atilir. Ayri mount'lar (`/tmp` tmpfs):
gorunmez mount noktasi oneki `mount_point_map` ile geri eklenir.
Ikisi de `tests/deep_verify.sh` icinde gercek deny kurallariyla
dogrulanir (`ayri mount yolu [tmpfs /tmp] uygulandi`).
`/tmp` bir tmpfs mount oldugu icin mount noktasinin adi dentry
zincirinde gorunmez. Bu yapisal bir sinirdir, bir hata degildir.
Yol kurallari kullanirken mutlak yolun **kok dosya sisteminde**
oldugundan emin olun.

SELinux tarafi:

```bash
# Surecler kendi alanlarinda calisir
$ ps -eo label,comm | grep ax
system_u:object_r:axlinux_daemon_t:s0 axdaemon
system_u:object_r:axlinux_log_t:s0      axlog

# Politika gercekten yuklu mu
$ sudo semodule -l | grep axlinux
axlinux
```

SELinux modulu `selinux-policy-devel` gerektirir; `install.sh`
paketi kendisi kurar ve modulu her seferinde yeniden derler.

### Fedora dogrulama sonucu

Fedora 44, kernel `6.19.10-300.fc44.x86_64`, SELinux Enforcing
uzerinde:

```
bpf: 5/5   kancalar: 5/5   enforcement: True   audit sagligi: True
tests/deep_verify.sh: 716 gecti / 0 kaldi / 2 atlandi
```

## 4. İlk beş dakika

```bash
# 1) Başlangıç: boş politika = sistem serbest
sudo axctl init

# 2) Hazır şablonlardan birini incele
axctl template ls
sudo axctl template apply web-server
axctl policy check              # uygulamadan ÖNCE doğrula

# 3) Uygula
sudo axctl reload --mode enforcing

# 4) Ne oluyor?
axctl status
axctl logs --limit 20

# 5) Kendi kuralını yaz
nano ~/.axlinux/policy.yaml
axctl policy check && sudo axctl reload
```

Bir kural şöyle görünür:

```yaml
version: 1
mode: enforcing
rules:
  - id: r1
    name: "nginx shadow okuyamaz"
    subject: nginx
    object: /etc/shadow
    action: file.read
    effect: deny
```

`subject` süreç adı, `object` yol (veya port), `action` ne yapılacağı,
`effect` izin mi yasak mı.

---

## 5. Komut referansı

| Komut | Ne yapar |
|---|---|
| `axctl init [--force]` | `~/.axlinux/` dizinini ve boş politikayı oluşturur |
| `axctl status [--json]` | LSM durumu, kancalar, sayaçlar, sağlık |
| `axctl reload [--mode M] [--force-empty]` | Politikayı derler ve uygular |
| `axctl mode enforcing\|permissive\|disabled` | Modu değiştirir |
| `axctl logs [--json] [--subject S] [--action A] [--effect E] [--filter K=V] [--since 1h] [--limit N] [--follow]` | Audit kayıtları |
| `axctl label add AD SÜRÜCÜ...` | Etiket tanımlar (birden çok süreç) |
| `axctl label ls` | Etiketleri listeler |
| `axctl label rm AD` | Etiketi siler |
| `axctl learn start [--days N]` | Öğrenme modunu başlatır |
| `axctl learn stop` | Öğrenmeyi durdurur |
| `axctl learn report [--format text\|json]` | Gözlem raporu + öneri YAML |
| `axctl template ls` | Hazır şablonları listeler |
| `axctl template apply AD` | Şablonu politikaya uygular |
| `axctl policy edit` | Politikayı editörde açar |
| `axctl policy check [-f DOSYA]` | Doğrular (uygulamadan önce!) |
| `axctl policy simulate [-f DOSYA] [--format json]` | Etkisini simüle eder |

### Çıkış kodları

Betikler bunlara güvenir:

| Kod | Anlamı | Örnek |
|---|---|---|
| `0` | başarı | — |
| `1` | **daemon'ın uygulama seviyesinde reddi** | `axctl learn start` ikinci kez → "öğrenme modu zaten aktif" |
| `2` | **politika hatası** *veya* **komut satırı hatası** | `policy check` bozuk YAML; `axctl mode bogus`; bilinmeyen komut/seçenek/argüman |
| `4` | **altyapı hatası** — makineyi kontrol et | daemon kapalı, soket yok |
| `5` | yapılandırma / şablon hatası | `axctl template apply yok` |
| `130` | kullanıcı Ctrl+C ile iptal etti | — |

> **`2` kodu iki şeyi birleştirir:** politika bozukluğu da, komut
> yanlış yazılmışı da `2` döner. Ayırt etmek için mesaja bak:
> `axctl: no such option` / `no such command` ise **komut satırı**
> hatasıdır; politika doğrulama mesajı ise **politika** hatasıdır.
> Önemli olan ayrım `1` ↔ `4`: `1` "komutu doğru yazdın, daemon
> reddetti", `4` "sistemde bir sorun var".

---

## 6. Aksiyonlar ve kancalar

| Aksiyon | LSM kancası | Anahtar |
|---|---|---|
| `file.read` | `file_open` | yol |
| `file.write` | `file_open` | yol |
| `file.execute` | `bprm_check_security` | yol |
| `process.exec` | `bprm_check_security` | süreç (yolsuz) |
| `net.connect` | `socket_connect` | `p:PORT` |
| `net.bind` | `socket_bind` | `p:PORT` |

Yol uzunluğu sınırı: **8 bileşene kadar**, bileşen başına 32 bayt.
Daha derin ya da uzun bileşenli yol kabul edilmez — böyle bir kural
eBPF anahtarına sığmaz ve **sessizce hiçbir şeyle eşleşmez**.

Ağ kurallarında `port` zorunludur. `object` ile birlikte verilemez.

---

## 7. Korumalı süreçler

Şu 29 süreç **hiçbir kurala tabi değildir**: `bash`, `sh`, `dash`, `zsh`,
`fish`, `sudo`, `doas`, `su`, `login`, `sshd`, `sshd-session`, `getty`,
`agetty`, `init`, `systemd`, `systemd-logind`, `systemd-journald`,
`systemd-udevd`, `systemd-oomd`, `systemd-userdbd`, `dbus-daemon`,
`dbus-broker`, `NetworkManager`, `wpa_supplicant`, `polkitd`,
`rtkit-daemon`, `gdm3`, `gdm-session-worker`, `kthreadd`.

Bunlar oturum açma ve kurtarma yoludur; engellenmeleri sistemi
kullanılamaz hale getirir. **Bu süreçlere kural yazarsan politika
reddedilir** — çünkü kuralın çalışmayacağı kanıtlanabilir ve
sessizce etkisiz kalmak, güvenlik aracında en tehlikeli sonuçtur.

Kuralı hedef **uygulamaya** yaz: `firefox`, `nginx`, `redis-server`,
`curl`, `postgres`.

---

## 8. Öğrenme modu

Sistemin normalde ne yaptığını gözlemleyip başlangıç politikası
üretir.

```bash
sudo axctl learn start --days 3
# ... normal işlerin ...
axctl learn report
sudo axctl learn stop
```

`learn start` verilen gün sayısı kadar çalışır, sonra kendiliğinden
kapanır. Gözlemler enforcement kancalarından **olay üretildiği anda**
gelir; sen bir şey sorgulamazsan da birikir.

Raporun altındaki öneri bloğu **doğrudan yapıştırılabilir YAML**'dır.
Doğrulamadan önce `axctl policy check` ile denetle.

---

## 9. Audit

Her denetim kararı JSONL olarak kalıcı diske yazılır:

```
/var/log/axlinux/audit-YYYY-MM-DD.jsonl        (bugün)
/var/log/axlinux/audit-YYYY-MM-DD.jsonl.gz     (sıkıştırılmış eski günler)
```

`axlog` ayrı bir servistir. Kayıt zinciri kırılırsa sessizce yutulmaz:
`axctl status` `audit_healthy: false` gösterir.

```bash
axctl logs --effect deny --limit 50      # sadece redler
axctl logs --subject nginx               # bir sürecin tüm eylemleri
axctl logs --action file.read --json     # makine-okunur
```

Filtrelemediğin alan varsa `axctl` seni **uyarır** — "uygulamadığım
filtre" sessizce yutulmaz, çünkü "redleri filtreledim sanıp allow
kayıtlarını görüp doğru çalıştığını düşünmek" tipik bir hatadır.

---

## 10. Modlar

| Mod | Davranış |
|---|---|
| `enforcing` | ihlal engellenir **ve** kaydedilir |
| `permissive` | ihlal kaydedilir, engellenmez (deneme için) |
| `disabled` | hiçbir kısıtlama yok |

### Acil kapatma

Yanlış bir politika yüzünden kilitlenirsen:

```bash
sudo axctl reload --force-empty --mode disabled
```

Bu komut **acil kurtarma yoludur** ve her durumda çalışır: boş politika
geçerli kabul edilir, kural sayısı denetlenmez.

> `sudo axctl mode disabled` da acil çıkıştır. İkisi de aynı anda
> kullanılabilir; acil durumda ikisini sırayla dene.

### Kilitlenme koruması

Politika yazarken yanlışlıkla oturumunu kapatman engellenir:
`bash`, `sh`, `sudo`, `sshd`, `login`, `systemd` ve 23 süreç daha her
zaman korunur (bkz. §7). Buna rağmen **canlı sistemde ilk politikayı
`permissive` modda dene**:

```bash
sudo axctl reload --mode permissive
# gözlemle, sonra enforcing yap
```

---

## 11. Doğrulama

Kurulumdan sonra kendi doğrulamanı çalıştır:

```bash
# hızlı: tek komut
sudo axctl status

# kapsamlı: 10 bölüm, 100 denetim (FİZİKSEL MAKİNEDE ÇALIŞMAZ)
sudo bash tests/deep_verify.sh

# tek bölüm
sudo bash tests/deep_verify.sh -k D
```

`deep_verify.sh` fiziksel makinede kendini reddeder; bu koruma
`AXLINUX_ALLOW_PHYSICAL=1` ile kapatılabilir ama **yapma**.

Kaynak geliştirme:

```bash
make test          # Go + statik + koruma + sessiz hata + Python (164 test)
make verify        # eBPF'yi derle ve denetle
make clean
```

---

## 12. Sınırlar (dürüst liste)

Bunları bilerek kabul etmen gerekir:

- **`net.accept` desteklenmiyor.** LSM'de karşılığı olan bir
  `socket_accept` kancası yok; bu yüzden kural yazmak da anlamsız
  olurdu. Gelen bağlantıları denetlemek `socket_bind` + uygulama
  katmanıyla yapılır.
- **Yol derinliği 8 bileşen, bileşen uzunluğu 31 bayt.** Daha derin
  yollar kural olarak yazılamaz (sessizce çalışmaz — reddedilir).
- **`subject` süreç adıdır, kullanıcı değil.** `curl` tüm
  kullanıcılar için aynıdır.
- **Kök dosya sistemi için her şey geçerlidir.** Politika, çalıştıran
  kullanıcıyı değil süreci konuşur.
- **Pardus'ta tam masaüstü kurulmadı.** Doğrulama sistemi Pardus'un
  resmî arşivinden (`bilgemdepo.pardus.org.tr`, imzalı) ve
  `base-files 13.8+pardus25.2.1` ile kuruldu; `pardus-backgrounds`,
  `pardus-bilge-grub-theme`, `desktop-base` kurulu. AXlinux'in
  çalışması için gereken çekirdek, kütüphaneler ve araçlar tamdır;
  XFCE/GNOME masaüstünün kendisi kurulmadı çünkü AXlinux masaüstü
  uygulaması değildir.
- **`lsm=bpf` çekirdek parametresidir.** Farklı bir önyükleme
  parametresi (GRUB'da `lsm=...,bpf`) gerekiyorsa ayrıca ayarla.

---

## 13. Kaldırma

```bash
sudo systemctl disable --now axdaemon axlog
sudo make uninstall
```

Kalanlar: `~/.axlinux/policy.yaml`, `/etc/axlinux/`,
`/var/log/axlinux/`, `/usr/lib/tmpfiles.d/axlinux.conf`.
Politikanı saklamak istersen `policy.yaml`'ı önce yedekle.

---

## 14. Nasıl çalışır (kısa)

```
  axctl (Python)          axdaemon (Go)                çekirdek
       │                        │                          │
       │  JSON-RPC soket       │                          │
       ├───────────────────────►│                          │
       │  derlenmiş politika   │  eBPF map'lerine yaz     │
       │                        ├─────────────────────────►│
       │                        │                          │ LSM
       │  JSON-RPC soket       │  audit olayı             │ kancaları
       ├───────────────────────►│  ◄───────────────────────┤ tetiklenir
       │                        │                          │
 axlog (Go) ◄───────────────────┤  JSONL diske             │
```

- `axctl` politika YAML'ını okur, doğrular ve **iç forma** derler.
- `axdaemon` bu formu eBPF map'lerine yazar; kancalar anında etkin olur.
- Bir kanca tetiklendiğinde karar audit kuyruğuna düşer.
- `axlog` kuyruğu boşaltır ve kalıcı JSONL dosyasına yazar.
- Mod (`enforcing`/`permissive`/`disabled`) ayrı bir map'te tutulur,
  anında değiştirilebilir.

Ayrıntılı tasarım: `docs/architecture.md`,
`docs/policy-language.md`, `docs/cli-reference.md`.

---

## 15. Yedeklenmiş sürüm

Bu belgenin eşlik ettiği kaynak arşivi:

```
/home/mami/axlinux-kaynak-20261001-1715.tar.gz
```

sha256 doğrulaması ve geri yükleme testi yapılmıştır (140 dosya;
geri yüklendiğinde 164 test geçiyor).

---

## Canlı sisteme alırken

Sürüm 1.0.0; üç dağıtımda uçtan uca doğrulandı. Yine de ilk kez
kuruyorsan sırayla git:

1. `permissive` modda başla ve bir süre gözlemle:
   `sudo axctl reload --mode permissive`
2. `/var/log/axlinux/` kayıtlarının gerçekten dolduğunu doğrula
   (`axctl logs`). Kayıt yoksa sistem düşündüğün gibi denetlemiyor.
3. **Acil kurtarma komutunu bir kez test et:**
   `sudo axctl reload --force-empty --mode disabled`
   Kullanmadan önce çalıştığını bilmen gerekir.
4. Modu `enforcing` yap ve ilk gün audit kayıtlarını oku.

Politika hatası ile karşılaşırsan önce:

```bash
sudo axctl reload --force-empty --mode disabled   # sistemi serbest bırak
axctl policy check                                 # hatayı bul
```

`axctl policy check` çıktısı kural kimliğini ve sebebini söyler; bu
bilgiyi `CHANGELOG.md` veya sorun olarak paylaşmak istersen
kullanılabilir bilgidir.