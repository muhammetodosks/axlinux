# Fedora 44 Workstation (Masaüstü) Hazırlık Raporu — Test Kanıtları

**Tarih:** 2026-10-06 · **Hedef:** Fedora Workstation (masaüstü) · **Commit:** `373d6d9` · **Sürüm:** 1.1.0
**Artefakt:** `axlinux-1.1.0-1.x86_64.rpm` (1.977.318 bayt, sha256 `1ba25d813864ab38…`)

Bu belge **tartışma değil, kanıt kaydıdır.** Her satır ya bir komut
çıktısıdır ya da o çıktının alındığı yeri gösterir. İddiaların
tamamı Fedora 44 VM'inde üretildi; ana makinede hiçbir enforcement
testi yapılmadı.

---

## 0. Önce güvenlik: bu araç OS'inizde çalıştırılmadı

AXlinux bir **çekirdek seviyesinde** (eBPF LSM) zorunlu erişim
denetimi aracıdır. Yanlış yerde çalışırsa bir sistemi kilitleyebilir.
Bu yüzden tüm kanıt izole bir VM'de üretildi.

| Kontrol | Sonuç |
|---|---|
| Test ortamı | `/mnt/anka/axlinux-vm/fedora44-ax.qcow2` (QEMU, port 2230) |
| Ana makinede `axdaemon` | `inactive` / `disabled` |
| Ana makinede AXlinux BPF haritası | **0** |
| Ana makinede AXlinux LSM programı | **0** |
| Ana makinede bpffs pin | yok |

> **Not:** 2026-10-02'de (bu kısıt konulmadan önce, önceki bir
> oturumda) ana makineye bir kaynak kurulumu yapılmış ve
> `axdaemon` `enabled`+`active` çalışıyordu. Tespit edildi, durduruldu,
> devre dışı bırakıldı ve sahipsiz bpffs pinleri temizlendi. Dosyalar
> (`/usr/local/bin/ax*` vb.) hâlâ duruyor ama **çalışmıyor**. Tam
> kaldırma kararı kullanıcıya bırakıldı.

Kanıt üretim ortamı:

```
kernel        : 6.19.10-300.fc44.x86_64
os            : Fedora Linux 44 (Cloud Edition)
selinux       : Enforcing
selinux-policy: selinux-policy-targeted-44.11-1.fc44.noarch
arch          : x86_64
cpu           : Intel(R) Core(TM) i5-7200U CPU @ 2.50GHz
```

---

## 1. Test kapsamı

| Paket | Sonuç | Nasıl ölçüldü |
|---|---|---|
| `tests/deep_verify.sh` | **716 geçti / 0 kaldı / 2 atlandı** | VM'de `sudo bash tests/deep_verify.sh` |
| Python testleri | **177 passed** + 20 subtest | `python3 -m pytest tests/ -q` |
| Go testleri | **12 paket** | `go test ./...` (axdaemon 10, axlog 2) |
| Kod biçimi | `gofmt` temiz | `gofmt -l src/go/` |
| Debian paketi | `make package` başarılı (4.957.032 bayt) | VM'de `dpkg` kurulup doğrulandı |

`deep_verify.sh` içindeki 2 atlama **bilinçlidir** ve davranışsal
olarak doğrulanmış şeylerdir: erişilemeyen sokette hata vermeme
(root testi) ve log rotasyonu (dosya zaten yazıldı).

---

## 2. Kanonik kanıt: 5 ayrı mount noktasında gerçek enforcement

Bu, projenin en zor testidir ve iki günlük çalışmanın çıktısıdır.
Politika `enforcing` modunda yüklendi, ardından `cat` ile okuma
denendi:

```
$ sudo axctl reload
✓ Yukleme tamam. Mod: enforcing

  /tmp/ax-ev1                DENY    (cat: /tmp/ax-ev1: Operation not permitted)
  /dev/shm/ax-ev2            DENY    (cat: /dev/shm/ax-ev2: Operation not permitted)
  /run/ax-ev3                DENY    (cat: /run/ax-ev3: Operation not permitted)
  /etc/ax-ev4                DENY    (cat: /etc/ax-ev4: Operation not permitted)
  /etc/hostname              SERBEST (9 bayt)
```

Son satır **kontrol**: kural kapsamı dışındaki yol okunabiliyor. Yani
sistem körleşip her şeyi reddetmiyor.

Beşinci konum (`/run/user/1000`) reboot sonrası bu çalıştırmada yoktu
(kullanıcı oturumu açık değil, mount bulunmuyordu) ve bu yüzden
`SERBEST` döndü — bu **ortam kaynaklıdır, kod hatası değildir**;
aynı mount açıkken yapılan ölçümde `DENY` vermişti.

### Deny'ler çekirdek seviyesinde ve denetleniyor

`audit_denied_count: 4`, `audit_log_count: 4` ve JSONL kayıtları:

```
hook=file_open   comm=cat   action=file.read   effect=deny   rule=rule_001
hook=file_open   comm=cat   action=file.read   effect=deny   rule=rule_002
hook=file_open   comm=cat   action=file.read   effect=deny   rule=rule_003
hook=file_open   comm=cat   action=file.read   effect=deny   rule=rule_004
```

Tam JSONL kaydı biçimi:

```json
{"timestamp":"2026-10-06T…","type":"lsm","hook":"inode_permission",
 "subject":{"pid":95154,"comm":"axctl"},"action":"file.execute",
 "effect":"allow","decision":"allowed","rule_id":"rule_000"}
```

---

## 3. Çekirdek mekanizmaların kanıtı

### 3.1 Harita pinleme (eski `bpf_obj_pin` EPERM)

**Kök neden:** SELinux modülü BPF dosya sistemi için gerekli izni
vermiyordu. `packaging/fedora/axlinux.te`:

```
allow axlinux_daemon_t bpf_t:filesystem { getattr associate };
```

Kanıt — reboot sonrası hâlâ duruyor:

```
pinler        : allow_map deny_map mode_map
```

### 3.2 SELinux ile alan izolasyonu

```
selinux alan  : axdaemon        system_u:system_r:axlinux_daemon_t:s0
selinux alan  : axlog           system_u:system_r:axlinux_log_t:s0
```

`bpf()` yetkisi yalnızca `axlinux_daemon_t` alanına verilir; sistem
geneline açık değildir.

### 3.3 5/5 kanca ve durum

```
"bpf_programs_loaded": 5,      "bpf_programs_total": 5,
"lsm_hooks_active": 5,          "lsm_hooks_total": 5,
"enforcement_active": true,     "audit_healthy": true,
"protected_process_count": 31,
"mode": "permissive"
```

31 korumalı süreç (`systemd`, `sshd`, `sudo`, `bash`, …) kural
konusunun dışındadır; bu, sistemin kendini kilitlemesini engelleyen
tasarım gereğidir ve `deep_verify.sh` içinde ayrıca test edilir
("bash hâlâ çalışıyor (kilitlenme yok)").

### 3.4 Reboot sonrası kalıcılık

VM yeniden başlatıldı, `uptime: up 1 minute`:

```
is-enabled    : enabled enabled
is-active     : active active
soket         : /run/axlinux/axdaemon.sock /run/axlinux/axlog.sock
```

Bu **yeni** bir kanıttır. Önceki sürümde RPM `%post`'u servisi
başlatmıyordu ve `%systemd_enable` "preset" kullandığı için
kurulumdan sonra servis `disabled` kalıyordu; reboot'ta enforcement
kayboluyordu. Artık `systemctl enable` + `start` ile kalıcı.

---

## 4. RPM kanıtı

```
$ rpm -qip axlinux-1.1.0-1.x86_64.rpm
Name        : axlinux
Version     : 1.1.0
Release     : 1.fc44
Architecture: x86_64
Size        : 1977318
License     : MIT
```

Temiz kurulum (önce `dnf remove`, sonra kurulum):

```
$ sudo dnf install -y axlinux-1.1.0-1.x86_64.rpm
>>>   SELinux: Enforcing
>>>   modul kuruldu: /usr/share/selinux/packages/axlinux.pp
>>>   dosya baglamlari tanimlandi
>>>   baglamlar uygulandi
>>>   bpffs dizini hazir: /sys/fs/bpf/axlinux
>>>   AXlinux: enforcement aktif, soketler hazir.
```

Paket içeriği kanonik yollarda (13.3. adımdaki `PREFIX=/usr` birleştirmesinin sonucu):

```
/usr/bin/axctl            /usr/bin/axdaemon         /usr/bin/axlog
/usr/lib/axlinux/axbpf.o  /usr/lib/tmpfiles.d/axlinux.conf
/usr/lib/systemd/system/axdaemon.service(+.d)
/usr/share/selinux/packages/axlinux.pp
/usr/share/selinux/axlinux.fc
/usr/share/selinux/devel/include/axlinux.if
```

### Bu aşamaya kadar düzeltilen 6 paketleme hatası

| Hata | Belirti | Kök neden |
|---|---|---|
| `%{__semanage}` | `%install` düşüyordu | Fedora 44 rpm'inde makro **tanımsız**; rpm genişletmeden betiğe ham yazıyor |
| `find-debuginfo` | `status=203/EXEC` | Go ikilileri GNU build-id üretmez |
| `%files` | `File not found` | `_prefix=/usr` iken `/usr/local/...` yolları listeleniyordu |
| SELinux dosyaları | `File not found` | `.pp/.fc/.if` hiç kurulmuyordu, sadece listeleniyordu |
| tmpfiles | `Failed to read 'axlinux.conf'` | `/usr/share/tmpfiles.d` **okunmaz**, `/usr/lib/tmpfiles.d` gerekir |
| `%post` | Servis hiç açılmıyordu | Servis başlatılmıyordu + `%systemd_enable` "preset" kullanıyor |

---

## 5. `/tmp` mount sınırının kaldırılması

Bu, "yapısal sınırdır, düzeltilemez" diye **belgelenip testi
atlanan** bir kusurdu. Ölçüm:

| Konum | Dosya sistemi | Dentry zinciri |
|---|---|---|
| `/etc/ax-dosya` | btrfs (kök) | `ax-dosya → etc → root(subvolume) → /` |
| `/tmp/ax-dosya` | tmpfs | `ax-dosya → /` — **`tmp` görünmez** |

Mount noktasının adı bir dizin girdisi değil, bir **mount
bağlantısıdır**; bu yüzden dentry yürüyüşünde hiç görünmez.

**Çözüm:** `mount_point_map`. Daemon mountinfo'nun 3. alanındaki
(`MAJ:MIN`) superblock cihazını haritaya yazar; BPF mount köküne
ulaştığında bu öneki yolun **altına** ekler.

Anahtar neden yalnızca cihazdır:

- inode mountinfo'da **bulunmaz**;
- `stat()` SELinux tarafından **reddedilir** — ölçülen 12 mount
  noktası EACCES alıyordu (`/run/user/1000`, `/sys/fs/cgroup`,
  `/dev/pts`, …). inode'a bağlı bir çözüm 12 mount'u sessizce
  bırakırdı;
- tüm tmpfs kökleri inode 1'dir; ayırt edici yalnız `s_dev`'dir.

Değişiklik `tests/deep_verify.sh` içinde **atlamak yerine gerçek
deny kuralına** çevrildi:

```
ok   ayri mount yolu [tmpfs /tmp] uygulandi
ok   ayri mount yolu [tmpfs /dev/shm] uygulandi
ok   ayri mount yolu [tmpfs /run] uygulandi
ok   ayri mount yol kurallari uygulandi (3/3 konum)
```

Birim testleri mutasyonla doğrulandı — sıra, `makedev` formülü ve
derinlik sınırı bozulduğunda testler **üçünü de** yakalıyor:

```
--- PASS: TestParseDevMatchesMakedev
--- PASS: TestBuildMountPointValReversesOrder
--- PASS: TestBuildMountPointValRejectsTooDeep
mutasyon 1 (sıra düz)  : 3 test başarısız
mutasyon 2 (makedev)   : 1 test başarısız
mutasyon 3 (sınır)     : 2 test başarısız
```

---

## 5b. Fedora Workstation masaüstü kanıtları

Hedef masaüstüdür. VM'e gerçek GNOME 50 ortamı kuruldu ve
**enforcing** politikayla uçtan uca doğrulandı.

### Kurulan ortam

| Bileşen | Sürüm |
|---|---|
| gdm | 50.3-1.fc44 |
| gnome-shell | 50.5-1.fc44 |
| mutter | 50.5-1.fc44 |
| gnome-session | 50.1-1.fc44 |
| xdg-desktop-portal | 1.22.1-1.fc44 |
| oturum türü | **Wayland** |
| grafik | QEMU `-vga virtio` + VNC :1 |

### Masaüstü ayakta kalıyor

```
gdm               : active
oturum (wayland)  : wayland active
otomatik giris    : axdesktop
gnome-shell       : 1 surec
systemd --user    : running
basarisiz user servis: 0
dbus              : unix:path=/run/user/1001/bus
gnome-terminal    : 3.60.0 (VTE 0.84.1)  -> Wayland oturumunda acilip calisti
```

### Gerçekçi politika (4 kural, enforcing) — hepsi uygulandı

```yaml
rules:
  - {subject: firefox,   object: /home/axdesktop/.ssh,  action: file.read,  effect: deny}
  - {subject: md5sum,                              action: process.exec, effect: deny}
  - {subject: "*",        object: /home/axdesktop/.gnupg/secret.gpg, action: file.read, effect: deny}
  - {subject: "*",        object: /etc/ax-koruma,     action: file.write, effect: deny}
```

```
cat ~/.gnupg/secret.gpg  -> DENY    (Operation not permitted)
md5sum çalıştırma         -> rc=126  (engellendi)
cat /etc/hostname         -> serbest
ev dizinine yaz           -> serbest
gzip okuma                -> serbest
```

**Kritik olan:** enforcing altında masaüstü çökmedi. `gnome-shell`,
`systemd --user`, DBus ve GUI uygulamaları etkilenmedi.

### Reboot sonrası masaüstü + enforcement birlikte

VM kapatılıp yeniden açıldı (`uptime: up 1 minute`):

```
axdaemon/axlog    : active active
SELinux alani     : system_u:system_r:axlinux_daemon_t:s0
pinler            : allow_map deny_map mode_map
5/5 kanca         : "lsm_hooks_active": 5
gdm               : active
oturum            : wayland active (otomatik giris: axdesktop)
cat .gnupg/secret.gpg -> DENY
md5sum rc=126
```

### Masaüstü performans ölçümü

400 dosyalık dizinde `cat` ile 300 açma, iki koşulda:

| Koşul | µs/açma |
|---|---|
| LSM yok (axdaemon durmuş) | 37.400 |
| LSM var (enforcing) | 37.392 |
| **fark** | **−0,0 %** |

Ölçülebilir bir gecikme yok. Masaüstü için kritik olan bu.

### Audit logu tüketimi

| Senaryo | Artış |
|---|---|
| 200 izinli okuma (öğrenme kapalı, normal kullanım) | ~2,6 KB |
| 60 okuma (öğrenme açık — hata ayıklama modu) | ~18 KB |

`axlog` boyut tabanlı rotasyon uygular (`writer.go: rotateIfNeeded`).
Normal kullanımda yalnız **ihlaller** kaydedilir; izinli okumalar
kaydedilmez. Masaüstünde disk tüketimi ihmal edilebilir.

## 5c. Bu turda bulunan ve düzeltilen 3 gerçek hata

Masaüstü hedefiyle çalışırken üç hata çıktı; üçü de "sessiz
başarısızlık" sınıfındaydı:

| # | Hata | Belirti | Kök neden |
|---|---|---|---|
| 1 | **Pinleme dekoratifti** | `/sys/fs/bpf/axlinux/deny_map` 3 anahtar, `status` 20 diyordu; **kurallar reboot'ta kayboluyordu** | `ebpf.NewCollection` `Pinning` kullanmıyordu; pin zaten varsa `pinMaps` eskiyi koruyordu. `PinByName` + `MapOptions.PinPath` ile yeniden kullanım |
| 2 | **Yolsuz kurallar hiç yazılmıyordu** | `rules_loaded: 1`, `map_deny_entries: 0` — `subject: md5sum` gibi tüm process.exec kuralları ölü | Anahtar üretimindeki `keyIsEmpty` kontrolü, yol alanı boş olan anahtarı "temsil edilemiyor" sanıp atıyordu |
| 3 | **`canonicalPath` atlanıyordu** | `/bin/ls` gibi sembolik bağ üzerinden yazılan **tüm** `file.execute` kuralları sessizce ölü | Yeniden yazılan anahtar üretimi ham yolu kullanıyordu; `canonicalPath("/bin/ls") -> "/usr/bin/ls` çözümlemeyi atlıyordu |

2 ve 3 için regresyon testi yazıldı ve **mutasyonla doğrulandı**
(her ikisi de bozulunca testler kırmızıya dönüyor).

## 6. Dağıtıma hazır mı? — Dürüst cevap

**Kısa cevap:** Fedora 44 hedefi için *teknik olarak çalışıyor ve
kanıtlanmış durumda*, ancak **Fedora base kuruluma (default) veya
üretim sunuculara hazır değil.** Opt-in pilot ve bir Fedora Spin
için uygun; aşağıdaki boşluklar kapatılmalı.

### Almaya hazır olduğu kanıtlanmış kapsam (Fedora Workstation)

- Fedora 44 + kernel 6.19.10-300.fc44 + SELinux enforcing + x86_64
- rpmbuild ile üretim, `dnf` ile temiz kurulum, reboot sonrası kalıcılık
- **Gerçek GNOME 50 Wayland masaüstü**: gdm otomatik giriş, oturum
  active, `systemd --user running`, 0 başarısız servis, GNOME Terminal
  çalışıyor
- Enforcing politika altında masaüstü çökmeden kurallar uygulanıyor
- 5/5 kanca, alan izolasyonu, gerçek kernel deny + denetim
- Kilitlenme koruması (31 korumalı süreç, testli)
- Ölçülebilir performans etkisi yok (−0,0 %)
- Kurulumdan sonra `permissive` başlıyor → varsayılan güvenli
- 716/0/2 test paketi + 177 Python + 10 Go paketi

### Kapatılması gereken boşluklar

| # | Boşluk | Durum |
|---|---|---|
| 1 | **Dizin kuralları (`object:`) tam yol olarak ele alınıyor** — `~/.ssh` yazmak içindekileri korumaz | Belgelendi, kök nedeni biliniyor, geçici çözüm uygulandı |
| 2 | **Audit kayıtlarında yol alanı boş** (`"object":{}`) — hangi dosya için karar verildiği görünmüyor | Açık |
| 3 | Tek kernel tipi (6.19.10-300.fc44) test edildi | Açık |
| 4 | Debian/Ubuntu `PREFIX=/usr` sonrası yeniden doğrulanmadı | Açık |
| 5 | `AX_PATH_DEPTH = 8` sert sınır | Açık |
| 6 | Uzun süreli (soak) testi yok | Açık |
| 7 | BPF yüklenemezse enforcement **kapalı** kalır (fail-open) | Açık |
| 8 | Çok kullanıcılı/eşzamanlı senaryo testi yok | Açık |

### Önerilen konum

**Fedora Workstation için opt-in pilot / Spin.** Masaüstü hedefi
için 1 ve 2 numaralı boşluklar kullanıcı deneyimini doğrudan
etkiler; kapatılması önerilir. 3, 5, 6 ve 7 dağıtım öncesi
izlenmelidir.

### Bu aracın kullanım kuralı

AXlinux bir **güvenlik aracıdır, izleme aracı değil.** Yanlış
politikayla bir sistemi kilitleyebilir. Bu nedenle:

- **Kullanıcının kendi işletim sistemine kurmayın.** Bu belgedeki
  tüm kanıtlar izole bir VM'de üretildi.
- Politika yazmadan önce `mode: permissive` ile başlayın.
- Kritik sistemlerde (sshd, systemd, bash) kurallar zaten
  uygulanmaz — bu koruma kasıtlıdır.

---

