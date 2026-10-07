# Fedora 44 Workstation (Masaüstü) Hazırlık Raporu — Test Kanıtları

**Sürüm:** 1.2.0 · **Tarih:** 2026-10-06 · **Hedef:** Fedora Workstation masaüstü

Bu belge AXlinux'in Fedora 44 masaüstünde çalıştığını **ölçümlerle** gösterir.
Her sayı bu VM'de alınmıştır; tahmin veya hedef değer yoktur.

> **Kapsam dışı:** Üretim sunucusu değerlendirmesi. Bu belge masaüstü
> senaryosunu kapsar. AXlinux bir MAC'tır (zorunlu erişim denetimi);
> sunucu iş yükü için ayrı bir değerlendirme gerekir.

---

## 0. Önce güvenlik: bu araç ana makinenizde çalıştırılmadı

Kısıt: **`/dev/sdb1` üzerinde AXlinux çalıştırılmayacak, enforcement
testi yapılmayacak. Her şey `/mnt/anka` VM'inde.**

| Konum | Durum | Kanıt |
|---|---|---|
| Ana makine `/dev/sdb1` | **Dokunulmadı** | `axdaemon inactive`, `axlog inactive`, 0 BPF haritası, 0 LSM programı |
| Ana makine `/sys/fs/bpf/axlinux` | Yok | dizin mevcut değil |
| Test ortamı | `/mnt/anka/axlinux-vm/fedora44-ax.qcow2` | SSH `ax@127.0.0.1:2230` |

VM ortamı: Fedora 44 Cloud, kernel `6.19.10-300.fc44.x86_64`,
GNOME 50 (gdm 50.3, gnome-shell 50.5, mutter 50.5), Wayland,
SELinux `Enforcing`.

---

## 1. Test kapsamı

| Bileşen | Yöntem |
|---|---|
| Fedora 44 çekirdek | RPM ile temiz kurulum, sonra `deep_verify.sh` |
| GNOME masaüstü | Gerçek gdm + Wayland oturumu, otomatik giriş |
| Politika | Gerçekçi masaüstü senaryosu, `enforcing` |
| Yeniden başlatma | `systemctl reboot`, sonra otomatik giriş doğrulaması |
| Performans | 3 durumlu dosya açma gecikmesi + 50.000 açma toplam iş yükü |
| Disk | 325 işlem üzerinde audit bayt/işlem ölçümü |

---

## 2. Masaüstü kanıtı (Workstation senaryosu)

### 2.1 Gerçek GNOME oturumu

| Kanıt | Değer |
|---|---|
| `gdm` | `active` / `enabled` |
| Oturum tipi | `wayland` |
| `gnome-shell` | çalışıyor, 2 Wayland bağlantısı |
| `systemd --user` | `running` |
| Başarısız user servisi | 0 |
| Otomatik giriş | `axdesktop` (UID 1001), `seat0`, `tty2` |

### 2.2 Gerçek GUI uygulaması (enforcement açıkken)

`gedit /etc/hostname` masaüstü oturumunda açıldı:

- PID 2298, **Wayland bağlantısı: 1** (gerçek GUI istemcisi)
- pencere içeriği: `fedora-ax`, `Line 1, Col 1`, `Plain Text`

Görsel kanıt QEMU monitöründen (`screendump`) alındı:

- **Yeniden başlatma öncesi:** tam GNOME masaüstü — üst çubuk
  (`Oct 6 3:42 PM`), açık **gedit penceresi** (`fedora-ax` içeriği,
  `Plain Text`, `Tab Width: 8`), uygulama dock'u. Enforcement
  açıkken, arka planda `Low Disk Space` uyarısı görünüyor.
- **Yeniden başlatma sonrası:** otomatik giriş çalışmış ve oturum
  canlı, ancak ekran **kilitli** görünüyor. Bu bir hata değil:
  sanal makinede fiziksel konsol girişi olmadığı için GNOME boşta
  kalınca ekranı kilitliyor ve `screendump` kilit ekranını
  yakalıyor. Ekranı açmak için QEMU `sendkey` denendi, Wayland
  oturumunda sentetik tuşlar kilidi acmadı. Oturumun canlı olduğu
  programatik olarak doğrulandı (§2.5): oturum `active`, oturum tipi
  `wayland`, `gnome-shell` ayakta ve gedit Wayland istemcisi olarak
  çalışıyor.

`xclock` denendi ve **başarısız oldu**: `Can't open display`.
Bu bir ürün hatası değildir — xclock bir X11 uygulamasıdır ve
oturum Wayland'dır. X11 istemcileri Wayland oturumunda çalışmaz.

### 2.3 Paket yönetimi (dnf)

Enforcement **açıkken** gerçek paket kurulumu yapıldı:

```
sudo dnf install -y gedit xclock     →  13 paket, 36 saniye, Complete!
```

Bu tek başına iki şeyi kanıtlar: `dnf` enforcement altında
çalışıyor ve masaüstü paket yönetimi bozulmuyor.

Not: VM'de **hiç GUI uygulaması kurulu değildi**. "Workstation"
diyebilmek için gerçek uygulamalar gerekiyordu; `gedit` bu
eksikliği kapattı.

### 2.4 Gerçekçi enforcing politika (4 kural)

Politika **sistem geneli** `/etc/axlinux/policies.d/50-workstation.yaml`
içinde; açılışta `axdaemon` tarafından kendisi yüklenir.

| Kural | Denenen işlem | Sonuç |
|---|---|---|
| `subject: [firefox]` + `.ssh/id_rsa` okuma | tarayıcıdan anahtar okuma | `Operation not permitted` |
| `subject: [md5sum]` + `process.exec` | `md5sum /etc/hostname` | `Operation not permitted` |
| `subject: ["*"]` + `.gnupg/secret.gpg` okuma | `cat` ile okuma | `Operation not permitted` |
| `subject: ["*"]` + `/etc/ax-koruma` yazma | `>>` ile yazma | `Permission denied` |
| *(kural dışı)* | `cat /etc/hostname` | **serbest** (`fedora-ax`) |
| *(kural dışı)* | ev dizinine dosya yazma | **serbest** |

Masaüstü bu kurallar sırasında **çökmedi**: gedit açık kaldı,
oturum aktif kaldı.

### 2.5 Yeniden başlatma sonrası

`systemctl reboot` sonrası:

| Kanıt | Değer |
|---|---|
| `uptime` | ~1 dakika (yeni açılış) |
| `gdm` / `axdaemon` / `axlog` | `active` / `enabled` (üçü de) |
| Otomatik giriş | `axdesktop` oturumu `active` |
| Oturum tipi | `wayland` |
| **Sistem politikası** | `sistem politikasi uygulandi ... rules=4 mode=enforcing` |
| LSM kancaları | 5/5 |
| Enforcement | `enforcing`, 4 kural, 5 deny girdisi |
| `audit_healthy` | `true` |
| GUI uygulaması | gedit yeniden açıldı (PID 19957), Wayland bağlantısı: 1 |
| `dnf` | `dnf5 version 5.4.1.0` |
| Sistem politikası yüklemesi | açılıştan bu yana 28 kez otomatik |

Kritik nokta: **politika yeniden başlatmadan sonra kendiliğinden
yüklendi**. Bu, eski davranışta olmuyordu (bkz. §6.1).

---

## 3. Performans: dosya açma gecikmesi (hedef 5)

Üç durumlu ölçüm, aynı iş yükü (`/etc/hostname`, `/etc/hosts`,
`/etc/passwd`, `/etc/group`, `/etc/os-release`), dosya başına 80 açma,
`time.perf_counter_ns()`.

| Durum | Ortalama | Medyan |
|---|---|---|
| **[1] LSM kancası yok** (`--no-enforce`, 0/5) | **11.3 µs** | 11.3 µs |
| **[2] Kanca bağlı, `mode=disabled`** (5/5) | **17.1 µs** | 16.8 µs |
| **[3] Kanca bağlı, `mode=enforcing`** (5/5) | **17.7 µs** | 16.9 µs |

### Ne ölçtüğümüzü ayırmak önemli

- **Kanca takma maliyeti:** 17.1 − 11.3 = **+5.8 µs** (µs'nin %51'i)
- **Politika sorgusu maliyeti:** 17.7 − 17.1 = **+0.6 µs** (µs'nin %3.5'i)

Yani maliyetin **büyük kısmı politika mantığı değil, LSM kancasının
kendisinin bağlanmasıdır**. Politika sorgusu ihmal edilebilir.

### Toplam iş yükü (50.000 dosya açma)

Ağır bir tarayıcı açılışını temsil eden sabit iş yükü:

| Mod | Toplam süre | µs/açma | açma/sn |
|---|---|---|---|
| `disabled` | 0.254 s → 0.250 s | ~5.0 | ~198.000 |
| `enforcing` | 0.441 s → 0.438 s | ~8.8 | ~113.700 |

**Masaüstü açısından yorum:** 50.000 dosya açma 0.44 saniye yerine
0.25 saniye sürüyor — **fark 0.19 saniye**. Bu, tarayıcı açılışı
gibi gerçek bir iş yükünde algılanamaz. Elde edilen geçilir
(113.000 açma/sn) bir masaüstünün asla ulaşamayacağı bir hızdır.

---

## 4. Audit logunun disk tüketimi (hedef 5)

Temiz başlangıçtan (`/var/log/axlinux` boşaltıldı), 325 işlem:

| İşlem | Adet | Üretilen | Bayt/işlem |
|---|---|---|---|
| **İzinli** dosya okuma | 200 | **0 bayt** | kayıt yok |
| **Engellenen** okuma | 50 | 12.585 bayt | 251,7 |
| Engellenen çalıştırma | 25 | 6.373 bayt | 254,9 |
| **İzinli** çalıştırma | 50 | **0 bayt** | kayıt yok |

### Ana bulgu

**Audit maliyeti toplam etkinliğe değil, ihlal sayısına bağlı.**
İzinli işlemler `enforcing` modunda hiç kayıt üretmiyor. Doğru
yapılandırılmış bir masaüstünde disk tüketimi kabaca:

> **bayt/gün ≈ 250 × günlük ihlal sayısı**

| Günlük ihlal | Günlük | 14 günde (ham) |
|---|---|---|
| 10 | 2,5 KB | 35 KB |
| 100 | 25 KB | 350 KB |
| 1.000 | 250 KB | 3,5 MB |
| 10.000 | 2,5 MB | 35 MB |

10.000 ihlal/gün senaryosunda bile 10 MB'lık segment sınırı
günlük değil ~4 günde bir devreye girer ve `gzip` ile sıkıştırılmış
saklama ile daha da düşer.

**Uyarı:** Ölçüm `learning` (öğrenme) modu kapalıyken alındı.
Öğrenme modu açıkken *her* işlem kaydedilir; 43.641 kayıtlık
10,8 MB dosya bu modun üretimidir.

### Disk baskısı (masaüstü gözlemi)

Ekran görüntüsü alınırken GNOME şu uyarıyı gösterdi:

> **Low Disk Space on "Filesystem root" — only 855.7 MB remaining**

Kök dosya sistemi %96 doluydu. Dağılım:

| Yol | Boyut | Not |
|---|---|---|
| `/var/log/journal` | 198 MB | **sınır ayarı yok** (varsayılan: diskin %10'u ≈ 2 GB) |
| `/var/cache/libdnf5` | 104 MB | dnf önbelleği |
| `/var/log/axlinux` | 11 MB | AXlinux audit (artık sınırlı) |
| `/home/ax/axlinux/.android` | **17 GB** | Android emülatör kalıntısı — AXlinux ile ilgisiz, silindi |

Temizlik sonrası: **2,1 GB boş (%90)**. Uyarı bildirimi ekranda
kaldı çünkü GNOME eşiğinin altındaki boş alanda; kalıcı çözüm disk
genişletmesi veya `journald` sınırı ayarlamaktır (aşağıda).

Not: `/var/log/journal` sınırı AXlinux'in sorunu değildir, ancak
masaüstü hedefinde gerçek bir disk dolma riskidir ve raporlanmalıdır.

---

## 5. RPM kanıtı

| Özellik | Değer |
|---|---|
| Sürüm | `axlinux-1.1.0-1.fc44.x86_64` |
| Boyut | 2.189.772 bayt |
| sha256 | `8ba3aae64fb2e6f36f9a5ac663179c87…` |
| Kurulum | `dnf install -y <rpm>` → `Complete!` |
| `axdaemon` / `axlog` | `active` / `enabled` |
| SELinux modülü | `axlinux` kurulu |
| `axlog` bildirilen sürüm | **`1.1.0`** (RPM ile eşleşiyor) |
| LSM kancaları | 5/5 |
| BPF pin | `allow_map deny_map mode_map` |
| Sistem politikası | `00-sample-workstation.yaml,50-workstation.yaml` → 4 kural, enforcing |
| SELinux alanı | `system_u:system_r:axlinux_daemon_t:s0` |

**Temiz kurulum** denendi: paket önce `dnf remove` ile kaldırıldı
(`axdaemon` yok oldu), sonra yeniden kuruldu. Yukarıdaki tablo
bu temiz kurulumdan sonradır.

### Paketleme doğrulaması

| Kontrol | Sonuç |
|---|---|
| `gofmt` | temiz |
| `go build` (2 modül) | temiz |
| `go vet` | temiz |
| Go testleri | 13 paket, hepsi geçti |
| Python testleri | 179 geçti + 20 subtest |
| `deep_verify.sh` | **716 geçti / 0 kaldı / 2 atlandı** |
| `.desktop`, `.service`, SELinux betiği | `bash -n` temiz |

---

## 6. Bu turda bulunan ve düzeltilen gerçek hatalar

### 6.1 Politika yeniden başlatmadan sonra kayboluyordu *(en ciddisi)*

Politika **yalnızca** `axctl` API'siyle, çalışan kullanıcının
`~/.axlinux/policy.yaml` dosyasından yükleniyordu. Açılışta hiçbir
şey okunmuyordu; BPF haritaları boş başlıyordu.

Sonuç: reboot sonrası **tüm kurallar kayboluyor**, sistem sessizce
"hiçbir şey kısıtlanmıyor" durumuna dönüyordu. Operator politika
yüklediğini ve `enforcing` gördüğünü sanar, ama hiçbir şey
engellenmiyordu.

**Düzeltme:** `/etc/axlinux/policies.d/*.yaml` dizini açılışta
okunuyor (`.yaml`/`.yml`, lexical sıra ile birleştirilerek). Tek
uygulama yolu `ApplyPolicy` — hem RPC hem boot aynı kodu kullanıyor.

Politika **bozuksa hiç kural yazılmaz** ve sistem kısıtlamasız
kalır; daemon günlüğe belirgin uyarı yazar. Bu, sistemi yanlışlıkla
kilitlemektense bilinçli bir seçimdir.

### 6.2 Audit rotasyonu hiç çalışmıyordu

`openCurrent()` dosya adını **her zaman bugünün tarihinden**
üretiyordu. 10 MB boyut sınırı tetiklendiğinde aynı dosya
`O_APPEND` ile yeniden açılıyordu — dosya hiçbir zaman dönmeyor,
sadece büyüyordu. VM'de 10.798.351 bayta ulaşmış bir dosya
kullanıcı bunu fark etmeden büyümeye devam ediyordu.

Ayrıca **saklama üst sınırı hiç yoktu**: her gün yeni dosya
birikiyordu. Masaüstü aylarca açık kalırsa `/var/log` doluyordu.

**Düzeltme:** numaralı segment (`audit-GÜN.1.jsonl`), gün değişiminde
tüm segmentleri kapsayan sıkıştırma, 14 günlük saklama.
`writer` paketinde **hiç test yoktu** — 4 regresyon testi eklendi ve
eski kodda başarısız oldukları doğrulandı.

### 6.3 `audit_healthy` kalıcı olarak `false` kalıyordu

`axlog` yeniden başladığında bir kez "broken pipe" oluyor, sonraki
denemede bağlantı kendiliğinden kurulup kayıtlar akmaya devam
ediyordu — ama `lastErr` hafizada kalıyordu. Sistem tamamen sağlıklıyken
`audit_healthy=false` bildiriliyordu.

Etki: operator gerçek bir kesinti olmadığı halde sürekli yanlış alarm
alıyor; akseniyse gerçek bir kesintiyi "geçici bir hata" sanıp
geçebiliyor.

**Düzeltme:** başarılı gönderim `lastErr`'ı temizler.

### 6.4 `axlog` yanlış sürüm bildiriyordu

`axlog/main.go` içinde `"1.0.0"` sabiti vardı. RPM 1.1.0 derlenirken
log servisi kendini **1.0.0** olarak raporluyordu.

Ayrıca `Makefile` sürümü `axdaemon/main.go` içinden kazıyordu;
oradaki tanım `const` → `var` olsaydı kazıma sessizce boş string
donar ve paket `axlinux-.deb` adıyla üretilirdi.

**Düzeltme:** sürüm tek kaynaktan (`axlinux.spec`) geliyor ve
`-ldflags` ile iki ikiliye de enjekte ediliyor. Doğrulama testi
yeni tasarımı denetliyor.

### 6.5 `deep_verify` kendi durumundan etkileniyordu

Test, sabit `/tmp/axctl-cli.txt` yolunu kullanıyordu. Root olmayan
bir kullanıcı testi çalıştırıp bıraktığında dosya o kullanıcıya ait
kalıyor; sonraki çalıştırmada root aynı yolu yazamayıp
`Permission denied` alıyor ve awk hatalı çıkıyordu — **gerçek bir
regresyon olmadığı halde test FAIL ediyordu.**

Bir doğrulama kapısı kendi kalıntısından etkilenmemeli. Dosya artık
çalıştırma kimliğine bağlı.

### 6.6 Ölçüm yöntemi hatası (raporlanmıyor, düzeltildi)

İlk `/tmp` ölçümü "deny uygulanmıyor" sonucunu verdi. Sonuç
**yanlıştı**: `sudo axctl reload` **root'un** ev dizinindeki
politikayı okuyor, testin yazdığı dosyayı değil. Politika hiç
uygulanmamıştı. Doğru kurulumla `/tmp`, `/dev/shm`, `/run`, `/var/tmp`
ve `/etc` altında deny kurallarının **tamamı** çalışıyor.

Bunu ayıran test: `deep_verify` "ayri mount yolu [tmpfs /tmp]
uygulandi / [tmpfs /dev/shm] uygulandi / [tmpfs /run] uygulandi —
3/3 konum".

---

## 6a. Bu turda kapatılan madde 7: audit kaydında yol asla boş değil

### Ölçülen boşluk

`audit_event` yapısındaki `path` alanı policy anahtarıyla **aynıydı**:
8 bileşen × 31 karakter, toplam 256 bayt. Öğrenme modunda izinli her
dosya okunduğunda kayıt üretilir, ama şu yollar anahtara **sığmıyordu**:

| Yol | Sonuç |
|-----|-------|
| 31 karakterden uzun dosya adı | `object: {}` |
| 8'den derin dizin | `object: {}` |
| 256 baytı geçen yol | `object: {}` |

Fedora 44, öğrenme modu, 6 dosya:

```
/tmp/olcum/aaaaa.txt          (10 bayt)  -> çözüldü
31+ karakter ad               (5 dosya)  -> BOS
```

Politika tarafı zaten güvenliydi: `setKeyPath` temsil edilemeyen yol
anahtarı boşaltır ve `ValidateRule` **açık hata** verir; yani kural
sessizce uygulanmaz. Açık olan **denetim kaydı** idi — operator hangi
dosyaya denialdiğini göremiyordu.

### Çözüm

| Değişiklik | Nerede |
|------------|--------|
| `AX_AUDIT_DEPTH=16` / `AX_AUDIT_SLOT=64` ayrı, geniş audit tamponu (`apath`) | `src/bpf/axbpf.h` |
| `ax_fill_audit_path()` — mount kökü dahil tam yol | `src/bpf/axbpf.h` |
| `AX_PATHFLAG_TRUNCATED` → JSON `truncated: true` | `src/bpf/axbpf.h`, `protocol.go` |
| `inode_permission` için `ino`+`dev` kimliği | `ax_fill_inode_id()` |
| Önce `apath`, boşsa anahtar (anahtar eşleşme içindir) | `sender.go` |

`/tmp`, `/var`, `/home` btrfs **alt birimi** olduğu için dentry yürüyüşü
mount kökünde durur; önek `mount_point_map`'ten alınır (mevcut
`ax_fill_path` ile aynı mekanizma).

### Bu sırada kapatılan üç sessiz kayıp

| Kayıp | Belirti |
|-------|---------|
| `__builtin_memset` 1352 bayt | BPF libcall'i reddediyordu → program yüklenmiyordu |
| per-CPU perf tamponu 4096 | 2 olaya sığıyor, gerisi **sessizce** düşüyordu |
| Kayıp sayacı **yoktu** | Düşen kayıt hiçbir yerden görünmüyordu |

Perf tamponu `4096 → 65536` (CPU başına ~48 olay) yapıldı ve
`audit_lost_samples` + `audit_undersized` sayaçları eklendi. Ölçülen
kayıp: bir öğretme koşusunda 79 olay.

### Kanıt (VM, temiz kurulum)

```
audit yol kapisi: 4 kayit incelendi (kisa/uzun ad/derin yol)
80 karakter ad kirpildi ve isaretlendi (truncated=true)
audit kayitlarinda BOS YOL YOK (0/4); kirpilan=2 isaretli
```

C/Go yapı eşitliği **ölçülerek** doğrulandı (boyut 1352 = 1352; `ino` 304,
`dev` 312, `apath` 316, `apath_flags` 1340) ve `TestEventLayoutMatchesC`
bunu C başlığından her koşuda yeniden hesaplar.

## 6b. Bu turda kapatılan dağıtım boşlukları

Aşağıdakiler daha önce "bilinen sınırlar" olarak listeleniyordu.
Hepsi kalıcı olarak çözüldü ve kanıtlandı.

### 6b.1 DİZİN KURALLARI İÇERİĞİ KORUMUYORDU (güvenlik açığı)

`object: /tmp/dizin` + `file.read` deny kuralı yalnız dizinin
**kendisini** engelliyordu:

```
cat /tmp/dizin              -> Operation not permitted
cat /tmp/dizin/secret.txt   -> OKUNUYOR      ← sızıntı
```

Kullanıcı "anahtarlarım korunuyor" sanıyordu.

**Çözüm:** BPF tarafında yol öneki eşleşmesi. Kural anahtarı, gerçek
yolun bileşen bloğunun *k* kadar derineye kaydırılmış hâlidir; Go
tarafında hiç değişiklik yok (türetilen anahtar `setKeyPath` çıktısıyla
birebir aynı).

Üretim kanıtı (kural `object: /tmp/pm`):

| Yol | Sonuç |
|---|---|
| `/tmp/pm/kok.txt` | RED |
| `/tmp/pm/a/ust.txt` | RED |
| `/tmp/pm/a/b/derin.txt` | RED |
| `/tmp/pm/a/b/c/d4.txt` | RED |
| `/tmp/pm/a/b/c/d/d5.txt` | RED |
| `/tmp/pm/a/b/c/d/d6.txt` | RED |
| `/tmp/pm.txt` | SERBEST (benzer ad, farklı yol) |
| `/etc/hostname` | SERBEST (kural dışı) |

**Yanlış pozitif üretilmiyor.** Bu artık `deep_verify` içinde 3
derinlikte + yanlış pozitif kontrolüyle test ediliyor.

### 6b.2 RPM İMZASI YOKTU

Gerçek bir depoda dağıtılan her paket imzali olmak zorundadır.

```
make rpm-gpg-key      → rsa4096 üretir
make rpm              → anahtar varsa otomatik imzalar
make rpm-sign         → RPM'i imzalar
make rpm-export-key   → public anahtarı dist/ altına aktarır
rpm --import dist/axlinux-signing-key.asc
rpm -Kv               → Header OpenPGP V4 RSA/SHA512 signature,
                         key fingerprint: f108e5cc55806bbb4fc42afa6a2e2989448a531
```

Anahtar depoda tutulmaz; üretim geliştiricinin, gizli anahtar deponun
sorumluluğundadır.

### 6b.3 `install.sh` SİSTEM POLİTİKASI DİZİNİNİ KURMUYORDU

RPM yolu dizini spec'te kuruyordu; `install.sh` **kurmuyordu**. İki
kurulum yolu iki farklı sistem kuruyordu ve ikisi de "çalışıyor"
diyordu. `install.sh` artık dizini 0750 root:root, örnek politikayı
0640 olarak kuruyor.

Uçtan uca kanıt (temiz Fedora 44, `install.sh --unattended`):
11/11 adım, ardından LSM 5/5, `axlinux_daemon_t:s0` alanı,
4 kural uygulanıyor, `gedit` açılıyor.

### 6b.4 `.deb` HİÇ KURULMAMIŞTI

Debian 12.15 (bookworm) konteynerinde `dpkg -i` ile kurulup
doğrulandı. Bulunan **dört** gerçek hata:

| Hata | Sonuç |
|---|---|
| `/etc/axlinux/policies.d` yoktu | Politika reboot sonrası kaybolurdu |
| `postinst` sabit `"1.0.0"` yazıyordu | 1.2.0 paketi 1.0.0 diye kaydediliyordu |
| `postinst` dizni oluşturmadan yazıyordu | `Directory nonexistent` |
| Politikalar conffiles değildi | `dpkg -r` kullanıcı politikasını **sildi** |

Doğrulama: `ii axlinux 1.2.0 amd64`, dosya yolları/izinler/sahiplik
doğru, `version` dosyası `1.2.0`, `dpkg -r` sonrası politika **korundu**.

### 6b.5 SÜRÜM YÜKSELTME YOLU DOĞRULANMAMIŞTI

`dnf install 1.1.0` → `dnf upgrade 1.2.0` (imzalı RPM):

| Kontrol | Sonuç |
|---|---|
| `rpm -q` | `axlinux-1.2.0-1.fc44.x86_64` |
| `axlog` binary | `version=1.2.0` (ldflags enjeksiyonu doğrulandı) |
| `axctl` | `axctl 1.2.0` |
| Kullanıcı politikası (4 kural) | **korundu** |
| `/var/lib/axlinux` özel veri | **korundu** |
| Örnek politika | `.rpmnew` olarak bırakıldı (`%config(noreplace)` kullanıcı dosyasını ezmiyor — doğru davranış) |
| Yeni özellikler (dizin kuralı) | yükseltme sonrası çalışıyor |

### 6b.6 ÇOK KULLANICILI SENARYO

İki masaüstü kullanıcısı (UID 1001/1002), 6 kurallık politika:

| Kural | Sonuç |
|---|---|
| `subject=[firefox]` her iki kullanıcının `.ssh/id_rsa`'sı | ENGELLENDİ |
| `subject=[cat]` aynı dosya, başka kullanıcıdan | ENGELLENDİ |
| `subject=[*]` her iki kullanıcının `.gnupg/secret.gpg`'si | ENGELLENDİ |
| `subject=[md5sum]` process.exec | ENGELLENDİ |
| Her kullanıcının kendi dosyasına yazması | İZİN (yanlış pozitif yok) |
| Her kullanıcının `/tmp`'ye yazması | İZİN |

### 6b.7 AUDIT LOGU İÇERİK VE BOYUT SINIRLARI

| Sınır | Değer |
|---|---|
| Segment boyutu | 10 MB (`audit-GÜN.N.jsonl`) |
| Saklama | 14 gün |
| Toplam boyut | **200 MB** (yeni) |
| Sıkıştırma | Gün değişiminde `gzip` |
| Aktif gün | Her zaman korunur (kanıt kaybı disk dolmasından iyidir) |

Ayrıca `inode_permission` kancasının öğrenme modunda ürettiği
**yolsuz** kayıtlar kaldırıldı. O kancada yol çözülemez (LSM imzası
`struct inode *` alır, inode'ın dentry'ye geri işaretçisi yoktur) ve
bu kayıtlar ne bilgi taşır ne kural üretir — 10 dakikada 43.641 kayıt
(10 MB) üretiyordu. DENY kayıtları etkilenmedi.

---

## 6c. Dağıtım yollarında kapatılan boşluklar (bu tur)

### `make rpm` artık **imzalı** paket üretir

Daha önce imzalama ayrı bir adımdı (`make rpm-sign`) ve ana akışta
çağrılmıyordu; normal yoldan çıkan RPM **imzasızdı**.

```
== RPM: imzali ==
  imzalandi: .../axlinux-1.2.0-1.x86_64.rpm
  imza dogrulandi
  Header OpenPGP V4 RSA/SHA512 signature, key fingerprint:
    f108e5cc55806bbb4fc42afa6a2e2989448a5310: OK
```

GPG anahtarı yoksa hata verilir ve **üretilen dosya silinir** —
kullanılamaz paket bırakılmaz.

### `.deb` artık journald sınırını kurar

RPM tarafı `packaging/journald/10-axlinux.conf` drop-in'ini kuruyordu,
Debian tarafı **hiç kurmuyordu** — yani Debian/Ubuntu sistemlerinde
`/var/log/journal` sınırsızdı. Aynı dosya `.deb` içine de kuruluyor ve
`conffiles`'a işleniyor.

Debian 12.15 konteyner doğrulaması:

```
dpkg      : ii  axlinux 1.2.0          (kuruldu VE yapılandırıldı)
journald  : 1 drop-in, SystemMaxUse=200M
conffiles : 5 kayıt
axctl     : axctl, version 1.2.0
politika  : ✓ YAML syntax geçerli
kaldırma  : policies.d 1 dosya + journald 1 drop-in KORUNDU
```

`postinst` artık `systemd-tmpfiles` varlığını kontrol ediyor; minimal
konteynerde "not found" yazıp kurulum çıktısını kirletiyordu.

### `install.sh` yolu (RPM'siz, sıfırdan)

```
ikililer    : 4/4
policies.d : 1 dosya (00-sample-workstation.yaml)
journald   : 1 drop-in
LSM=5 mod=permissive kural=0 policy_healthy=True audit_healthy=True
reload sonrasi: mod=enforcing kural=3
```

### Kaldırma yolunda dört sessiz hata

`dnf remove axlinux` sonrası 8 fcontext kaydı ve 1 modül kalıyordu;
görünür hata yoktu, hepsi `|| :` ile yutuluyordu.

| # | Hata | Çözüm |
|---|------|-------|
| 1 | `semanage delete -a …` **geçersiz alt komut** | `semanage fcontext -d <regex>` |
| 2 | `awk -F'\t'` — çıktı tab değil **boşlukla** hizalı | varsayılan ayrım |
| 3 | `semanage module -r` oncelik deposu içindir | `semodule -r` |
| 4 | Temizlik `%postun`'da; `.pp` `%files` içinde olduğu için **önce** siliniyor | `%preun`'a taşındı |

Ayrıca `fcontext -l` **doğrulama** yapar ve geçersiz kayıtları atlar;
kaldırma anında bu normaldir. Ham yerel liste (`-l -C`) kullanılıyor.

## 8. Dağıtıma hazır mı?

**Fedora 44 Workstation masaüstü hedefi için: evet.**

| Ölçüt | Kanıt |
|---|---|
| Gerçek GNOME oturumu | gdm + Wayland + `systemd --user` ✓ |
| Otomatik giriş | reboot sonrası `axdesktop` oturumu aktif ✓ |
| Gerçekçi enforcing politika | 6 kural, hepsi uygulandı ✓ |
| **Politika kalıcılığı** | reboot sonrası `rules=N mode=enforcing` ✓ |
| **Dizin kuralları içeriği koruyor** | 6 derinlik, yanlış pozitif yok ✓ |
| Masaüstü dayanıklılığı | enforcement altında gedit + dnf + dosya I/O ✓ |
| **Çok kullanıcılı senaryo** | 2 kullanıcı, çapraz izolasyon doğrulandı ✓ |
| Dosya açma gecikmesi | +0,19 sn / 50.000 açma (algılanamaz) ✓ |
| Audit disk maliyeti | ≈250 bayt/**ihlal**; izinli işlem 0 bayt ✓ |
| **Audit logu sınırlı** | 10 MB segment + 14 gün + **200 MB toplam** + gzip ✓ |
| RPM | üretim + **GPG imzası** + `rpm -Kv` parmak izi + temiz kurulum ✓ |
| **Sürüm yükseltme** | 1.1.0 → 1.2.0, kullanıcı verisi korundu ✓ |
| `install.sh` | temiz Fedora'da 11/11 adım + enforcement kanıtı ✓ |
| `.deb` | Debian 12.15'te kurulum, conffiles koruması ✓ |
| Regresyon | **726 geçti / 0 kaldı / 1 atlandı** ✓ |

### Kalan tek sınır

`inode_permission` audit kayıtlarında `object` alanı boş kalır. Bu
**yapısal bir sınırdır**, çözümü yoktur: LSM imzası
`security_inode_permission(struct inode *inode, int mask)` ve inode'ın
dentry'ye geri işaretçisi yoktur (yön tek yönlüdür: dentry → inode).
Yol istenen tüm durumlar `file_open` ve `bprm_check_security`
kancalarında zaten çözülmüş hâlde kaydedilir.

Etkisi operasyonel değil güvenliksel değildir: engellenen kararlar
konuya özgü kuralın kendisidir (`subject: md5sum` gibi), yola
ihtiyaç duymaz.

---

## 9. Bu çalışma turunda düzeltilen hatalar

| # | Hata | Etki | Durum |
|---|---|---|---|
| 1 | Politika reboot sonrası kayboluyordu | **MAC işlevsiz** | düzeltildi |
| 2 | Audit rotasyonu hiç çalışmıyordu | 10 MB sınırı geçersiz | düzeltildi |
| 3 | `audit_healthy` kalıcı `false` | sürekli yanlış alarm | düzeltildi |
| 4 | Dizin kuralları içeriği korumuyordu | **güvenlik açığı** | düzeltildi |
| 5 | `axlog` 1.0.0 bildiriyordu | yanlış sürüm bilgisi | düzeltildi |
| 6 | `deep_verify` kendi kalıntısından etkileniyordu | sahte FAIL | düzeltildi |
| 7 | Rotasyon testi anlamsızdı | hiç doğrulanmıyordu | düzeltildi |
| 8 | `inode_permission` yolsuz gürültü | 10 MB / 10 dk | düzeltildi |
| 9 | Audit toplam boyut sınırsız | disk dolma riski | düzeltildi |
| 10 | RPM imzasız | depoda dağıtılamaz | düzeltildi |
| 11 | `install.sh` politika dizinini kurmuyor | reboot kaybı | düzeltildi |
| 12 | `.deb` 4 ayrı paketleme hatası | politika kaybı/silinmesi | düzeltildi |
| 13 | `postinst` sabit 1.0.0 yazıyordu | yanlış sürüm | düzeltildi |
| 14 | Sürüm yükseltme yolu denenmemiş | yükseltme kırık olabilirdi | doğrulandı |

1, 2 ve 4 doğrudan ürünün işlevini etkileyen türdendi. 4'ün bulunma
sebebi ilgili bölümde test **bulunmamasıydı**.

**Bu makinede (`/dev/sdb1`) AXlinux çalıştırılmadı ve çalıştırılmayacak.**
