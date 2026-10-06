# Fedora 44 Workstation (Masaüstü) Hazırlık Raporu — Test Kanıtları

**Sürüm:** 1.1.0 · **Tarih:** 2026-10-06 · **Hedef:** Fedora Workstation masaüstü

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

Ekran görüntüsü QEMU monitöründen (`screendump`) alındı: GNOME
üst çubuğu, açık gedit penceresi ve uygulama dock'u görünür.

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
| GUI uygulaması | gedit yeniden açıldı, Wayland bağlantısı var |
| `dnf` | `dnf5 version 5.4.1.0` |

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

Temizlik sonrası: **2,2 GB boş (%89)**.

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

## 7. Bilinen sınırlar (dürüstçe)

| Sınır | Durum |
|---|---|
| Dizin kuralları içindeki dosyalar | **Tam yol eşleşmesi.** `object: /home/u/.gnupg` yalnız o dizini korur, `secret.gpg` dosyasını değil. Belgelenmiş. |
| Öğrenme modu kayıt hacmi | `learning` açıkken her işlem kaydedilir; kısa süreli kullanılmalı |
| `/var/log/journal` sınırı | Ayar yok; masaüstünde disk dolma riski (OS düzeyi) |
| Debian paketi (`.deb`) | Derleniyor; Debian sisteminde kurulum **test edilmedi** |
| Sunucu iş yükü | Kapsam dışı (masaüstü hedefi) |

---

## 8. Dağıtıma hazır mı?

**Fedora 44 Workstation masaüstü hedefi için: evet.**

| Ölçüt | Kanıt |
|---|---|
| Gerçek GNOME oturumu | gdm + Wayland + `systemd --user` ✓ |
| Otomatik giriş | reboot sonrası `axdesktop` oturumu aktif ✓ |
| Gerçekçi enforcing politika | 4 kural, 4/4 uygulandı, kural dışı yollar serbest ✓ |
| Politika kalıcılığı | reboot sonrası `rules=4 mode=enforcing` ✓ |
| Masaüstü dayanıklılığı | enforcement altında gedit + dnf + dosya I/O ✓ |
| Dosya açma gecikmesi | +0,19 sn / 50.000 açma (algılanamaz) ✓ |
| Audit disk maliyeti | ≈250 bayt/**ihlal**; izinli işlem 0 bayt ✓ |
| Audit logu sınırlı | 10 MB segment + 14 gün saklama + gzip ✓ |
| Paketleme | RPM temiz kurulum + kaldırma + yeniden kurulum ✓ |
| Regresyon | 716 geçti / 0 kaldı / 2 atlandı ✓ |

Bu turda bulunan **altı gerçek hata** düzeltildi; bunların üçü
(politika kaybı, rotasyonun hiç çalışmaması, `audit_healthy` yanlış
alarmı) ürünün işlevini doğrudan etkileyen türdendi. Hiçbiri
test kapsamının dışında kalmadı — bulunmalarının sebebi, o bölümlerde
test bulunmamasıydı (`writer` paketinde hiç test yoktu) veya testin
kendi durumundan etkilenmesiydi.

**Bu makinede (`/dev/sdb1`) AXlinux çalıştırılmadı ve çalıştırılmayacak.**
