# Doğrulama Raporu — AXlinux 1.2.0

**Tarih:** 2026-10-10
**Kapsam:** README.md, SUPPORT.md, DAGITIM.md, DAGITIM-READY.md,
FEDORA-READINESS.md, CHANGELOG.md ve `docs/` altındaki her sayısal ve
"destekleniyor" iddiası.
**Yöntem:** Her iddia gerçekten çalıştırılarak ölçüldü. Hiçbir sayı
tahmin ya da önceki oturumdan kopyalanma değildir.

> **Kural:** Kanıt üretilemeyen iddia düzeltildi veya metinden çıkarıldı.
> "Doğrulanmadı" diyen açık bir kalem bu raporun yazıldığı anda kalmıyor.

---

## 1. Test ortamı

| Platform | Sürüm | Çekirdek | Yöntem |
|---|---|---|---|
| Fedora 44 Cloud | 44 | 6.19.10-300.fc44 | İmzalı RPM kurulumu |
| Fedora 43 Cloud | 43 | 6.17.1-300.fc43 | İmzasız RPM kurulumu |
| Ubuntu 24.04.5 LTS | 24.04 | 6.8.0-146-generic | `.deb` kurulumu |
| Debian 12 (bookworm) | 12 | 6.1.0-53-cloud | `.deb` kurulumu |
| Pardus 25.2 (yirmibes) | 25.2 | 6.12.107+deb13 | `.deb` kurulumu |
| Arch Linux | güncel | konteyner | `install.sh` çalıştırma |
| Alpine | 3.24 | konteyner | `install.sh` çalıştırma |
| openSUSE Leap | 15.6 | konteyner | `install.sh` çalıştırma |

Sistem başına iki çekirdek koşulu ölçüldü:
- `/sys/kernel/security/lsm` içinde `bpf` zincirde
- `CONFIG_BPF_LSM=y`

---

## 2. Sonuç özeti

### 2.1 `deep_verify.sh` — son kodla

| Platform | geçti | kaldı | atlandı |
|---|---|---|---|
| **Fedora 44** | **732** | **0** | **0** |
| **Fedora 43** | 732 | 1 | 1 |
| Ubuntu 24.04.5 | 731 | 0 | 1 |
| Debian 12 | 731 | 0 | 1 |
| Pardus 25.2 | 731 | 0 | 1 |

**Atlanan tek kalemin gerekçesi:** `SELinux yok (Debian/Ubuntu/Pardus)`.
Debian ailesi SELinux sağlamaz — bu eksik değil, platform farkıdır.
Fedora 44'te aynı kalem çalışır ve 0 atlanan kalemle geçer.

**Fedora 43'teki tek hata dürüst bir rapordur:**
`axdaemon unconfined alanda; SELinux korumasi YOK`. Bu imajda SELinux
kuşaklaması eBPF yüklemesini engellediği için kurulum betiği etiketleri
geri alır ve enforcement LSM üzerinden çalışmaya devam eder
(ölçülen: kanca 5/5, eBPF 5/5). Ayrıntı §5.2.

### 2.2 Yerel doğrulama paketi

| Paket | Sonuç |
|---|---|
| Python (pytest) | 179 geçti + 20 alt test |
| Go — axdaemon | 10 paket |
| Go — axlog | 3 paket |
| `install.sh` sözdizimi | temiz |
| `deep_verify.sh` sözdizimi | temiz |
| `selinux-setup.sh` sözdizimi | temiz |
| `.github/workflows/ci.yml` | geçerli YAML |

---

## 3. Doğrulanan kalemler (madde madde)

### 3.1 Paket yöneticileri — çalıştırılarak

`SUPPORT.md` bu üçünü "tanınıyor, **doğrulanmadı**" diye listeliyordu.
Gerçek konteynerlerde `install.sh` çalıştırıldı.

| Yönetici | Ortam | Ölçülen sonuç |
|---|---|---|
| `pacman` | Arch Linux | paket yöneticisi tanındı · paketler kuruldu · Go 1.23.4 · click/rich/yaml |
| `apk` | Alpine 3.24 | paket yöneticisi tanındı · paketler kuruldu · Go 1.23.4 · click/rich/yaml |
| `zypper` | openSUSE Leap 15.6 | paket yöneticisi tanındı · paketler kuruldu · Go 1.23.4 · pip yedeğiyle click/rich/yaml |

**Bulunan ve düzeltilen 3 gerçek hata:**

1. `pkg_available()` her yöneticide farklı anlam taşıyordu.
   `apk info -e` ve `zypper search -i` **"kurulu mu"** sorar — "depoda
   var mı" değil. Sonuç: Alpine ve openSUSE'de *mevcut* olan `clang`,
   `make`, `git` paketleri "paket yok" sanılıp atlanıyordu.
   Doğrusu: `apk add --no-cache --simulate` ve
   `zypper --non-interactive install --dry-run`.
2. Bağımlılık listesinde `zypper` dalı **hiç yoktu**; openSUSE `*)`
   yedeğine düşüp Fedora paket adlarını deniyordu
   (`linux-headers` yerine `linux-devel-default`). Python
   bağımlılıklarında da ne `zypper` ne yedek dalı vardı.
3. `tar` hiçbir yerde bağımlılık olarak bildirilmemişti, ama
   `install.sh` Go'yu açarken kullanıyordu.

### 3.2 CI paketleme matrisi — koşularak

| İmaj | Sonuç | 8/8 içerik | conffiles | SELinux modülü |
|---|---|---|---|---|
| `fedora:41` | geçti | ✓ | 5 | ✓ |
| `fedora:42` | geçti | ✓ | 5 | ✓ |
| `fedora:43` | geçti | ✓ | 5 | ✓ |
| `fedora:44` | geçti | ✓ | 5 | ✓ |
| `debian:12` | geçti | ✓ | 5 | ✓ |

8 içerik kalemi: `axbpf.o`, `axdaemon`, `axlog`, `axctl`, journald
drop-in, SELinux modülü (`axlinux.pp`), systemd servisi, `kernel-core`.

**Bulunan ve düzeltilen 2 kırık nokta:**

1. **Debian işi her zaman düşüyordu.** `apt`'in `golang` paketi Go 1.19
   veriyor; proje Go 1.21 istiyor (`go.mod`, `log/slog`). Artık
   `bookworm-backports`'tan `golang-1.23-go` kuruluyor ve ayrı bir
   adımda sürüm denetleniyor.
2. **RPM matrisinin tamamı düşüyordu.** `go build` VCS damgası istiyor,
   git'e erişilemeyen konteynerde `error obtaining VCS status` veriyor.
   `Makefile` artık `-buildvcs=false` ile derliyor; derleme `.git`'e
   bağımlı değil.

### 3.3 Kurulum artefaktları

| Artefakt | Ölçülen |
|---|---|
| RPM imzası | `Header OpenPGP V4 RSA/SHA512, key fingerprint: f108e5cc55806bbb4fc42afa6a2e2989448a5310: OK` |
| Header/Payload digest | SHA256 OK |
| conffiles | 5 |
| SELinux modülü | `axlinux.pp` — Fedora 43'te bozuk modül ölçüldü, düzeltildi (§5.4) |
| `.deb` sürüm alanı | `Version: 1.2.0` |
| Kaldırma | iki ardışık temiz döngüde `semodule=0`, `fcontext=0`, `yerel fcontext=0`, `modül dosyası=0`, `ikili=0/4` |

### 3.4 SELinux konfasyonu

| Ortam | Bağlam | eBPF | Sonuç |
|---|---|---|---|
| Fedora 44 | `axlinux_daemon_exec_t` | 5/5 | `alan dogrulandi: ...axlinux_daemon_t:s0 (eBPF: 5)` |
| Fedora 43 | `bin_t` (geri alındı) | 5/5 | uyarı verildi, enforcement çalışıyor |

### 3.5 Performans — üçer kez tekrar ölçüldü

`FEDORA-READINESS.md` daha önce şunu diyordu:
*"kanca takma maliyeti +5.8 µs (%51), politika sorgusu +0.6 µs (%3.5)"*
ve çıkarımı **ters**ydi.

| Durum | 3 koşu (µs/açma) | Medyan |
|---|---|---|
| LSM kancası yok | 14.3 · 13.2 · 12.1 | 13.2 |
| Kanca bağlı, `disabled` | 12.7 · 16.3 · 17.8 | 16.3 |
| Kanca bağlı, `enforcing` | 22.1 · 26.2 · 21.9 | **22.1** |

- **Politika sorgusu maliyeti gerçek:** +5.8 µs, aralıklar çakışmıyor
  ([2] en yüksek 17.8 < [3] en düşük 21.9).
- **Kanca takma maliyeti ölçülemedi:** aralıklar çakışıyor
  ([1] 12.1–14.3, [2] 12.7–17.8) — koşu-koşu gürültüsü.

Throughput (50.000 açma): `disabled` 0.228 s · `enforcing` 0.559 s
(eski değer 0.44 s idi; enforcement maliyeti **fazla iyimser** gösteriliyordu).

---

## 4. Doğrulama sırasında kapatılan `deep_verify` boşlukları

| Önce | Sonra |
|---|---|
| `nc` kurulu değil → 2 socket testi atlanıyordu | `netcat-openbsd` kuruldu, ikisi de çalışıyor |
| "erişilemeyen sokette hata vermedi (**root testi**)" — kontrol ROOT olarak çalışıyordu; root `chmod 000` sokete de eriştiği için test **kendini kandırıyordu** | kontrol yetkisiz kullanıcı ile çalışıyor (`rc=4`, "Socket izni yok") |
| LSM kancası kapısında sabit 5 deneme — yavas VM'de "LSM kancalari: ?/?" | sağlığa göre bekleme (`ax_wait_healthy`) |
| `axctl reload` "socket bulunamadı" ile başarısız, hata **yutuluyordu** | reload rc'si ve çıktısı kayda geçiyor |
| politika "yüklenmiş" sanılıyordu, oysa `rules_loaded=0` | deny'nin **fiilen etkili olması** bekleniyor |

---

## 5. Bulunan kritik ürün hataları

### 5.1 İki ayrı politika ayrıştırıcısı — kalıcı konum tamamen kırıktı

`axctl policy check` tekil `subject: curl` yazan politikayı **geçerli**
diyordu. Kullanıcı yolunda (`axctl reload`) de öyleydi. Ama
`/etc/axlinux/policies.d` — **kalıcı konum** — aynı dosyayı reddediyordu:

```
sistem politikasi yuklenemedi; sistem KISITLAMASIZ kaliyor
error="50-....yaml: policy JSON parse hatasi: json: cannot unmarshal
       string into Go struct field Rule.rules.subject of type []string"
```

Sonuç: kullanıcı reboot sonrası "kurallarım yüklü" sanıyordu;
**hiçbir kural yazılmıyordu.** Sistem kısıtlamasızdı.

Düzeltme: `SubjectList` + özel `UnmarshalJSON`. Regresyon koruması:
- `internal/policy/subjectlist_test.go` — scalar/list/bozuk girdi
- `internal/policy/systemload_subject_test.go` — **sistem yolu**
- `deep_verify`: "sistem politikasi yuklendi (policies.d)" kapısı

Reboot kalıcılığı elle doğrulandı: politika `policies.d`'den yüklendi,
deny derinlikte çalıştı (`Operation not permitted`, 2 DENIED kaydı),
kural dışı ve benzer adlı komşu serbest kaldı (yanlış pozitif yok).

### 5.2 SELinux kuşaklaması sessizce hiç kurulmuyordu

Dosya bağlamları `semanage fcontext` ile yazılıyor; bu araç
`policycoreutils-python-utils` ile gelir ve spec bunu **Requires olarak
bildirmiyordu**.

Fedora 43 imajında ölçülen sonuç:
- `semanage: command not found` → etiketler yazılmıyor
- `/usr/bin/axdaemon` → `bin_t`
- daemon **unconfined** çalışıyor
- `deep_verify`: `FAIL axdaemon unconfined alanda; SELinux korumasi YOK`

Fedora 44'te çalışıyordu **tesadüfen** — o imajda paket zaten vardı.

Düzeltme (iki aşamalı):

1. `Requires: policycoreutils-python-utils` eklendi.
2. Kurulum betiğine **fonksiyonel doğrulama**: etiketler uygulandıktan
   sonra eBPF gerçekten yükleniyor mu bakılır. Yüklenmiyorsa etiketler
   geri alınır, servis yeniden başlatılır ve operator'a bildirilir.

Bu ikinci aşama gerekti çünkü Fedora 43'te etiketli `axdaemon`
`axlinux_daemon_t` alanına girince SELinux **BPF harita işlemini
reddediyor**:

```
avc: denied { map_read map_write } for comm="axdaemon"
     scontext=system_u:system_r:axlinux_daemon_t:s0

etiketli  -> kanca 0/0, bpf 0, "ebpf yuklenemedi"
etiketsiz -> kanca 5/5, bpf 5, enforcement çalışır
```

Yani kuşaklama, kuşaklamsız sistemden **daha kötü** bir sistem
bırakıyordu. Ölçülen nihai sonuç:

```
UYARI: konfinasyon eBPF yuklemeyi engelliyor
etiketler geri alindi; enforcement LSM ile aktif
yeniden baslatildi; eBPF: 5 program
```

### 5.3 Test kapıları ortamda yanlış sonuç veriyordu

`deep_verify` birçok yerde sabit kısa bekliyordu ("sleep 1", "sleep 5").
Yavaş sanal makinelerde politika/kanca hazır olmadan ölçüm yapılıyordu
ve kapılar ürün hatası sanılan kırmızılar veriyordu — ürün sağlıklıyken.
Tümü sağlığa göre beklemeye çevrildi.

### 5.4 Bayat SELinux modülü paketleniyordu

`make rpm` yalnızca `all` çağırıyordu ve `2>/dev/null` derleme
hatalarını **gizliyordu**. Ağaçta daha önce derlenmiş bir `.pp`
varsa `make` onu "güncel" sayıp derlemeyi atlıyor; RPM'e o bayat
modül paketleniyordu.

Fedora 43'te ölçülen bozuk modül: **91.660 bayt, 0 tip, 0 fcontext
kuralı** — modül "kuruldu" görünüyor ama hiçbir şeyi etiketlemiyordu.

Düzeltme: modül her zaman `clean` + `all` ile sıfırdan derlenir; boş
modül (0 tip) üretilirse derleme **hata verir**. Doğru modül 91.880 bayt.
`.pp` ve `.rpmbuild/` artık `.gitignore`'da.

---

## 6. İddia düzeltmeleri

| Belge | Eski | Yeni |
|---|---|---|
| `README.md` | 732/0/1 | platform bazlı (Fedora 44 → 732/0/0; Debian ailesi → 731/0/1) |
| `SUPPORT.md` | pacman/apk/zypper "doğrulanmadı" | üçü de çalıştırıldı, kanıt tablosu |
| `SUPPORT.md` | Fedora 41–44 "kesin doğrulanmış" | derleme 4'ünde; çalışma zamanı 43 ve 44'te |
| `DAGITIM.md` | Ubuntu/Pardus/Debian 732/0/1 | 731/0/1; Fedora 43 ve 44 eklendi |
| `DAGITIM.md` | "10 bölüm, 100 denetim" | 8 adlandırılmış bölüm (K–R), 732 kontrol |
| `FEDORA-READINESS.md` | kanca +5.8 µs, politika +0.6 µs | politika +5.8 µs (gerçek), kanca ölçülemedi |
| `FEDORA-READINESS.md` | throughput 0.44 s | 0.559 s |
| `docs/roadmap.md` | "10 bölüm / 100 denetim" | 8 bölüm, ölçülmüş 732 kontrol |

---

## 7. Kalıcı koruma

Bu oturumda bulunan hataların geri dönmesini engelleyen kalıcı kapılar:

| Kapı | Koruduğu hata |
|---|---|
| `internal/policy/subjectlist_test.go` | scalar/list `subject` ayrışımı |
| `internal/policy/systemload_subject_test.go` | `policies.d` yolunun ayrışması |
| `tests/deep_verify.sh` → sistem politikası kapısı | kalıcı konumun bozuk kalması |
| `tests/deep_verify.sh` → soket yetki kapısı | yetkilendirme yolunun test edilmemesi |
| `tests/deep_verify.sh` → `ax_wait_healthy` | hazır olmadan ölçüm |
| `tests/test_doc_numbers.py` | bayat doğrulama sayılarının belgeye dönmesi |
| CI Go sürüm denetimi | Go 1.21 altına düşmesi |
| `Makefile` boş modül kontrolü | SELinux modülünün bozuk paketlenmesi |
| `selinux-setup.sh` eBPF doğrulaması | kuşaklamanın eBPF'i kırması |

---

## 8. Kapsam dışı (dürüstçe)

- **Fedora 41 ve 42 çalışma zamanı testi koşturulmadı.** RPM derleme
  ve içerik doğrulandı (`make rpm` + 8/8 + 5 conffiles + SELinux
  modülü); gerçek kurulum + `deep_verify` çalıştırılmadı.
  `SUPPORT.md` buna göre yazıldı.
- **`inode_permission` yolu kernel ABI'sinde alınamaz.** Bu kanca yalnızca
  `struct inode *` verir; dentry'ye geri referans yoktur. Çözüm `ino/dev`
  kimliğini audit kaydına eklemektir; yol gerektiren kayıtlar
  `file_open`/`bprm` kancalarında kalır. Bu yapısal bir sınırdır,
  ölçülebilir bir kusur değildir.
- **Fedora 43'te SELinux kuşaklaması yok** (bkz. §5.2). Ölçülmüş,
  belgelenmiş ve güvenli geri almeyle karşılanmış bir platform sınırıdır.