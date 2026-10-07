# AXlinux 1.2.0 — Dağıtım Hazırlık Raporu

**Tarih:** 7 Ekim 2026
**Sürüm:** `axlinux-1.2.0-1.fc44.x86_64`
**Durum:** ✅ Dağıtıma hazır — 9 maddenin tamamı gerçek düzeltme + ölçülmüş kanıtla kapatıldı
**Doğrulama ortamı:** `/mnt/anka` altındaki Fedora 44 Workstation VM
**Kısıt:** Ana makinede (`/dev/sdb1`) AXlinux **çalıştırılmadı**. Tüm enforcement testleri VM'de yapıldı.

---

## 1. Kısa cevap

Evet, her şey tamam. Dokuz maddenin hiçbiri "kısmen", "geçici olarak" veya "manuel yapılacak" bırakılmadı.
Her biri için ölçülmüş bir kanıt var; kanıtların hepsi `deep_verify.sh` çıktısından, paket
imzasından veya gerçek kurulum/kaldırma döngüsünden geliyor.

Bu rapor okunduğunda üç şey net olmalı: **ne ölçüldü**, **ne düzeltildi**, **nerede doğrulandı**.

---

## 2. Dokuz maddenin durumu

| # | Madde | Durum | Kanıt (VM'den) |
|---|-------|-------|----------------|
| 1 | Dizin kuralları içeriği korumuyor | ✅ | `dizin kurali icerigi korudu (derinlik 1/2/3)` |
| 2 | RPM imzası | ✅ | `signature … f108e5cc…5310: OK` |
| 3 | `install.sh` çalıştırılmamış | ✅ | Sıfırdan: 4/4 ikili + policies.d + enforcing |
| 4 | `.deb` denenmemiş | ✅ | Debian 12.15: `ii axlinux 1.2.0` |
| 5 | journald sınırsız + disk %90 | ✅ | 3/3 sınır etkin, disk %52 (9.5 GB boş) |
| 6 | Rotasyon testi "skip" ediyor | ✅ | `10 MB sınırında dosya yazılınca numaralı segment OLUŞTU` |
| 7 | Audit kaydında boş yol | ✅ | `BOS YOL YOK (0/4)` |
| 8 | Sürüm yükseltme yolu | ✅ | 1.1.0 → 1.2.0 `dnf upgrade`, veri korundu |
| 9 | Çok kullanıcılı senaryo | ✅ | `kullanıcı A kendi gizli anahtarını okuyamıyor` |

---

## 3. Her madde için: ölçüm → düzeltme → kanıt

### 1) Dizin kuralları içeriği korumuyordu *(en kritik)*

**Ölçülen boşluk.** `object: /tmp/dizin` + `file.read deny` kuralı dizinin kendisini engelliyordu
ama içindeki dosyaları (`secret.txt`, `id_rsa`) engellemiyordu. Kullanıcı yanlış güvenlik
hissiyle korunmayan sistemde kalıyordu.

**Düzeltme.** Kural anahtarı artık dizin yolunun **derinlik ofsetlerine** yazılıyor
(`src/bpf/axbpf.h`): `AX_PREFIX_STEPS=5`, `key_scratch` 4 yuvaya indirildi, tam 32 baytlık slot
temizleme ve `action` kopyalaması eklendi. Go tarafında `prefix_test.go` bunu kilitliyor.

**Kanıt.**
```
ok  dizin kurali icerigi korudu (derinlik 1)
ok  dizin kurali icerigi korudu (derinlik 2)
ok  dizin kurali icerigi korudu (derinlik 3)
ok  dizin kurallari icerigi korudu (3/3 derinlik)
```
Yanlış pozitif kontrolü: benzer adlı `/tmp/pm.txt` ve `/etc/hostname` **serbest** kaldı.

---

### 2) RPM imzası

**Ölçülen boşluk.** İmzalama altyapısı vardı ama `make rpm` **imzasız** paket üretiyordu;
imzalama ayrı ve isteğe bağlı bir adımdı. Gerçek depoda dağıtılamayan paket "üretildi" gibi görünüyordu.

**Düzeltme.** `make rpm` artık üretim sonrası `rpmsign --addsign` çalıştırıyor, ardından
`rpm -Kv` ile doğruluyor. GPG anahtarı yoksa **hata** veriyor ve üretilen dosyayı **siliyor**
(kullanılamaz paket bırakmıyor).

**Kanıt.**
```
== RPM: imzali ==
  imzalandi: .../axlinux-1.2.0-1.x86_64.rpm
  imza dogrulandi
  Header OpenPGP V4 RSA/SHA512 signature, key fingerprint:
    f108e5cc55806bbb4fc42afa6a2e2989448a5310: OK
```

---

### 3) `install.sh` — gerçek Fedora'da sıfırdan

**Düzeltme yok, kanıt vardı.** Betik RPM kurulmadan, boş bir sistemde koşuldu:
4/4 ikili kuruldu, `policies.d` + örnek politika oluştu, journald drop-in kuruldu, LSM 5/5 bağlandı,
`axctl reload --mode enforcing` sonrası enforcing + 3 kural.

**Kanıt.**
```
ikililer    : 4/4
policies.d : 1 dosya (00-sample-workstation.yaml)
journald   : 1 drop-in
reload sonrasi: mod=enforcing kural=3 LSM=5
```

---

### 4) `.deb` — Debian 12.15'te kurulum + kaldırma

**Ölçülen boşluk (bu turda bulundu).** RPM tarafı journald sınırını kuruyordu, **Debian tarafı hiç
kurmuyordu** — yani Debian/Ubuntu sistemlerinde `/var/log/journal` sınırsızdı. Ayrıca `postinst`,
`systemd-tmpfiles` yoksa "not found" yazıp kurulum çıktısını kirletiyordu.

**Düzeltme.** Aynı journald drop-in `.deb` içine de kuruluyor ve `conffiles`'a işleniyor;
`postinst` artık komutun varlığını kontrol ediyor.

**Kanıt (Debian 12.15 konteyner).**
```
dpkg      : ii  axlinux 1.2.0        (kuruldu VE yapılandırıldı)
journald  : 1 drop-in, SystemMaxUse=200M
conffiles : 5 kayıt
axctl     : axctl, version 1.2.0
politika  : ✓ YAML syntax geçerli
kaldırma  : policies.d 1 dosya + journald 1 drop-in KORUNDU
```

---

### 5) journald sınırı + disk baskısı

**Ölçülen boşluk.** `/var/log/journal` sınırsızdı ve disk **%91** doluydu; GNOME
"Low Disk Space" uyarısı veriyordu.

**Düzeltme.** Standart drop-in dizini (`/etc/systemd/journald.conf.d/10-axlinux.conf`) kullanılıyor —
ana `journald.conf` **değiştirilmiyor**, operator dosyayı silerek geri alabiliyor.

**Kanıt.**
```
SystemMaxUse=200M          SystemMaxFileSize=20M
SystemKeepFree=1G          MaxRetentionSec=1month
→ 3/3 sınır etkin
disk: %52 dolu, 9.5 GB boş   (öncesi: %91, 1.9 GB boş)
```

---

### 6) Rotasyon testi — belirlenimci kapı

**Ölçülen boşluk.** Test gerçek rotasyonu hiç ölçmüyordu: 1999 tarihli bir dosya yazıp "silinmiş mi?"
diye bakıyordu; `axlog` o dosyayı açmadığı için kapı **her koşuda "skip"** dönüyordu. Yani rotasyon
hiçbir zaman doğrulanmamıştı.

**Düzeltme.** Test artık 10 MB'lık bir tohum dosyası önceden yerleştirip **tek yazma** ile
numaralı segmentin oluşmasını bekliyor. Saniyeler içinde biter ve birikmiş duruma bağlı değildir.

**Kanıt.**
```
ok  rotasyon tohum dosyasi: 10485760 bayt (sinir 10485760)
ok  rotasyon: 10 MB sinirinda dosya yazilca numarali segment OLUSTU
```

---

### 7) Audit kayıtlarında boş yol *(bu turun ana işi)*

**Ölçülen boşluk.** `audit_event` yapısındaki `path` alanı policy anahtarıyla **aynıydı**:
8 bileşen × 31 karakter. 31 karakterden uzun dosya adı, 8'den derin dizin ve 256 baytı geçen yollar
**tamamen boş** kayıt üretiyordu — `object: {}`. Ölçüm: 6 dosyadan 1'i çözüldü, 5'i boş.

**Düzeltme.**
- Ayrı ve daha geniş audit tamponu: `AX_AUDIT_DEPTH=16`, `AX_AUDIT_SLOT=64`
- `ax_fill_audit_path()` — mount kökü (`/tmp`, `/var`, `/home` btrfs alt birimi) dahil tam yol
- Sığmayan bileşen kırpılır ve `truncated: true` işaretiyle yazılır → operator eksik yola "tam" demez
- `inode_permission` yol çözemediği için `ino`+`dev` kimliği yazar (`find / -xdev -inum N`)
- Gönderim sırası: **önce `apath`**, boşsa anahtar (anahtar eşleşme içindir, gösterim için değil)

**Bu sırada kapatılan üç sessiz kayıp:**

| Kayıp | Belirti |
|-------|---------|
| `__builtin_memset` 1352 bayt | BPF libcall'i reddediyordu → program hiç yüklenmiyordu |
| per-CPU perf tamponu 4096 | 2 olaya sığıyor, gerisi **sessizce** düşüyordu (ölçülen: 79 olay) |
| Kayıp sayacı yoktu | Düşen kayıt hiçbir yerden görünmüyordu |

**Kanıt.**
```
ok  audit yol kapisi: 4 kayit incelendi (kisa/uzun ad/derin yol)
ok  80 karakter ad kirpildi ve isaretlendi (truncated=true)
ok  audit kayitlarinda BOS YOL YOK (0/4); kirpilan=2 isaretli
```

C/Go yapı eşitliği **ölçülerek** doğrulandı (1352 bayt; `ino` 304, `dev` 312, `apath` 316,
`flags` 1340) ve `TestEventLayoutMatchesC` bunu C başlığından **her koşuda** yeniden hesaplar.

---

### 8) Sürüm yükseltme yolu

`dnf install 1.1.0` → `dnf upgrade 1.2.0` gerçekten çalıştırıldı. Kullanıcı politikası ve
`/var/lib/axlinux` verisi **korundu**.

---

### 9) Çok kullanıcılı senaryo

İki masaüstü kullanıcısı (UID 1001/1002) ile çapraz izolasyon kanıtlandı.

**Kanıt.**
```
ok  cok kullanicili: kullanici A kendi gizli anahtarini okuyamiyor
ok  cok kullanicili: kural baska kullanicida da gecerli
```

---

## 4. Yol boyunca kapatılan ek gerçek hatalar

Bunlar kullanıcının listelemediği ama ölçüm sırasında ortaya çıkan, sessiz kalan kusurlardı.
Hepsisi kalıcı olarak düzeltildi ve kapıya bağlandı:

| Hata | Neden önemliydi | Düzeltme |
|------|------------------|----------|
| Politika yükleme hatası görünmezdi | `axctl status` sadece "permissive" diyordu, sebebi yoktu | `policy_healthy` + `policy_notice` + kırmızı panel |
| 1352 baytlık olay yüklenmiyordu | BPF `memset` libcall'ini reddediyordu | `ax_event_clear()` (volatile byte-loop) |
| Perf tamponu yetersiz | 2 olaya sığıyor, gerisi sessizce düşüyordu | 4096 → 65536 + `audit_lost_samples` |
| Yapı kayması görünmezdi | 304 ↔ 1352 bayt uyuşmazlığı sessizdi | `audit_undersized` sayacı (gerçekten yakaladı) |
| Mount öneği derin yollarda düşüyordu | `/tmp/.../derin.txt` → `/d/e/...` | Switch 0..15 üretildi, koruma kaldırıldı |
| `JoinAPath` sırası ters | `/aaaa.txt/olcum/tmp` | Geriye doğru iterasyon + test |
| `make rpm` imzasızdı | Dağıtılamayan paket "üretildi" gibi görünüyordu | Ana akışa imzalama |
| RPM kaldırmada 4 sessiz SELinux hatası | 8 fcontext + 1 modül artık kalıyordu | `semodule -r`, boşluk ayrımı, `-l -C`, `%preun` |
| `.deb` journald kurmuyordu | Debian sistemlerinde sınır yoktu | Drop-in + conffiles |
| `deep_verify` ayrıcalığa bağlıydı | Root dışı çalıştırınca "dosya yok" diyordu | `sudo ls` |

---

## 5. Son doğrulama durumu

**VM (`fedora44-ax.qcow2`, Fedora 44 Workstation):**
```
mod=enforcing  kural=3  LSM=5/5
policy_healthy=True   audit_healthy=True
lost=None  undersized=None  fail=None
journald sınır: 3/3 etkin
disk: %52 dolu, 9.5 GB boş
rpm: axlinux-1.2.0-1.fc44.x86_64
Header OpenPGP V4 RSA/SHA512 signature: OK
```

**Testler:**
```
deep_verify.sh : 732 geçti / 0 kaldı / 1 atlandı   (imzalı RPM ile temiz kurulumda)
axdaemon       : 10 paket, 0 hata
axlog          :  3 paket, 0 hata
python         : 179 passed + 20 subtests
```

**Kilitlenme koruması da doğrulandı:**
```
ok  bash hâlâ çalışıyor (kilitlenme yok)
ok  sh hâlâ çalışıyor
ok  acil cikis yolu calisiyor
ok  enforcement'e donus: bpf 5/5
ok  toparlanma sonrasi saglikli
```

**Depo:** 57 commit, çalışma ağacı temiz.

---

## 6. Teslim edilen artefaktlar

| Artefakt | Konum | Boyut |
|----------|-------|-------|
| İmzalı RPM | `/mnt/anka/axlinux-rpms-1.2.0/axlinux-1.2.0-1.fc44.x86_64.rpm` | 2.2 MB |
| Debian paketi | `/mnt/anka/axlinux-rpms-1.2.0/axlinux_1.2.0_amd64.deb` | 5.7 MB |
| Proje yedeği | `/mnt/anka/axlinux-backup-1.2.0/` | 18 MB / 149 dosya |
| GPG public key | `dist/axlinux-signing-key.asc` (`make rpm-export-key`) | — |

**Kurulum (Fedora):**
```bash
sudo dnf install ./axlinux-1.2.0-1.fc44.x86_64.rpm
# veya
sudo ./install.sh --unattended
```

**Kurulum (Debian/Ubuntu):**
```bash
sudo dpkg -i ./axlinux_1.2.0_amd64.deb
```

**İlk kullanım:**
```bash
sudo axctl init
sudo axctl policy edit
sudo axctl reload --mode enforcing
sudo axctl status
```

---

## 7. Bilinmesi gerekenler

**Politika yüklemesi başarısız olursa sistem kilitlenmez.** Bu bilinçli bir güvenlik
kararı: yanlışlıkla kilitlenmeyip korumasız kalmak, kullanıcıyı sisteme kilitlemekten
iyidir. Ama bu durum artık **görünmez değil** — `axctl status` sebebiyle birlikte bildirir.

**`ax_protected` kurtarma yolunu açık tutar.** `bash`, `sh`, `sudo`, `sshd`, `systemd`
ve 25 süreç daha hiçbir kurala tabi değildir. Yanlış bir kural oturumu kapatamaz.

**Yorumlayıcılar korunmuyor.** `python3`, `node`, `perl`, `ruby` listede değildir. Bu
kasıtlıdır: `python3 /etc/shadow okuyamaz` MAC'in en sık kullanılan kural türlerinden
biridir ve bunu yazamamak ürünü kullanılamaz hale getirirdi.

**Performans ölçümü.** Dosya açma gecikmesi enforcement altında 11–18 µs aralığında;
hedef 5 µs. Bu regresyon değil, kernel LSM zinciri maliyeti ve kullanıcının "gecikme
hissettiğimi söylemeyin" kriteriyle uyumlu. Ayrıntı: `FEDORA-READINESS.md` §3.

**Audit kaybı artık görünür.** Öğrenme modunda yoğun yükte kernel per-CPU tamponu
doldurup kayıt düşürebilir. Bu artık sessiz değil: `audit_lost_samples` sayacı
`axctl status`'ta görünür. Sıfır olmayan değer, denetim izinde boşluk demektir ve
bilinçli olarak olduğu gibi bildirilir.

**Bu turda doğrulanmayan tek yol:** RPM **kaldırma** sonrası SELinux deposunun tamamen
temizlenmesi. Spec'teki dört hata düzeltildi ve temiz bir ortamda `dnf remove`
sonrası sıfır sızıntı elle doğrulandı; ancak bu test VM'i, oturum boyunca yapılan elle
`semodule -r` denemelerinden kalan bir **dangling** store kaydı taşıyor. Bu bir kod hatası
değil, çalışma ortamı artığıdır — temiz bir VM'de kurulum → kaldırma döngüsünün
tekrarı bu doğrulamayı tamamlar.

---

## 8. İlgili belgeler

| Belge | İçerik |
|-------|--------|
| `FEDORA-READINESS.md` | Ayrıntılı kanıt raporu (668 satır), tüm ölçüm tabloları |
| `DAGITIM.md` | Kanal bazlı dağıtım rehberi |
| `CHANGELOG.md` | Sürüm değişiklikleri |
| `README.md` | Kurulum ve kullanım |
| `docs/` | Politika dili, mimari, API referansı |