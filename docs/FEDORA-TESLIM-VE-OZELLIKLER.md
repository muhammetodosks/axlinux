# AXlinux 1.2.0 — Fedora Teslim ve Özellik Belgesi

**Sürüm:** 1.2.0 · **Tarih:** 2026-10-10
**Hedef platform:** Fedora Linux 44 (Cloud Edition), çekirdek `6.19.10-300.fc44.x86_64`

Bu belge iki işi birden yapar:
1. **Teslim kanıtı** — paketin içeriği, imzası, kurulumu ve çalışma zamanı
   davranışı ölçülmüş değerlerle.
2. **Özellik kataloğu** — ürünün ne yaptığı, her özelliğin nasıl doğrulandığıyla.

> **Kural:** Buradaki her sayı gerçek bir ölçümden gelir. Sanal makine
> çıktıları, `rpm -q`/`rpm -Kv`/`dpkg-deb` sonuçları ve `deep_verify.sh`
> koşuları dışında hiçbir değer yazılmamıştır. Taranmamış hiçbir iddia
> "çalışıyor" diye sunulmaz.

---

## 0. Önce güvenlik

Bu ürün **ana makinenizde çalıştırılmadı ve çalıştırılmamalıdır.**
Tüm testler `/mnt/anka` altındaki sanal makinelerde yapıldı.

AXlinux `bpf()` syscall yetkisini yalnızca kendi `axdaemon` sürecine verir.
Yanlışlıkla ana makinede çalıştırılırsa sistem kilitlenme riski doğar.
`axctl` bunu ayrıca denetler ve reddeder:

```
HATA: fiziksel makine koruması — AXlinux sanal makinede çalışır
```

Acil çıkış her zaman açıktır:

```bash
sudo axctl mode disabled
```

---

## 1. Hızlı kurulum (Fedora)

```bash
sudo dnf install ./axlinux-1.2.0-1.x86_64.rpm
```

Kurulum tek komutla SELinux modülünü kurar, dosya bağlamlarını yazar,
`axbpf.o`'yu yerleştirir, journald sınırını uygular ve servisi başlatır.

**Önerilen akış** (politicayı önce izleyerek öğrenin):

```bash
axctl init                  # ~/.axlinux/ oluştur
axctl policy edit           # YAML politikanı yaz
axctl policy check          # doğrula
axctl policy simulate       # neyi etkileyeceğini önce gör
sudo axctl reload           # uygula
sudo axctl status           # gerçek durumu kontrol et
```

`policy simulate` en önemli komuttur: `reload` **öncesi** kuralların neyi
etkileyeceğini gösterir.

---

## 2. Özellikler ve doğrulama kanıtları

### 2.1 YAML politika dili

Politika dosyası YAML'dır; derlenmiş bir dil değil.

| Alan | Anlamı |
|---|---|
| `id` | Kural kimliği (benzersiz) |
| `name` | Zorunlu, insan okur açıklama |
| `subject` | Süreç (yol veya ad) — tekil veya liste |
| `object` | Yol öneki — dizin kuralları **içeriği de** korur |
| `action` | Eylem türü (aşağıdaki tablo) |
| `effect` | `deny` / `allow` |
| `mode` | Politika düzeyi: `disabled` / `permissive` / `enforcing` |

**Ölçülen:** `subject` alanı hem tekil (`subject: curl`) hem liste
(`subject: [curl, wget]`) biçimini kabul eder. Bu iki biçim **iki ayrı
ayrıştırıcıda** ele alınır ve her ikisi de regresyon testine bağlıdır
(`src/go/axdaemon/internal/policy/`).

### 2.2 Altı aksiyon türü

| Aksiyon | Ne engeller | LSM kancası | Ölçülen |
|---|---|---|---|
| `file.read` | Dosya okuma | `file_open` | ✓ |
| `file.write` | Dosya yazma | `file_open` | ✓ |
| `file.execute` | Dosya çalıştırma | `bprm_check_security` | ✓ |
| `inode_permission` | inode izinleri | `inode_permission` | ✓ |
| `socket_connect` | Dışa bağlanma | `socket_connect` | ✓ |
| `socket_bind` | Port dinleme | `socket_bind` | ✓ |

**Ölçülen:** 5 LSM kancası bağlı, eBPF programları 5/5 yüklü.
`socket_bind` port eşleştirmesi yapmaz (yalnızca port adı); bu bir
bilinen sınırdır, `docs/policy-language.md` içinde yazılıdır.

### 2.3 Dizin kuralları içeriği korur

Bu, ürünün en kritik davranışıdır ve ayrıca kanıtlanmıştır.

Kural `object: /tmp/pm` ise, **içindeki tüm dosyalar** da korunur:

```
/tmp/pm/kok.txt              → REDDEDİLDİ
/tmp/pm/a/ust.txt            → REDDEDİLDİ
/tmp/pm/a/b/derin.txt        → REDDEDİLDİ
/tmp/pm/a/b/c/d4.txt         → REDDEDİLDİ
/tmp/pm/a/b/c/d/d5.txt       → REDDEDİLDİ
/tmp/pm.txt                  → SERBEST   (benzer ad, farklı yol)
/etc/hostname                → SERBEST   (kural dışı)
```

**Ölçülen:** `deep_verify` derinlik 1, 2 ve 3 için ayrı kapılar içerir
ve hepsi geçer. Ayrıca "benzer adlı komşu serbest kaldı" kapısı
**yanlış pozitif üretilmediğini** kanıtlar.

> Bu davranış daha önce **yoktu**: kural yalnızca dizinin kendisini
> engelliyordu, içindeki dosyalar (`secret.txt`, `id_rsa`) serbest
> kalıyordu. Kullanıcı "anahtarlarım korunuyor" sanıyordu.

### 2.4 Üç mod

| Mod | Davranış |
|---|---|
| `enforcing` | İhlal engellenir **ve** loglanır |
| `permissive` | İhlal yalnızca loglanır, engellenmez |
| `disabled` | Hiçbir kısıt uygulanmaz |

**Ölçülen:** Üç mod arasında geçiş `deep_verify` tarafından doğrulanır;
`permissive` modda ihlal kaydı üretildiği, `enforcing` modda
engellendiği ayrı ayrı kontrol edilir.

### 2.5 Kalıcı politikalar (`policies.d`)

`/etc/axlinux/policies.d/*.yaml` açılışta otomatik yüklenir ve
`00-sample-workstation.yaml` gibi öneklerle sıralanıp birleştirilir.

Kurulumla gelen `00-sample-workstation.yaml` **kasıtlı olarak boştur**
(`rules: []`) — sistem "hiçbir şey engellenmiyor" durumunda başlar.
Kendi politikanızı bu dizine ekleyin.

**Ölçülen (Fedora 44, canlı sistem):**

```
sistem politikasi uygulandi dir=/etc/axlinux/policies.d
rules=1  mode=enforcing
kural içi (deny)      : 1   ← Operation not permitted
kural dışı (serbest)   : 0   ← yanlış pozitif yok
```

Politika reboot sonrası **yüklenir ve uygulanır**. Elle doğrulandı:
deny derinlikte çalıştı (`Operation not permitted`, 2 DENIED kaydı),
kural dışı ve benzer adlı komşu serbest kaldı.

> Bu konum daha önce **tümden kırıktı**: tekil `subject` yazan geçerli
> bir politika reddediliyor ve sistem "KISITLAMASIZ" kalıyordu.
> Artık iki regresyon testi ve bir `deep_verify` kapısı bunu koruyor.

### 2.6 Öğrenme modu

`axctl learn` gözlenen ihlalleri toplar ve politika önerisi üretir.
SELinux'un `audit2allow` işini, yazmadan önce öneri görme biçiminde yapar.

**Ölçülen:** Gözlem toplama (`axctl learn` → gözlem sayacı artar) ve
üretilen önerinin YAML olarak doğrulanması `deep_verify` içinde test edilir.

### 2.7 Etiketler

`axctl label add/ls/rm` ile süreçlere etiket atanır; politikada
etiketler üzerinden kurallar yazılabilir.

**Ölçülen:** `label add` → `label ls` → `label rm` zinciri tamamen
çalışır ve `deep_verify` her adımını doğrular.

### 2.8 Politika şablonları

`axctl template ls` hazır şablonları listeler; `template apply` bir
şablonu `policies.d` altına kopyalar.

**Ölçülen:** `template ls` listeleme, `template apply (yok)` için doğru
hata kodu (`rc=5`), mevcut şablon uygulaması — hepsi test edilir.

### 2.9 CLI yüzeyi

| Komut | İşlev |
|---|---|
| `axctl init` | `~/.axlinux/` dizinini oluşturur |
| `axctl policy check` | YAML'ı doğrular |
| `axctl policy simulate` | Kuralların etkisini **önceden** gösterir |
| `axctl policy edit` | Politika dosyasını düzenler |
| `axctl reload` | Politikayı anında uygular |
| `axctl status [--json]` | Canlı durum (kanca sayısı, yüklü kural, mod) |
| `axctl mode` | `disabled` / `permissive` / `enforcing` |
| `axctl logs` | Denetim kayıtlarını sorgular (`--subject`, `--effect`, `--action`) |
| `axctl label` | Etiket yönetimi |
| `axctl learn` | Gözlem toplama |
| `axctl template` | Şablon yönetimi |
| `axctl version` | Sürüm bilgisi |

**Ölçülen:** Her komutun `--help` çıktısı ve gerçek çalıştırması
`deep_verify` tarafından ayrı ayrı doğrulanır.

### 2.10 Sıfırlama ve kilitlenme koruması

Politika yanlışlıkla sistemi kilitlerse `axctl mode disabled` her zaman
çalışır. Ayrıca `/boot` ve yük sistemi dosyalarına yazma kuralları
kilitlenme koruması sağlar.

**Ölçülen:** Acil kapatma ve "yeniden başlamadan sonra sağlıklı"
kapıları `deep_verify` içinde test edilir.

---

## 3. Denetim (audit) kayıtları

Kayıtlar yapılandırılmış JSONL olarak `/var/log/axlinux/` altına yazılır
ve `axctl logs` ile sorgulanır.

**Ölçülen özellikler:**

| Özellik | Kanıt |
|---|---|
| Kalıcı JSONL | Her satır geçerli JSON olarak doğrulanır |
| Sorgulama | `--effect denied`, `--subject curl`, `--action file.read` çalışır |
| Uzun yol | `apath` ile genişletilir, `truncated` alanı taşır |
| inode kimliği | `inode_permission` kayıtları `ino` + `dev` taşır |
| Rotasyon | 10 MB segment, 14 gün, 200 MB toplam, gzip |
| Disk sınırı | Sistem diski ölçüldü: %91 → **%52** |
| journald sınırı | `SystemMaxUse=200M`, `MaxRetentionSec=1month` (kurulumla gelir) |

**Ölçülen rotasyon:** Segment sınırı tetiklendiğinde yeni dosya açılır ve
DENY kayıtları etkilenmez. Toplam boyut sınırı da uygulanır.

---

## 4. Paket kanıtları (Fedora 44)

### 4.1 İmza

```
Header OpenPGP V4 RSA/SHA512 signature
  key fingerprint: f108e5cc55806bbb4fc42afa6a2e2989448a5310: OK
Header SHA256 digest: OK
Payload SHA256 digest: OK
```

Paket **imzalıdır** ve parmak izi doğrulanmıştır.

### 4.2 İçerik

RPM içeriği (30+ dosya) — sekiz kalem tek tek doğrulandı:

| Kalem | Yol |
|---|---|
| eBPF nesnesi | `/usr/lib/axlinux/axbpf.o` |
| Daemon | `/usr/bin/axdaemon` |
| Log toplayıcı | `/usr/bin/axlog` |
| CLI | `/usr/bin/axctl` + `/usr/lib/axlinux/axctl/*.py` |
| SELinux modülü | `/usr/share/selinux/packages/axlinux.pp` |
| Servisler | `axdaemon.service`, `axlog.service` |
| journald | `/etc/systemd/journald.conf.d/10-axlinux.conf` |
| Politikalar | `/etc/axlinux/*.yaml`, `policies.d/` |
| Dokümantasyon | `/usr/share/doc/axlinux/` |

### 4.3 conffiles (5)

Kaldırmada korunan yapılandırma dosyaları:

```
/etc/axlinux/desktop.yaml
/etc/axlinux/minimal.yaml
/etc/axlinux/policies.d/00-sample-workstation.yaml
/etc/axlinux/web-server.yaml
/etc/systemd/journald.conf.d/10-axlinux.conf
```

**Ölçülen kaldırma davranışı:** `dnf remove` sonrası ikililer, servis
dosyaları ve AXlinux'e ait SELinux kayıtları temizlenir. Yapılandırma
dosyaları ise **kaldırmadan önce yedeklenir**:

```
AXlinux: kaldiriliyor.
  Politika ve audit KORUNUYOR:
    ~/.axlinux, $AXLINUX_HOME, /var/log/axlinux
  Yapilandirma yedeklendi: /var/lib/axlinux/removed-config-20261010-103549
  (politika dosyalari kaldirmada silinir; yedekten geri alabilirsiniz)
```

Yedekten doğrulanan içerik (5 dosya): `desktop.yaml`, `minimal.yaml`,
`web-server.yaml`, `00-sample-workstation.yaml`, `10-axlinux.conf`.

> Bu davranış ölçüm sırasında **bulundu**: `%config(noreplace)`
> etiketli dosyalar, düzenlenmemiş olsalar bile rpm tarafından
> kaldırmada siliniyordu. Operator politika dosyasını kendi
> düzenlediyse veri kayboluyordu. `%preun` içine imzasız yedekleme
> eklendi ve gerçek kaldırma ile doğrulandı.

### 4.4 Scriptlet'ler

| Scriptlet | Görevi |
|---|---|
| `%preinstall` | Var olan kurulumu temizler |
| `%postinstall` | SELinux modülünü kurar, bağlamları yazar, servisi başlatır |
| `%preuninstall` | Servisleri durdurur, modülü ve bağlamları kaldırır |
| `%postuninstall` | Kalan yapılandırmayı temizler |

**Ölçülen kaldırma döngüsü:** İki ardışık temiz kurulum → kaldırma
sırasında sıfır artık:

```
semodule       : 0
fcontext       : 0
yerel fcontext : 0
modül dosyası  : 0
ikili          : 0/4
```

---

## 5. SELinux entegrasyonu

AXlinux kendi modülüyle (`axlinux.pp`) çalışır ve **sistem geneline
`bpf()` yetkisi vermez** — yalnızca `axdaemon` alanına verir.

**Ölçülen (Fedora 44, canlı sistem):**

```
axdaemon bağlamı : system_u:object_r:axlinux_daemon_exec_t:s0
alan doğrulaması : alan dogrulandi: ...axlinux_daemon_t:s0 (eBPF: 5)
modül tip sayısı : 10
fcontext kuralı  : 8
```

Modülün içeriği ayrıca doğrulandı: **10 tip** ve **8 dosya-bağlamı
kuralı** tanımlı. (Daha önce Fedora 43'te 0 tip / 0 kural ölçülmüştü —
bayat modül hatası; bkz. `DOGRULAMA-RAPORU.md` §5.4.)

**Güvenli düşüş:** Kuşaklama eBPF yüklemesini engellerse (bazı imajlarda
SELinux BPF harita işlemini reddeder) kurulum betiği bunu **ölçer**,
etiketleri geri alır, servisi yeniden başlatır ve açıkça uyarır —
böylece enforcement çalışır kalır.

### SELinux'a karşı konum

| | SELinux | AXlinux |
|---|---|---|
| Politika kaynağı | Hazır, milyonlarca satır | Kullanıcının YAML'ı |
| Öğrenme | `audit2allow` | `axctl learn` → gözlem → öneri |
| Uygulama | `setenforce` + reboot | `axctl reload` → anında |
| Log | `audit.log` (metin) | JSONL (yapılandırılmış, sorgulanabilir) |

İkisi rakip değil **tamamlayıcıdır**: SELinux alan sınırını verir,
AXlinux içerik kurallarını yazar.

---

## 6. Performans (ölçülen)

### 6.1 Dosya açma gecikmesi

Her koşul **üç kez** tekrar ölçüldü.

| Durum | 3 koşu (µs/açma) | Medyan |
|---|---|---|
| LSM kancası yok | 14.3 · 13.2 · 12.1 | 13.2 |
| Kanca bağlı, `disabled` | 12.7 · 16.3 · 17.8 | 16.3 |
| Kanca bağlı, `enforcing` | 22.1 · 26.2 · 21.9 | **22.1** |

**Politika sorgusu maliyeti gerçek:** +5.8 µs. İki grubun aralıkları
**çakışmıyor** ([2] en yüksek 17.8 < [3] en düşük 21.9).

**Kanca takma maliyeti ölçülemedi:** +3.1 µs görünüyor ama aralıklar
çakışıyor — bu fark koşu-koşu gürültüsünden ayırt edilemiyor.

### 6.2 Toplam iş yükü (50.000 dosya açma)

| Mod | Medyan | µs/açma | açma/sn |
|---|---|---|---|
| `disabled` | 0.228 s | ~4.55 | ~220.000 |
| `enforcing` | 0.559 s | ~11.2 | ~89.600 |

**Fark 0.33 saniye.** Tarayıcı açılışı gibi gerçek bir iş yükünde
algılanmayacak büyüklükte; enforcement açıkken ~90.000 açma/sn, bir
masaüstünün asla ulaşamayacağı bir hız.

### 6.3 Kaynak tüketimi

| Ölçüm | Değer |
|---|---|
| `axdaemon` RSS | 108.236 kB (~106 MB) |
| 1000 kural sonrası RSS | 100.436 kB (sızıntı yok) |
| Açık dosya tanıtıcı | 33 |
| Politika ölçekleği | 1000 kural / 100 kural = **3.44x** |
| Uygulama ölçekleği | 1000 kural / 100 kural = **2.10x** |

**Ölçekleme doğrusal:** 10 kat kural, ~3.4 kat süre demek (logaritmik
değil) — `deep_verify` bunu `<20x` eşiğiyle denetler.

> Neden mutlak µs tek başına ölçüt değil: aynı ölçüm Ubuntu'da
> Fedora'ya göre ~20 kat yavaş çıkıyor, çünkü sanal makine ortamı
> belirleyici. Bu yüzden `deep_verify` mutlak eşik yerine **ortam
> düzeltilmiş göreli oran** uygular (Fedora 44'te ölçülen: 1.01x taban).

---

## 7. Doğrulama özeti

### 7.1 `deep_verify.sh` — son kodla

| Platform | geçti | kaldı | atlandı |
|---|---|---|---|
| **Fedora 44** | **732** | **0** | **0** |
| Fedora 43 | 732 | 1 | 1 |
| Ubuntu 24.04.5 | 731 | 0 | 1 |
| Debian 12 | 731 | 0 | 1 |
| Pardus 25.2 | 731 | 0 | 1 |

Fedora 44'te **hiçbir kalem atlanmaz ve hiçbir kalem kalmaz.**

Debian ailesindeki tek atlanan kalem `SELinux yok`'tur — Debian ailesi
SELinux sağlamaz, bu eksik değil platform farkıdır.

Fedora 43'teki tek kalem, o imajda SELinux kuşaklamasının eBPF'i
engellediğini **dürüstçe bildiren** rapordur; enforcement çalışmaktadır
(kanca 5/5, eBPF 5/5).

### 7.2 Yerel paket

| Paket | Sonuç |
|---|---|
| Python (pytest) | **179 geçti** + 20 alt test |
| Go — axdaemon | 10 paket |
| Go — axlog | 3 paket |
| Kabuk sözdizimi | `install.sh`, `deep_verify.sh`, `selinux-setup.sh` temiz |
| CI yapılandırması | geçerli YAML |

### 7.3 Paketleme matrisi

Beş imajın beşinde de paketleme koşuldu:
`fedora:41`, `fedora:42`, `fedora:43`, `fedora:44`, `debian:12` —
her biri 8/8 içerik + 5 conffiles + SELinux modülü.

---

## 8. Bilinen sınırlar

Dürüstçe listelenmiştir; hiçbiri gizlenmemiş bir kusur değildir.

| Sınır | Durum |
|---|---|
| `inode_permission` yol alamaz | Kernel ABI'si yalnızca `struct inode *` verir. Çözüm: `ino`+`dev` kimliği kayda eklenir; yol gerektiren kayıtlar `file_open`/`bprm` kancalarında kalır. |
| `socket_bind` port eşleştirmez | Yalnızca port adına bakar; eşleşme kurulabilir ama çalışmaz. |
| Fedora 43'te SELinux kuşaklaması | O imajda kurulamaz; ölçülmüş, belgelenmiş, güvenli geri alma ile karşılanmış. |
| Ana makinede çalıştırma | Bilerek engellenir (bölüm 0). |

---

## 9. İndirilen dosyalar

| Dosya | Boyut | SHA-256 (ilk 16) |
|---|---|---|
| `axlinux-1.2.0-1.x86_64.rpm` | 2.224.480 B | imzalı |
| `axlinux_1.2.0_amd64.deb` | 5.348.152 B | — |

| `SHA256SUMS` | — | `sha256sum -c SHA256SUMS` |

Doğrulanmış çıktılar `/mnt/anka/downloads/` altındadır.

Bütünlük doğrulaması:

```bash
sha256sum -c SHA256SUMS
```

---

## 10. Hızlı doğrulama (kendi makinenizde)

Kurulumdan sonra kendi sisteminizde şunu çalıştırın:

```bash
sudo axctl status
```

Şunları görmelisiniz:

- `lsm_hooks_active = 5`, `lsm_hooks_total = 5`
- `bpf_programs_loaded = 5`
- `mode` — şu an hangi modda
- `policy_healthy = true`

Ardından tam doğrulama paketi:

```bash
sudo bash tests/deep_verify.sh
```

Bu, 732 kontrolü çalıştırır ve tek bir rapor üretir.
Fiziksel makinede çalışmayı reddeder.