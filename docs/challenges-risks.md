# AXlinux Zorluklar ve Riskler

## Kritik Risk: Sistem Kilitlenmesi (Lockout)

**Bu, AXlinux'in en tehlikeli hata modudur ve tasarım gereği mühürlenmiştir.**

Bir kural `bash`, `sudo`, `sshd` veya `systemd` gibi kritik bir sürece
uygulanırsa sistem kendini kilitler: o sürecin tüm çocuk süreçleri
engellenir, oturum kapanır ve kullanıcı sisteme erişemez. Bu shell'den
kurtarma mümkün değildir; yalnızca fiziksel reboot gerekir.

**Önlem** (`ax_protected`, `src/bpf/axbpf.h`):

Aşağıdaki süreçler **hiçbir kurala tabi değildir**; programlar onlar için
doğrudan `0` döner. Policy "bash /bin/echo çalıştıramaz" dese bile:

- `bash`, `sh`, `dash`, `zsh`, `fish` — kullanıcı oturumu açık kalır
- `sudo`, `su`, `doas` — mod değiştirilebilir, müdahale edilebilir
- `sshd`, `login`, `agetty` — uzaktan/yerel bağlantı mümkün kalır
- `systemd`, `dbus-daemon`, `polkitd`, `NetworkManager` — oturum ve
  ağ çalışmaya devam eder

Liste **bilinçli olarak kısadır**: yalnızca **kurtarma yolunu**
kapsar. Her aday şu sorudan geçer:

> "Engellersem sisteme tekrar erişebilir miyim?" → hayır ise korunur.

Bu soru neden tek başına yeterli: **dil çalıştırıcıları korunmaz.**
`python3`, `node`, `perl`, `ruby`, `npm` listede değildir.

Çünkü çoğu gerçek uygulama bir yorumlayıcıdan çalışır. Onları
korumak "python3 /etc/shadow okuyamaz", "node ağa çıkamaz" gibi MAC'in
en sık kullanılan kurallarını yazılamaz hâle getirirdi — ürün
kullanılamaz olurdu. Ve kazanılan tek şey sıfırdı: bir yorumlayıcıyı
engellemek kilitlenme **yaratmaz**, çünkü kullanıcı zaten korumalı bir
kabuğa sahiptir.

Buna karşılık `firefox`, `nginx`, `curl` gibi uygulamalar da listede
değil — onlar zaten hedef.

**Doğrulama**: `tests/test_protection.py` korunan ve korunmaması
gereken süreçleri statik olarak denetler (her iki yönde);
`tests/verify_all.sh` adım 8'de canlı olarak kanıtlar.

**Politika yazarken**: `subject` alanına `bash`, `sudo`, `systemd`
gibi bir süreç adı yazmak **yükleme anında hata verir**; kural hiç
yazılmaz. `python3` gibi bir yorumlayıcı yazmak ise normaldir ve
kurallar uygulanır.

## Teknik Zorluklar

### 1. eBPF LSM Koşulları

**Zorluk**: `CONFIG_BPF_LSM=y` ve kernel 5.15+ gerektirir.

**Çözüm**:
- Kernel < 5.15'te graceful fallback: "AXlinux sadece audit modunda çalışıyor"
- Dağıtım bazlı ön kontrol: `bash install.sh` 2. adımı (Ortam denetimi) ve `axctl status`
- Ubuntu 22.04+, Fedora 35+, Debian 12+ desteklenir

**Risk**: Eski distro'larda çalışmaz.

### 2. eBPF Map Boyutu

**Zorluk**: eBPF map'leri sınırlı boyutta (genelde ~16MB).

**Çözüm**:
- Sadece aktif politikayı tut (tüm sistemi değil)
- LRU map kullan (en az kullanılanı at)
- Politika compression (gzip)

**Risk**: Çok büyük politikalar (~10K+ kural) tutmayabilir.

### 3. Process Adı Çakışması

**Zorluk**: `comm` sadece 16 karakter. `google-chrome` → `google-chrome` (tam), `nginx: worker` → `nginx`.

**Çözüm**:
- Prefix matching
- PID tracking (geçici)
- Label'lara alternatif: executable path (`/usr/bin/python3`)

**Risk**: Yanlış process eşleşmesi.

### 4. Path Resolution

**Zorluk**: eBPF'de path çözümleme zor. `~/.ssh` → `/home/user/.ssh` dönüşümü kernel'de yapılamaz.

**Çözüm**:
- Kullanıcı tarafında ön işleme: `~` → ev dizini
- eBPF'de sadece prefix matching
- `realpath()` syscall hook (gelecek)

**Risk**: Sembolik link'ler ve `..` path'leri atlanabilir.

### 4.1. `bpf_d_path` Kullanılamaz (kritik)

**Belirti**: Derleme ve yükleme başarılı, 5/5 kanca bağlı, daemon
`enforcement_active: true` ve "1 kural yüklendi" diyor — ama **hiçbir
yol kuralı tutmuyor**, audit boş.

**Kök neden**: `bpf_d_path` bu projede kullanılamaz. libbpf 1.3.0 onu
global bir fonksiyon işaretçisi olarak tanımlar; BPF'ye çağrı olarak
derlendiğinde hedef tampona yazım **iki konuma birden** düşer:

- doğru offset (yol alanı)
- **242 byte kaymış** ikinci bir konum

Sonuç: `comm` ve `action` doğru, `path` alanı çöplü → hash hiç eşleşmez.
Kural "yüklendi" görünür ama hiçbir şey engellenmez. Bu, MAC'te en
kötü hata biçimidir: **sessiz başarısızlık**.

Kanıt, çekirdeğin ürettiği 276 baytın Go'nun yazdığı 276 baytla
bayt bayt karşılaştırılmasıyla elde edildi; iki metin aynı görünüyordu
(`comm=cat`, `path=/etc/hostname`) ama ham baytlar offset 242'den
itibaren ayrışıyordu.

**Çözüm** (`ax_fill_path`, `src/bpf/axbpf.h`): yol alanı 8 sabit bloğa
bölünür (`char path[8][32]`), her bileşen kendi bloğuna yazılır.
Bölme ve birleştirme Go tarafında yapılır. Toplam anahtar boyutu
değişmez: 16 + 8×32 + 4 = **276 byte**.

**Tasarım kuralları** (bu çözümü bozmadan önce bilin):

1. **Hedef ve boyut sabit olmalı.** `bpf_probe_read_kernel(dst, len, src)`
   için `dst` ve `len` derleme zamanında sabitse verifier sınırı görür.
   Çalışma anında hesaplanan `dst[pos]` reddedilir.
2. **Her iki geçiş de unroll'lenmeli.** Runtime döngüde verifier döngü
   gövdesini her yineleme için yeniden doğrular; 63 × program boyutu
   1M instruction sınırını aşar. İç içe unroll ise 512 byte stack
   sınırını aşar.
3. **`bpf_probe_read_kernel_str` kullanmayın.** İçinde 256 adımlık gizli
   bir unroll vardır; slot başına çağrıldığında programı 40 kat şişirir.
   Sabit boyutlu `bpf_probe_read_kernel` + elle NUL aynı işi yapar.
4. **Kök bileşen yazılmaz.** Go tarafı kök içeriği üretmez; eBPF tarafı
   de yazmaz, aksi halde blok 0'da `"//"` oluşur ve anahtarlar eşleşmez.
5. **`bpf_map_lookup_elem` sonrası harici pointer yazma yapılmaz.**
   Verifier pointer'ı "unbounded" işaretler. Bu yüzden audit alanları
   map aramasından **önce** doldurulur.

**Sözleşme kilidi**: `struct policy_key` ve `struct audit_event`
boyutları C tarafından bağımsız hesaplanıp Go struct ile
karşılaştırılır (`internal/maps/contract_test.go`,
`internal/audit/audit_test.go`). Bu testler düz (256 byte) ve bloklu
(8×32) dizi düzenlerini ikisini de tanır.

### 5. Performans

**Zorluk**: Her sistem çağrısında eBPF map araması.

**Çözüm**:
- LRU cache map
- First-hit kısa devre
- Per-CPU map'ler (lock-free)

**Risk**: ~1-3% overhead kabul edilebilir.

### 6. Audit Log Patlaması

**Zorluk**: enforcing modda binlerce deny/saat.

**Çözüm**:
- Rate limiting (kural başına max 1 log/sn)
- Aggregate log (aynı kural+obje → tek log)
- Ring buffer (son 10K kayıt)

**Risk**: Log disk'i dolar.

## Güvenlik Zorlukları

### 7. Kullanıcı Yanlışlığı

**Zorluk**: Kullanıcı kendini kilitler.

**Çözüm**:
- Simulate modu (her zaman ücretsiz)
- `axctl mode disabled` her zaman çalışır
- `axctl reload --force-empty` acil çıkış
- Config backup (her reload'den önce)

**Risk**: Kullanıcı sistemi başlatamaz hale getirebilir.

### 8. eBPF Program Güvenliği

**Zorluk**: eBPF programları kernel çekirdeğinde çalışır.

**Çözüm**:
- Verifier (eBPF verifier zaten var)
- Minimal C, sadece LSM kancaları
- `CAP_BPF` yetkisi gerekli

**Risk**: eBPF programı bug'lı ise kernel panic.

### 9. Yetki Yükseltme

**Zorluk**: root her şeyi geçer.

**Çözüm**:
- AXlinux sadece non-root kullanıcı için anlamlı
- Root için sadece audit log
- `CAP_BPF` olmadan politika yüklenemez

**Risk**: Root AXlinux'u bypass eder.

### 10. Politika Bütünlüğü

**Zorluk**: Kullanıcı politika dosyasını değiştirirse AXlinux fark edemez (reload'den sonra).

**Çözüm**:
- Politika dosyası hash'i (her reload'de kontrol)
- İmza doğrulama (gelecek)
- Read-only politika dosyası (opsiyonel)

**Risk**: Kullanıcı kendi politikasını değiştirip yeniden yükleyebilir (ama bu zaten kendi sorumluluğunda).

## Operasyonel Zorluklar

### 11. Öğrenme Modu Yanlış Öneri

**Zorluk**: 3 günlük öğrenme, yanlış politika önerebilir.

**Çözüm**:
- Öneri her zaman "öneri"dir, otomatik uygulanmaz
- Kullanıcı onayladığında uygulanır
- Geliştirici modu: permissive + log

**Risk**: Yanlış öneri kullanıcıyı yanlış yönlendirebilir.

### 12. Uyumluluk

**Zorluk**: Mevcut SELinux/ApArmor politikaları ile çakışma.

**Çözüm**:
- AXlinux sadece kendi politikasını uygular
- Diğer MAC sistemleri ile birlikte çalışabilir (üst üste)
- Migration tool: SELinux → AXlinux (gelecek)

**Risk**: İki MAC sistemi birlikte çalışabilir ama karmaşıklık artar.

### 13. Dağıtım

**Zorluk**: Kurulum, kernel modülü, daemon, CLI.

**Çözüm**:
- Tek binary (axctl + axdaemon)
- `apt install axlinux` veya `dnf install axlinux`
- systemd unit: `axdaemon.service`

**Risk**: Dağıtım bazlı farklılıklar.

## Sınırlamalar (1.0.0)

Bu tablo **1.0.0'da gerçekte neyin çalıştığını** listeler. Önceden
sürüm numarasıyla etiketlenmişti ve sürüm 1.0.0 olduğunda yanlış
izlenim bırakıyordu: tablo "user bazlı kural ✗ 1.0" derken biz
zaten 1.0.0'dayız.

| Özellik | Durum | Not |
|---------|-------|-----|
| Dosya kancası | ✓ | `file_open`, `inode_permission` |
| exec kancası | ✓ | `bprm_check_security` |
| ağ kancası | ✓ | `socket_connect`, `socket_bind` |
| signal kancası | ✗ | yok, LSM'de karşılığı bağlı değil |
| `net.accept` | ✗ | `socket_accept` kancası bağlı değil |
| `file.delete` / `file.create` | ✗ | silme/oluşturma kancası yok |
| user bazlı kural | ✗ | kural **süreç** adına konuşur, kullanıcıya değil |
| zaman/koşul kuralı | ✗ | politika dili koşul içermiyor |
| container kapsamı | ✗ | kapsam sistem geneli |
| Grafik arayüz | ✗ | CLI ve YAML; GUI yok |
| İmzalı politika dağıtımı | ✗ | tek politika kaynağı: kendi dosyan |

## Kabul Edilebilir Riskler

1. **eBPF overhead**: ~1-3% — Kabul edilebilir
2. **Sınırlı map boyutu**: ~10K kual — Yeterli
3. **Root bypass**: Kabul edilebilir (root zaten her şeyi yapabilir)
4. **Kernel 5.15+ gereksinimi**: Kabul edilebilir (2026 itibarıyla çoğu distro)

## Kabul Edilemeyen Riskler

1. **Kernel panic**: eBPF programı asla kernel panik yapmamalı.
2. **Veri kaybı**: AXlinux hiçbir veri silmez.
3. **Backdoor**: AXlinux'da backdoor olmamalı.
4. **Politika imyası**: Kullanıcı her zaman kendi politikasını değiştirebilmeli.
