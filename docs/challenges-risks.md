# AXlinux Zorluklar ve Riskler

## Teknik Zorluklar

### 1. eBPF LSM Koşulları

**Zorluk**: `CONFIG_BPF_LSM=y` ve kernel 5.15+ gerektirir.

**Çözüm**:
- Kernel < 5.15'te graceful fallback: "AXlinux sadece audit modunda çalışıyor"
- Dağıtım bazlı ön kontrol: `axctl check-kernel`
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
- İmza doğrulama (v0.5+)
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

## Sınırlamalar (v0.1)

| Özellik | v0.1 | Not |
|---------|------|-----|
| Dosya kancası | ✓ | file_open, inode_permission |
| exec kancası | ✓ | bprm_check_security |
| ağ kancası | ✓ | socket_connect, socket_bind |
| signal kancası | ✗ | v0.2 |
| user bazlı kural | ✗ | v1.0 |
| zaman kuralı | ✗ | v2.0 |
| container | ✗ | v1.0 |
| GUI | ✗ | v1.5 |
| AI öneri | ✗ | v2.0 |

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
