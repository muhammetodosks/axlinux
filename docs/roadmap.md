# AXlinux Yol Haritası

Bu belge **gerçekte neyin yapıldığını** gösterir. Önceden sürüm
numaralarıyla etiketlenmiş ve uygulanmış özellikleri yapılmamış
işaretliyordu; sürüm 1.0.0 olduğunda bu yanlış izlenim bırakıyordu.

## 1.0.0 — Tamamlanan

### Çekirdek

- [x] YAML politika dili (etiket, joker subject, öncelik)
- [x] `axctl` CLI: `init`, `status`, `reload`, `mode`, `logs`,
      `label add|ls|rm`, `learn start|stop|report`,
      `template ls|apply`, `policy edit|check|simulate`, `version`
- [x] `axdaemon` (Go): LSM kancaları, eBPF map yönetimi, JSON-RPC
- [x] `axlog` (Go): kalıcı JSONL audit, günlük sıkıştırma
- [x] `axbpf` (C): 5 LSM kancası

### Doğrulama

- [x] Kapsamlı test paketi (`tests/deep_verify.sh`, 10 bölüm / 100 denetim)
- [x] Fiziksel makine koruması (test VM dışında çalışmayı reddeder)
- [x] Python ↔ Go ↔ eBPF sözleşme testleri
- [x] Belge–CLI denetimi (`tests/test_docs.py`)
- [x] Üç dağıtımda uçtan uca doğrulama: Ubuntu 24.04.5,
      Debian 12, Pardus 25.2

### Politika dili

- [x] Kural öncelik sıralaması (`priority`)
- [x] Çakışma tespiti (aynı hedefe farklı etki)
- [x] Yinelenen kural tespiti
- [x] Uygulanabilirlik denetimi (uygulanamayan kural reddedilir)
- [x] `policy check -f` ile aday politika doğrulama
- [x] `policy simulate` ile etki analizi

### Öğrenme modu

- [x] Olay akışından gözlem toplama (`learn_map`)
- [x] Pattern aggregation (konu + nesne + eylem)
- [x] Öneri motoru: yapıştırılabilir YAML üretimi
- [x] Süreli çalışma (`--days`), otomatik kapanma

### Güvenlik

- [x] 29 korumalı süreç (kilitlenme koruması)
- [x] Uygulanamayan kural uyarı değil **hata** (sessiz etkisizlik yok)
- [x] Boş politika geçerli → `reload --force-empty` acil kurtarma yolu
- [x] Kalıcı audit; yazma hatası sayacı ve `audit_healthy`
- [x] Dağıtım bağımsız kurulum (apt/dnf/pacman/apk/zypper)
- [x] Çalışma zamanı bağımlılık sözleşmesi (`requirements.txt`)

## Gelecek

Bu listeye giren hiçbir özellik **yoktur**. Sürüm numarası
verilmedi: tarih vermek, planlanmayan bir şeyi vaat etmek olurdu.

### Yüksek öncelik

- [ ] `net.accept` desteği — `lsm/socket_accept` kancası bağlıysa
- [ ] Silme/oluşturma denetimi — `lsm/inode_unlink_at` kancası
- [ ] Kullanıcı bazlı kurallar — kuralın öznesi kullanıcı olsun
- [ ] `sudo` bağlamı — `sudo -u` ile çalışan süreçler ayrıştırılsın

### Orta öncelik

- [ ] Zaman/koşul kuralları — "her gün 09:00-18:00 arası"
- [ ] Politika imzalama ve doğrulama
- [ ] Uzak politika kaynakları (`trust`, `policy install`)
- [ ] Olay tabanlı kurallar — "bu dosya değişirse"
- [ ] Sıcak yeniden yükleme (daemon yeniden başlatmadan)

### Düşük öncelik

- [ ] Container kapsamı (yalnız bir container'ı denetleme)
- [ ] Grafik arayüz
- [ ] Sinyal kancası (`lsm/signal`)

## Bilinçli olarak yapılmayanlar

Bunlar eksiklik değil, **karardır**:

- **İmzasız uzak politika çekme.** İmza doğrulama yarım kalmış bir
  güvenlik özelliği, hiç olmamasından daha kötüdür. Ya imza
  doğrulama tam olur ya da uzak politika yükleme hiç yapılmaz.
- **Sessizce etkisiz kurallar.** Bir kuralın çalışmayacağı kanıtlanabiliyorsa
  (`bash`'a kural, 8'den derin yol, kancasız aksiyon) politika
  reddedilir. Kullanıcı bir kuralın yüklendiğini sanıp sistemi
  korumalı sandığında, uyarı yetmez.
- **Kilitlenmeye izin vermek.** 29 kurtarma yolu süreci hiçbir kurala
  tabi değildir. Bu bir ödün değil, kullanılabilirliğin şartıdır.