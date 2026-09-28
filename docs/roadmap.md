# AXlinux Yol Haritası

## v0.1 — Temel (MVP)

**Hedef**: YAML parser + axctl + eBPF dosya kancası

- [x] YAML politika dili tasarımı
- [x] axctl CLI (init, policy edit, check, reload, status, logs)
- [x] axc derleyici (YAML → JSON)
- [x] axdaemon (Go) — temel daemon
- [x] axbpf (C) — file_open kancası
- [x] axlog (Go) — JSON audit log
- [ ] eBPF map yöneticisi
- [ ] Temel dokümantasyon
- [ ] Test senaryoları

**Çıktı**: Kullanıcı yaz, AXlinux dosya erişimini kontrol etsin.

## v0.2 — Simülatör

**Hedef**: "Bu YAML neyi etkiler?" göster

- [x] axctl policy simulate
- [ ] Kural öncelik sıralaması
- [ ] Çakışma tespiti
- [ ] Etkilenen işlemler listesi

**Çıktı**: Kullanıcı politika yüklemeden önce sonucu görsün.

## v0.3 — Öğrenme Modu

**Hedef**: Sistem izle, 3 gün sonra YAML öner

- [x] axctl learn start
- [x] axctl learn report
- [ ] eBPF syscall tracing
- [ ] Pattern recognition
- [ ] Öneri motoru (basit ML)
- [ ] Onay akışı

**Çıktı**: Kullanıcı "öğren" desin, AXlinux politika önerisi sunsun.

## v0.4 — Şablonlar

**Hedef**: Önceden tanımlı politika kalıpları

- [x] axctl template ls
- [x] axctl template apply
- [ ] minimal, web-server, desktop, database şablonları
- [ ] Şablon paylaşımı (git)
- [ ] Özel şablon oluşturma

**Çıktı**: Kullanıcı "şablon uygulayınca" hızlıca başlasın.

## v0.5 — Topluluk ve İmza

**Hedef**: Güvenilir politika paylaşımı

- [ ] axctl trust add
- [ ] axctl policy install
- [ ] Ed25519 imzalama
- [ ] İmza doğrulama
- [ ] Topluluk repo (github.com/axlinux/policies)

**Çıktı**: Kullanıcı topluluk politikalarını güvenle kullanabilsin.

## v1.0 — Container/K8s

**Hedef**: Modern altyapı entegrasyonu

- [ ] Kubernetes CRD (AxPolicy)
- [ ] Docker security-opt
- [ ] Pod security policy
- [ ] Containerd hook
- [ ] Helm chart
- [ ] Operator

**Çıktı**: K8s cluster'da pod bazlı politika.

## v1.5 — GUI

**Hedef**: Masaüstü yönetim arayüzü

- [ ] Qt/GTK GUI (axctl-gui)
- [ ] Politika editör (syntax highlighting)
- [ ] Simülasyon görselleştirme
- [ ] Log dashboard
- [ ] Sistem tray ikonu

**Çıktı**: Kullanıcı komut satırı olmadan yönetebilsin.

## v2.0 — AI Destekli

**Hedef**: Yapay zeka ile politika önerisi

- [ ] LLM entegrasyonu (önceden eğitilmiş)
- [ ] "Bu işlem için politika öner" → LLM
- [ ] Anormal davranış tespiti
- [ ] Otomatik politika güncelleme
- [ ] Doğruluk onay akışı

**Çıktı**: Kullanıcıya akıllı öneriler.

## Süre Tahmini

| Versiyon | Süre | Ekip |
|----------|------|------|
| v0.1 | 2 ay | 2 kişi |
| v0.2 | 1 ay | 2 kişi |
| v0.3 | 2 ay | 3 kişi |
| v0.4 | 1 ay | 2 kişi |
| v0.5 | 1 ay | 2 kişi |
| v1.0 | 3 ay | 4 kişi |
| v1.5 | 2 ay | 3 kişi |
| v2.0 | 3 ay | 4 kişi |

**Toplam**: ~15 ay (v0.1 → v2.0)

## Başarı Kriterleri

### v0.1
- 100 kullanıcı, 1000 indirme
- 5 GitHub issue, 2 PR
- 1 blog yazısı

### v1.0
- 10K kullanıcı
- 100 yıldız
- 10 topluluk politikası
- 1 dağıtım partneri

### v2.0
- 100K kullanıcı
- 1K yıldız
- 100 topluluk politikası
- 5 dağıtım partneri
- 1 kurumsal kullanıcı
