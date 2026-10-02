# AXlinux Kullanıcı Senaryoları

## Senaryo 1: İlk Kurulum

```bash
# Kurulum
sudo apt install axlinux

# Başlat
axctl init

# Durum
axctl status
# → Mod: enforcing, boş politika, sistem serbest

# Politika yaz
axctl policy edit
```

## Senaryo 2: Shadow Dosyasını Koru

Kullanıcı, tarayıcıların `/etc/shadow` okumasını engellemek istiyor.

```bash
# policy.yaml dosyasını düzenle
axctl policy edit

# İçerik:
# version: 1
# mode: enforcing
# rules:
#   - name: "tarayıcılar shadow okuyamaz"
#     subject: firefox
#     object: /etc/shadow
#     action: file.read
#     effect: deny

# Doğrula
axctl policy check
# → ✓ Geçerli

# Simüle et
axctl policy simulate
# → firefox, /etc/shadow okuyamaz

# Uygula
axctl reload
# → ✓ Yüklendi

# Test et
cat /etc/shadow  # root ile
# → firefox bu dosyayı okuyamaz
```

## Senaryo 3: Web Sunucusu Kilitli

Kullanıcı, nginx'in sadece `/var/www` okuyabilmesini istiyor.

```bash
axctl policy edit

# İçerik:
# version: 1
# mode: enforcing
# rules:
#   - name: "nginx web içeriğini okur"
#     subject: nginx
#     object: /var/www
#     action: file.read
#     effect: allow
#   - name: "nginx shadow okuyamaz"
#     subject: nginx
#     object: /etc/shadow
#     action: file.read
#     effect: deny
#   - name: "nginx bash çalıştıramaz"
#     subject: nginx
#     action: process.exec
#     object: /bin/bash
#     effect: deny

axctl policy check
axctl reload

# nginx artık:
# → /var/www/* okuyabilir
# → /etc/shadow okuyamaz
# → bash çalıştıramaz
```

## Senaryo 4: Öğrenme Modu

Kullanıcı, sistemin nasıl davrandığını öğrenmek istiyor.

```bash
# Öğrenmeyi başlat
axctl learn start
# → Sistem 3 gün izlenecek

# 3 gün sonra rapor al
axctl learn report

# Örnek çıktı:
# Öğrenme Raporu (3 gün)
# ======================
#
# Gözlemlenen işlemler:
#
# nginx (web sunucusu):
#   → /var/www/* okudu (1.247 kez)
#   → /etc/nginx/nginx.conf okudu (89 kez)
#   → /var/log/nginx/* yazdı (456 kez)
#   → 80 ve 443 portlarına bind oldu
#
# firefox (tarayıcı):
#   → ~/ indirdi (345 kez)
#   → /etc/shadow okumaya çalıştı (3 kez) ← ENGELLENDİ
#   → 500+ farklı host'a bağlandı
#
# Önerilen politika:
#
# rules:
#   - name: "nginx web içeriğini okur"
#     subject: nginx
#     object: /var/www
#     action: file.read
#     effect: allow
#   - name: "nginx kendi loglarını yazar"
#     subject: nginx
#     object: /var/log/nginx
#     action: file.write
#     effect: allow
#   - name: "firefox shadow okuyamaz"
#     subject: firefox
#     object: /etc/shadow
#     action: file.read
#     effect: deny
```

## Senaryo 5: Permissive Mod (Geliştirme)

Geliştirici, politikanın ne yapacağını görmek ama engellememek istiyor.

```bash
axctl mode permissive
# → Mod: permissive (ihlal = sadece log)

# Test et
axctl policy simulate

# İhlalleri izle
axctl logs --follow --filter deny

# Hazır olduğunda
axctl mode enforcing
```

## Senaryo 6: Ağ Kısıtlaması

```bash
axctl policy edit

# python dışarı çıkamaz
# rules:
#   - name: "python dışarı çıkamaz"
#     subject: python
#     action: net.connect
#     effect: deny

axctl reload

# python artık:
# → socket() çağırdığında connect() engellenir
# → bind() yapamaz
# → Sadece Unix socket iletişimi mümkün
```

## Senaryo 7: Hata ve Kurtarma

Kullanıcı yanlış politika yazdı.

```bash
axctl policy edit

# Yanlış içerik:
# rules:
#   - name: "her şeyi engelle"
#     subject: "*"
#     action: "*"
#     effect: deny

axctl policy check
# → ✗ Hata: subject "*" sadece deny için kullanılabilir

# Simüle et
axctl policy simulate
# → ⚠ DİKKAT: Bu politika sistemi kilitleyebilir!

# Kullanıcı düzeltir
axctl policy edit

# Doğru içerik
axctl policy check
axctl reload
```

## Senaryo 8: Acil Durum Çıkışı

Kullanıcı sistemi kilitledi.

```bash
# Her zaman çalışır
axctl mode disabled
# → Tüm kısıtlamalar kaldırıldı

# Veya
axctl reload --force-empty
# → Boş politika yüklendi, sistem serbest
```

## Senaryo 9: Container Kullanımı (v1.0)

```bash
# Container'a politika ver
docker run --security-opt axpolicy=./nginx-policy.yaml nginx

# veya
kubectl apply -f axpolicy.yaml
# → Pod'a AXlinux politikası uygulanır
```

## Senaryo 10: Topluluk Politikası (GELECEK — henüz yok)

> **Bu senaryo bir tasarım hedefidir; aşağıdaki komutlar
> çalışmaz.** Uzak politika güvenliği henüz uygulanmadı.
> Bugün kendi `~/.axlinux/policy.yaml` dosyanı yaz.

```bash
# Güvenilir kaynak ekle
axctl trust add https://github.com/axlinux/policies

# Politika yükle
axctl policy install nginx-hardened

# Doğrula
axctl policy verify nginx-hardened
# → ✓ İmza geçerli

# Uygula
axctl policy use nginx-hardened
axctl reload
```
