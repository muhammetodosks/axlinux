# Güvenlik Notu — Lisansın Parçası Değildir

Bu dosya lisansın **parçası değildir**. Lisans metni için [LICENSE](LICENSE)
dosyasına bakın (MIT).

## Neden ayrı?

AXlinux bir **Mandatory Access Control** sistemidir. Yanlış yazılmış bir
politika sizi kendi sisteminizden kilitleyebilir. Bu bir hata değil, tasarımın
doğal sonucudur — ama lisansın altında durması, lisans koşullarını okuyan
birinin bu uyarıyı kaçırmasına yol açabilirdi.

Bu yüzden uyarı burada, ayrı ve açık bir dosyada durur.

## Enforcing uygulamadan önce

```bash
axctl policy check      # 1. sözdizimi ve anlam doğrulaması
axctl policy simulate  # 2. etkiyi ÖNCEDEN gör
axctl mode permissive   # 3. loglar, engellemez
axctl reload            # 4. uygula
axctl status            # 5. gerçek durumu doğrula
```

Bu sırayı atlarsanız sistemi kilitleyebilirsiniz.

## Acil çıkış

```bash
sudo axctl mode disabled
```

Bu komut **her zaman** çalışır, tüm kısıtları kaldırır ve yeniden
başlatma gerektirmez.

## Fiziksel makine koruması

AXlinux fiziksel makinede çalışmayı **reddeder**. Bu bir eksik değil,
bilinçli bir güvenlik sınırıdır: testler de üretim de sanal makine
gerektirir.

## Ayrıntı

- [SECURITY.md](SECURITY.md) — güvenlik açığı bildirimi
- [README.md](README.md#güvenlik) — güvenli uygulama sırası