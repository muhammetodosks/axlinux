# Güvenlik Politikası

## Desteklenen sürümler

| Sürüm | Durum |
|---|---|
| 1.2.0 | ✅ Destekleniyor |
| < 1.2.0 | ❌ Desteklenmiyor |

## Açık bildirim

**Lütfen herkese açık GitHub issue açmayın.** Herkese açık bir issue,
kullanılmadan önce tüm dünyaya detayı verir.

Bunun yerine e-posta gönderin:

```
guvenlik@axlinux.invalid
```

> Bu adres örnek amaçlıdır. Yayımlamadan önce gerçek, sizin
> kontrolünüzde bir adresle değiştirin.

## Ne bildirilmeli

- Erişim denetiminin **atlanmasına** yol açan hatalar
- Politika ayrıştırma hataları (geçersiz politikanın kabul edilmesi)
- Denetim kaydı kaybı veya yanlış kayıt
- Kurulum/kaldırma sırasında sistemin kırılması
- `axdaemon`'ın beklenmedik ayrıcalıklarla çalışması

## Ne bildirilmeye gerek yok

- Politikanın beklendiği gibi çalışmaması ama güvenlik açığı
  **oluşturmaması** durumu
- `inode_permission` kancasının yol döndürememesi (bilinen yapısal sınır)
- Performans gözlemleri

## Süreç

1. **Onay** — 48 saat içinde bildirimi aldığımızı doğrularız.
2. **Değerlendirme** — hatayı yeniden üretir, etkisini belirleriz.
3. **Düzeltme** — kök nedeni kapatırız; yüzeysel yama yapmayız.
4. **Doğrulama** — düzeltme gerçek sistemde yeniden ölçülür.
5. **Yayım** — düzeltme yayımlanır, ardından bildirimi kamuya açabiliriz.

## Acil çıkış (kullanıcılar için)

Yanlışlıkla kilitlenirseniz:

```bash
sudo axctl mode disabled
```

Bu komut her zaman çalışır ve tüm kısıtları kaldırır. Yeniden
başlatmaya gerek yoktur.

## Güvenlik modeli hakkında

AXlinux bir **Mandatory Access Control** sistemidir. Yanlış yazılmış bir
politika sizi kendi sisteminizden kilitleyebilir. Bu bir hata değil,
tasarımın doğal sonucudur — bu yüzden güvenli uygulama sırası
(`policy check` → `simulate` → `permissive` → `reload`) bu sırayla
verilmiştir.

Ayrıntı: [README.md](README.md#acil-çıkış)