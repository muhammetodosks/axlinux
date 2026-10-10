---
name: Hata bildirimi
about: Bir şey beklendiği gibi çalışmıyor
labels: bug
---

## Ne oldu

<!-- Kısa açıklama -->

## Ne bekliyordunuz

<!-- Beklenen davranış -->

## Nasıl yeniden ürettiniz

```bash
# Tam olarak çalıştırdığınız komutlar
```

## Ortam

| Bileşen | Değer |
|---|---|
| İşletim sistemi | |
| Çekirdek | `uname -r` |
| LSM zinciri | `cat /sys/kernel/security/lsm` |
| AXlinux sürümü | `axctl version` |
| Kurulum yolu | RPM / .deb / install.sh |

## `axctl status` çıktısı

```
```

## Denetim kaydı

<!-- Varsa /var/log/axlinux/ altındaki JSONL kayıtları -->

```bash
sudo axctl logs --limit 20
```

> **Güvenlik açığı değilse** bu formu kullanın. Erişim denetimi
> atlatma gibi güvenlik açıklarını herkese açıkça yazmayın —
> [SECURITY.md](../../SECURITY.md) yöntemini izleyin.
