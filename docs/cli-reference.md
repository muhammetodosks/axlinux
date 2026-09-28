# AXlinux CLI Referansı

## Genel Kullanım

```
axctl <komut> [seçenekler]
```

## Komutlar

### init

AXlinux'u başlatır. `~/.axlinux/` dizinini ve boş politika dosyasını oluşturur.

```bash
axctl init [--force]
```

| Seçenek | Açıklama |
|---------|----------|
| `--force` | Mevcut dizini sıfırlar |

### policy edit

Politika dosyasını varsayılan editörde açar.

```bash
axctl policy edit [--editor EDITOR]
```

| Seçenek | Açıklama |
|---------|----------|
| `--editor` | Editör seçimi (nano, vim, code) |

### policy check

Politikanın geçerliliğini doğrular.

```bash
axctl policy check [--verbose]
```

| Seçenek | Açıklama |
|---------|----------|
| `--verbose` | Detaylı çıktı |

**Çıktı**:
- ✓ YAML syntax geçerli
- ✓ Schema doğrulaması başarılı
- ✓ N kural, M etiket bulundu
- ✓ Çakışma yok

### policy simulate

Politikanın neyi etkilediğini simüle eder.

```bash
axctl policy simulate [--format text|json]
```

| Seçenek | Açıklama |
|---------|----------|
| `--format` | Çıktı formatı |

### reload

Politikanı derler ve uygular.

```bash
axctl reload [--mode MODE] [--force-empty]
```

| Seçenek | Açıklama |
|---------|----------|
| `--mode` | enforcing, permissive, disabled |
| `--force-empty` | Boş politika yükle (acil durum) |

### status

Sistem durumunu gösterir.

```bash
axctl status [--json]
```

### logs

Audit log'u okur.

```bash
axctl logs [--follow] [--filter FIELD=VALUE] [--since TIME] [--limit N]
```

| Seçenek | Açıklama |
|---------|----------|
| `--follow` | Canlı izleme (tail -f) |
| `--filter` | Filtre (action=file.read, effect=deny) |
| `--since` | Zamandan beri (1h, 1d, 1w) |
| `--limit` | Maksimum kayıt sayısı |

### learn start

Öğrenme modunu başlatır.

```bash
axctl learn start [--days N]
```

| Seçenek | Açıklama |
|---------|----------|
| `--days` | Öğrenme süresi (varsayılan: 3) |

### learn stop

Öğrenme modunu durdurur.

```bash
axctl learn stop
```

### learn report

Öğrenme raporunu gösterir.

```bash
axctl learn report [--format text|json]
```

### label ls

Etiketleri listeler.

```bash
axctl label ls
```

### label add

Etiket ekler.

```bash
axctl label add LABEL PROCESS
```

### mode

Modu değiştirir.

```bash
axctl mode enforcing|permissive|disabled
```

### template ls

Şablonları listeler.

```bash
axctl template ls
```

### template apply

Şablon uygular.

```bash
axctl template apply NAME
```

### trust add

Güvenilir kaynak ekler.

```bash
axctl trust add URL
```

### policy install

Topluluk politikası yükler.

```bash
axctl policy install NAME
```

### policy verify

Politika imzasını doğrular.

```bash
axctl policy verify NAME
```

### policy use

Politikayı aktif eder.

```bash
axctl policy use NAME
```

### version

Sürüm bilgisini gösterir.

```bash
axctl version
```

## Çıkış Kodları

| Kod | Anlam |
|-----|-------|
| 0 | Başarılı |
| 1 | Genel hata |
| 2 | Politika hatası |
| 3 | eBPF hatası |
| 4 | İletişim hatası |
| 5 | Yetki hatası |

## Ortam Değişkenleri

| Değişken | Açıklama |
|----------|----------|
| `AXLINUX_HOME` | AXlinux dizini (varsayılan: ~/.axlinux) |
| `AXLINUX_SOCKET` | axdaemon socket yolu |
| `AXLINUX_LOG_LEVEL` | Log seviyesi (debug, info, warn, error) |
| `AXLINUX_EDITOR` | Varsayılan editör |

## Yapılandırma

`~/.axlinux/config.yaml`:

```yaml
# AXlinux yapılandırması
editor: vim
log_level: info
mode: enforcing
auto_reload: false
backup_count: 10
```
