# AXlinux Mimari Dokümanı

## Felsefe

**Sen YAML yaz, AXlinux uygulasın.**

SELinux'te politika sana verilir, sen uyarsın. AXlinux'ta politika sana aittir, sen yazarsın. Güvenlik, kullanıcının elinde olmalı.

## Katmanlar

```
┌─────────────────────────────────────────────────────────┐
│                    KULLANICI                            │
│  ~/.axlinux/policy.yaml                                 │
└──────────────────────┬──────────────────────────────────┘
                       │ YAML
┌──────────────────────▼──────────────────────────────────┐
│  axctl (Python CLI)                                     │
│  ┌─────────┐ ┌─────────┐ ┌──────────┐ ┌─────────────┐  │
│  │  init   │ │  check  │ │ simulate │ │   reload    │  │
│  └─────────┘ └─────────┘ └──────────┘ └─────────────┘  │
│  ┌─────────┐ ┌─────────┐ ┌──────────┐ ┌─────────────┐  │
│  │ status  │ │  logs   │ │  learn   │ │   label     │  │
│  └─────────┘ └─────────┘ └──────────┘ └─────────────┘  │
└──────────────────────┬──────────────────────────────────┘
                       │ compile
┌──────────────────────▼──────────────────────────────────┐
│  axc (Python Derleyici)                                 │
│  YAML → Doğrulama → İç Politika Formatı (JSON)         │
└──────────────────────┬──────────────────────────────────┘
                       │ gRPC / Unix socket
┌──────────────────────▼──────────────────────────────────┐
│  axdaemon (Go)                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │  eBPF Map Yöneticisi                            │    │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────────┐    │    │
│  │  │ allow_map│ │ deny_map │ │  audit_map   │    │    │
│  │  └──────────┘ └──────────┘ └──────────────┘    │    │
│  └─────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────┐    │
│  │  Audit Servisi (axlog)                          │    │
│  └─────────────────────────────────────────────────┘    │
└──────────────────────┬──────────────────────────────────┘
                       │ BPF syscall
┌──────────────────────▼──────────────────────────────────┐
│  axbpf (C) — eBPF LSM Programları                       │
│  ┌──────────────┐ ┌──────────────┐ ┌────────────────┐  │
│  │  file_open   │ │inode_perm    │ │bprm_check_sec  │  │
│  └──────────────┘ └──────────────┘ └────────────────┘  │
│  ┌──────────────┐ ┌──────────────┐                     │
│  │socket_connect│ │ socket_bind  │                     │
│  └──────────────┘ └──────────────┘                     │
└─────────────────────────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│  Linux Çekirdek (5.15+, CONFIG_BPF_LSM=y)               │
└─────────────────────────────────────────────────────────┘
```

## Veri Akışı

### 1. Politika Yazma ve Uygulama

```
Kullanıcı → ~/.axlinux/policy.yaml
    ↓
axctl policy check
    ↓
axc compile
    ↓
Doğrulama (schema, çakışma, güvenlik kontrolü)
    ↓
İç politika formatı (JSON)
    ↓
axdaemon (gRPC/Unix socket)
    ↓
eBPF map'lerine yazma
    ↓
eBPF LSM programları artık karar veriyor
```

### 2. Runtime Karar Akışı

```
Sistem çağrısı (open, connect, bind, ...)
    ↓
eBPF LSM kancası tetiklenir
    ↓
eBPF map'lerinde arama yapılır
    ↓
allow_map'te var → ALLOW
deny_map'te var → DENY + audit log
ikisinde de yok → DEFAULT (genelde ALLOW)
    ↓
Karar çekirdeğe döner
```

### 3. Audit Log Akışı

```
eBPF programı → perf buffer
    ↓
axlog (Go) → JSON formatında log
    ↓
/var/log/axlinux/audit.json
    ↓
axctl logs → kullanıcıya okunabilir format
```

## Bileşen Detayları

### axctl (Python CLI)

Kullanıcının tek temas noktası. Tüm komutlar:

| Komut | Açıklama |
|-------|----------|
| `axctl init` | `~/.axlinux/` dizinini ve boş policy.yaml oluşturur |
| `axctl policy edit` | Varsayılan editörde policy.yaml açar |
| `axctl policy check` | YAML syntax ve schema doğrulaması |
| `axctl policy simulate` | "Bu YAML neyi etkiler?" simülasyonu |
| `axctl reload` | Politikayı derler ve axdaemon'a iletir |
| `axctl status` | Sistem durumu, aktif politika, eBPF durumu |
| `axctl logs` | JSON audit log okur ve filtreler |
| `axctl learn start` | Öğrenme modunu başlatır |
| `axctl learn report` | 3 günlük öğrenme raporunu gösterir |
| `axctl label` | Dosya/işlem etiketleme yardımcısı |

### axc (Python Derleyici)

YAML'ı iç politika formatına çevirir:

1. **Parse**: YAML → Python dict
2. **Validate**: Schema doğrulaması, çakışma tespiti
3. **Compile**: Python dict → JSON (iç politika formatı)
4. **Sign**: İsteğe bağlı olarak politika imzalar (gelecek)

### axdaemon (Go)

Sürekli çalışan sistem daemon'ı:

1. **Policy Loader**: axc'den gelen JSON'ı parse eder
2. **Map Manager**: eBPF map'lerine yazar/günceller
3. **LSM Hook Manager**: eBPF programlarını yükler ve bağlar
4. **Audit Service**: axlog ile audit log üretir
5. **gRPC Server**: axctl ile iletişim kurar

### axbpf (C)

eBPF LSM programları — minimum C:

- `file_open`: Dosya açma kontrolü
- `inode_permission`: inode erişim kontrolü
- `bprm_check_security`: execve kontrolü
- `socket_connect`: Bağlantı kontrolü
- `socket_bind`: Bind kontrolü

Her program aynı pattern'i izler:
1. PID veya comm (process adı) al
2. eBPF map'lerinde ara
3. Karar ver (ALLOW/DENY)
4. Audit log yaz

### axlog (Go)

JSON audit log servisi:

- eBPF perf buffer'dan okur
- JSON formatında log yazar
- Filtreleme ve arama API'si
- Log rotation

## Modlar

| Mod | Açıklama |
|-----|----------|
| `enforcing` | Politikalar uygulanır, ihlal = engelle + log |
| `permissive` | Politikalar uygulanır, ihlal = sadece log |
| `disabled` | Hiçbir politika uygulanmaz |

Anında geçiş: `axctl reload --mode=enforcing`

## Güvenlik İlkeleri

1. **Default deny yok**: Kullanıcı yazmadığı şey serbest. AXlinux'u kilitleme.
2. **Simulate her zaman ücretsiz**: `axctl policy check` ve `simulate` her zaman çalışır, politika yüklenmeden önce.
3. **Audit her zaman açık**: En azından permissive modda bile log tutulur.
4. **Kullanıcı her zaman çıkabilir**: `axctl reload --mode=disabled` her zaman çalışır.
5. **Politika imzalama (gelecek)**: Topluluk politikaları imzalanarak güvenilirlik sağlanacak.

## SELinux vs AXlinux

| Özellik | SELinux | AXlinux |
|---------|---------|---------|
| Politika kaynağı | Hazır, milyonlarca satır | Kullanıcı YAML'ı |
| Öğrenme | `audit2allow` | `axctl learn` → 3 gün → öneri |
| Uygulama | `setenforce` + reboot riski | `axctl reload` → anında |
| Log formatı | `audit.log` (metin) | JSON, yapılandırılmış |
| Öğrenme eğrisi | Duvar | Merdiven |
| Felsefe | Sen uyarsın | Sen yazarsın |
