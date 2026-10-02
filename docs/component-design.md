# AXlinux Bileşen Tasarımı

## 1. axctl — Python CLI

Kullanıcının tek temas noktası. Click/Typer tabanlı, renkli çıktı.

### Komutlar

```
axctl init
axctl policy edit
axctl policy check
axctl policy simulate
axctl reload
axctl status
axctl logs [--follow] [--filter ACTION] [--since TIME]
axctl learn start
axctl learn stop
axctl learn report
axctl label ls
axctl label add NAME PROCESS
axctl mode enforcing|permissive|disabled
axctl version
```

### Teknik Detaylar

- **Dil**: Python 3.10+
- **Bağımlılıklar**: `click`, `rich`, `pyyaml`, `grpcio`
- **Konum**: `/usr/bin/axctl`
- **İletişim**: axdaemon ile Unix socket (`/run/axlinux/axdaemon.sock`)

### init

```bash
$ axctl init

AXlinux başlatılıyor...
~/.axlinux/ oluşturuldu
~/.axlinux/policy.yaml oluşturuldu (boş politika, sistem serbest)
~/.axlinux/audit/ oluşturuldu
Mod: enforcing (boş politika = kısıtlama yok)

Hazır. axctl policy edit ile politikanı yaz.
```

### policy check

```bash
$ axctl policy check

✓ YAML syntax geçerli
✓ Schema doğrulaması başarılı
✓ 5 kural, 3 etiket bulundu
✓ Çakışma yok
✓ Öncelik sıralaması tamam

Politika geçerli. axctl reload ile uygula.
```

### policy simulate

```bash
$ axctl policy simulate

Politika Simülasyonu
=====================

Mod: enforcing
Toplam kural: 5
Etiket: 3

[1] nginx web içeriğini okuyabilir
    subject: web_servers → [nginx, apache2, caddy]
    object: /var/www
    action: file.read
    effect: ALLOW

[2] nginx shadow dosyasını okuyamaz
    subject: web_servers → [nginx, apache2, caddy]
    object: /etc/shadow
    action: file.read
    effect: DENY
    ⚠ Spesifik kural, [1]'den sonra değerlendirilir

Çakışma: Yok
```

### reload

```bash
$ axctl reload

Politika derleniyor...
✓ 5 kural, 3 etiket
✓ eBPF map'lerine yazıldı
✓ LSM kancaları güncellendi

Yükleme tamam. Mod: enforcing
```

### status

```bash
$ axctl status

AXlinux Durumu
===============

Mod: enforcing
Uptime: 3 saat 24 dakika
Aktif politika: 5 kural, 3 etiket
eBPF programları: 5/5 yüklü
LSM kancaları: 5/5 aktif
Son reload: 2 dakika önce

Audit log: 1.247 kayıt (son 24 saat)
  deny: 23
  allow: 1.224
```

### logs

```bash
$ axctl logs --follow --filter deny

{"timestamp": "2026-09-27T14:23:01Z", "mode": "enforcing", "subject": "firefox", "object": "~/.ssh/id_rsa", "action": "file.read", "effect": "deny", "pid": 12345, "decision": "denied"}
{"timestamp": "2026-09-27T14:23:05Z", "mode": "enforcing", "subject": "nginx", "object": "/etc/shadow", "action": "file.read", "effect": "deny", "pid": 12346, "decision": "denied"}
```

### learn

```bash
$ axctl learn start

Öğrenme modu başlatıldı.
Sistem 3 gün izlenecek.
3 gün sonra axctl learn report ile önerileri görebilirsin.

İpucu: Öğrenme modu sırasında normal şeyleri yap. AXlinux senin alışkanlıklarını öğrenecek.
```

---

## 2. axc — Python Derleyici

```
axc compile policy.yaml → policy.json
axc validate policy.yaml → errors[]
axc simulate policy.yaml → simulation_result
```

### Aşamalar

1. **Parse**: YAML → Python dict
2. **Validate**: Schema, çakışma, güvenlik kontrolü
3. **Normalize**: Etiketleri aç, öncelik sırasına koy
4. **Compile**: Python dict → JSON (iç politika formatı)
5. **Sign** (gelecek): İsteğe bağlı imza

### İç Politika Formatı

```json
{
  "version": 1,
  "mode": "enforcing",
  "labels": {
    "web_servers": ["nginx", "apache2", "caddy"]
  },
  "rules": [
    {
      "id": "rule_001",
      "name": "nginx web içeriğini okuyabilir",
      "subject": ["nginx", "apache2", "caddy"],
      "object": "/var/www",
      "action": "file.read",
      "effect": "allow",
      "priority": 100
    }
  ]
}
```

---

## 3. axdaemon — Go Daemon

Sürekli çalışan sistem servisi.

### Sorumlulukları

| Modül | Açıklama |
|-------|----------|
| `policy` | axc'den gelen JSON'ı parse eder |
| `maps` | eBPF map'lerine yazar/günceller |
| `lsm` | eBPF programlarını yükler ve bağlar |
| `audit` | axlog ile audit log üretir |
| `server` | Unix socket / gRPC sunucusu |
| `mode` | enforcing/permissive/disabled geçişleri |

### Go Paket Yapısı

```
axdaemon/
├── cmd/axdaemon/main.go
├── internal/
│   ├── server/       # gRPC + Unix socket
│   ├── policy/       # Politika yükleme ve yönetimi
│   ├── maps/         # eBPF map yöneticisi
│   ├── lsm/          # LSM kanca yönetimi
│   ├── audit/        # Audit log üretimi
│   └── mode/         # Mod geçişleri
└── pkg/
    └── proto/        # gRPC tanımları
```

### Başlatma Sırası

1. eBPF programlarını yükle (`axbpf.o`)
2. LSM kancalarını bağla
3. Mevcut politikayı yükle (varsa)
4. Unix socket'i dinle
5. axlog servisini başlat
6. Mode'u uygula (varsayılan: enforcing)

---

## 4. axbpf — C eBPF Programları

Minimum C. Her program aynı pattern:

```c
// file_open_kancası
SEC("lsm/file_open")
int BPF_PROG(file_open_kanca, struct file *file)
{
    // 1. PID ve comm al
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // 2. eBPF map'lerinde ara
    // allow_map'te var → ALLOW
    // deny_map'te var → DENY + audit

    // 3. Karar ver
    return 0; // ALLOW
    // return -EPERM; // DENY
}
```

### Kancalar

| Kanca | LSM Hook | Kapsam |
|-------|----------|--------|
| `file_open` | `lsm/file_open` | Dosya açma |
| `inode_permission` | `lsm/inode_permission` | inode erişim |
| `bprm_check_security` | `lsm/bprm_check_security` | execve |
| `socket_connect` | `lsm/socket_connect` | Bağlantı |
| `socket_bind` | `lsm/socket_bind` | Bind |

### eBPF Map'ler

| Map | Tip | İçerik |
|-----|-----|--------|
| `allow_map` | Hash | PID/comm → izin verilen işlemler |
| `deny_map` | Hash | PID/comm → engellenen işlemler |
| `audit_map` | Perf Buffer | Audit log kayıtları |

---

## 5. axlog — Go Audit Servisi

### Format

```json
{
  "timestamp": "2026-09-27T14:23:01.123456789Z",
  "type": "audit",
  "mode": "enforcing",
  "hook": "file_open",
  "subject": {
    "pid": 12345,
    "comm": "firefox",
    "label": "browsers"
  },
  "object": {
    "path": "/home/user/.ssh/id_rsa",
    "inode": 123456
  },
  "action": "file.read",
  "effect": "deny",
  "decision": "denied",
  "rule_id": "rule_002",
  "rule_name": "firefox ssh anahtarlarını göremez"
}
```

### Özellikler

- JSON Lines formatı (`.jsonl`)
- Log rotation (günlük, 10MB)
- Filtreleme API'si
- `--follow` desteği (tail -f gibi)

---

## 6. Şablon Yöneticisi

```
axctl template ls
axctl template apply minimal
```

Şablonlar, önceden tanımlı politika kalıpları:

- `minimal`: Sadece /etc/shadow koruması
- `web-server`: Nginx/Apache için tam koruma
- `desktop`: Masaüstü için makul varsayılanlar
- `database`: Postgres/MySQL için ağ koruması

---

## 7. Topluluk ve İmza (GELECEK ÖZELLİK — henüz yok)

```
axctl trust add https://github.com/user/axpolicy
axctl policy install user/nginx-hardened
axctl policy verify user/nginx-hardened
```

Topluluk politikaları imzalama ile güvenilirlik sağlar. AXlinux, imzasız politikaları uyarı ile kabul eder.
