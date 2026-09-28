# AXlinux YAML Politika Dili

## Felsefe

**Sen YAML yaz, AXlinux uygulasın.**

Politika basit, okunabilir, birinci sınıf bir YAML dosyası. AXlinux hiçbir gizli sözdizimi yok, hiçbir ara dil yok. Ne yazarsan o uygulanır.

## Dosya Konumu

```
~/.axlinux/policy.yaml
```

## Sözdizimi

```yaml
# AXlinux politika dosyası
# Sen yaz, AXlinux uygulasın.

version: 1

# Mod: enforcing | permissive | disabled
mode: enforcing

# Etiketler: işlem/dosya grupları
labels:
  web_servers:
    - nginx
    - apache2
    - caddy
  browsers:
    - firefox
    - chromium
    - google-chrome
  databases:
    - postgres
    - mysql
    - redis-server

# Kurallar
rules:
  # Dosya erişimi
  - name: "nginx web içeriğini okuyabilir"
    subject: web_servers
    object: /var/www
    action: file.read
    effect: allow

  - name: "nginx shadow dosyasını okuyamaz"
    subject: web_servers
    object: /etc/shadow
    action: file.read
    effect: deny

  - name: "firefox ssh anahtarlarını göremez"
    subject: browsers
    object: ~/.ssh
    action: file.read
    effect: deny

  # Ağ erişimi
  - name: "python dışarı çıkamaz"
    subject: python
    action: net.connect
    effect: deny

  - name: "sshd sadece 22 portunu dinler"
    subject: sshd
    action: net.bind
    port: 22
    effect: allow

  # Process exec
  - name: "nginx bash çalıştıramaz"
    subject: web_servers
    action: process.exec
    object: /bin/bash
    effect: deny
```

## Alanlar

| Alan | Zorunlu | Açıklama |
|------|---------|----------|
| `version` | Evet | Politika formatı sürümü (şimdilik 1) |
| `mode` | Hayır | Varsayılan: `enforcing` |
| `labels` | Hayır | İşlem grupları |
| `rules` | Evet | Kural listesi |

### Kural Alanları

| Alan | Zorunlu | Açıklama |
|------|---------|----------|
| `name` | Evet | Kural açıklaması (insan okunabilir) |
| `subject` | Evet | Kim? (label veya tek işlem adı) |
| `object` | Hayır | Ne? (dosya, dizin, işlem) |
| `action` | Evet | Ne yapıyor? |
| `effect` | Evet | `allow` veya `deney` |
| `port` | Hayır | Port numarası (net.bind için) |

## Eylemler

| Eylem | Açıklama | LSM Kancası |
|-------|----------|-------------|
| `file.read` | Dosya okuma | `inode_permission` |
| `file.write` | Dosya yazma | `inode_permission` |
| `file.execute` | Dosya çalıştırma | `bprm_check_security` |
| `file.delete` | Dosya silme | `inode_permission` |
| `net.connect` | Dışa bağlanma | `socket_connect` |
| `net.bind` | Port dinleme | `socket_bind` |
| `net.accept` | Bağlantı kabul | `socket_connect` |
| `process.exec` | Process çalıştırma | `bprm_check_security` |
| `process.signal` | Sinyal gönderme | `task_kill` (gelecek) |
| `file.create` | Dosya oluşturma | `inode_permission` |

## Etiketler

Etiketler, işlem gruplarını tanımlar. Tek bir kural, birçok işlemi kapsayabilir.

```yaml
labels:
  web_servers:
    - nginx
    - apache2
    - caddy
```

Kullanım:

```yaml
rules:
  - name: "web sunucuları /etc/shadow okuyamaz"
    subject: web_servers
    object: /etc/shadow
    action: file.read
    effect: deny
```

## Öncelik Kuralları

1. **Deny her zaman allow'dan önce gelir.** Kullanıcı yanlış yazsa bile, deny kazanır.
2. **Spesifik kural, genel kuraldan önce gelir.** `/etc/shadow` kuralı, `/etc` kuralından önce değerlendirilir.
3. **Aynı öncelikte son yazılan kazanır.**

## Simülasyon

`axctl policy simulate` komutu, politikanın neyi etkilediğini gösterir:

```
$ axctl policy simulate

Politika Simülasyonu
=====================

Mod: enforcing
Toplam kural: 5
Etiket: 3

Kural 1: nginx web içeriğini okuyabilir
  → nginx, /var/www/* okuyabilir
  → Etkilenen işlemler: nginx, apache2, caddy

Kural 2: nginx shadow dosyasını okuyamaz
  → nginx, /etc/shadow okuyamaz
  → Etkilenen işlemler: nginx, apache2, caddy
  → DİKKAT: Bu kural, Kural 1'den sonra gelir ve spesifik

Kural 3: firefox ssh anahtarlarını göremez
  → firefox, ~/.ssh/* okuyamaz
  → Etkilenen işlemler: firefox, chromium, google-chrome

Kural 4: python dışarı çıkamaz
  → python, dışa bağlanamaz
  → Etkilenen işlemler: python

Kural 5: sshd sadece 22 portunu dinler
  → sshd, sadece port 22'ye bind olabilir
  → Etkilenen işlemler: sshd

Çakışma: Yok
Güvenlik: Temiz
```

## Örnek Politikalar

### Minimal Güvenlik

```yaml
version: 1
mode: enforcing

rules:
  - name: "tarayıcılar ssh anahtarlarını okuyamaz"
    subject: firefox
    object: ~/.ssh
    action: file.read
    effect: deny

  - name: "tarayıcılar /etc/shadow okuyamaz"
    subject: firefox
    object: /etc/shadow
    action: file.read
    effect: deny
```

### Web Sunucusu

```yaml
version: 1
mode: enforcing

labels:
  web:
    - nginx
    - apache2

rules:
  - name: "web sunucuları web içeriğini okur"
    subject: web
    object: /var/www
    action: file.read
    effect: allow

  - name: "web sunucuları /etc/shadow okuyamaz"
    subject: web
    object: /etc/shadow
    action: file.read
    effect: deny

  - name: "web sunucuları bash çalıştıramaz"
    subject: web
    action: process.exec
    object: /bin/bash
    effect: deny

  - name: "web sunucuları sadece 80 ve 443 dinler"
    subject: web
    action: net.bind
    port: 80
    effect: allow

  - name: "web sunucuları sadece 80 ve 443 dinler"
    subject: web
    action: net.bind
    port: 443
    effect: allow
```

### Gelişmiş

```yaml
version: 1
mode: permissive

labels:
  web:
    - nginx
    - apache2
  db:
    - postgres
    - mysql
  cache:
    - redis-server

rules:
  - name: "web sunucuları web içeriğini okur"
    subject: web
    object: /var/www
    action: file.read
    effect: allow

  - name: "web sunucuları veritabanına bağlanır"
    subject: web
    object: db
    action: net.connect
    effect: allow

  - name: "veritabanları dışarı çıkamaz"
    subject: db
    action: net.connect
    effect: deny

  - name: "redis sadece localhost'ta dinler"
    subject: cache
    action: net.bind
    port: 6379
    effect: allow

  - name: "hiçkimse /etc/shadow okuyamaz"
    subject: "*"
    object: /etc/shadow
    action: file.read
    effect: deny
```

## Sınırlamalar

1. **Wildcard sadece `subject: "*"` için.** Object wildcard yok.
2. **Regex yok.** Sadece tam yol veya prefix.
3. **Zaman kuralları yok.** (v2.0'da eklenebilir)
4. **Kullanıcı bazlı kural yok.** (v1.0'da eklenebilir)
5. **Dinamik politika yok.** Her değişiklik için `axctl reload` gerekir.
