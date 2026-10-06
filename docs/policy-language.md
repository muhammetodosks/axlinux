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
| `effect` | Evet | `allow` veya `deny` |
| `port` | Hayır | Port numarası (net.bind için) |

## Eylemler

Aşağıdaki tablo **gerçekte uygulanan** eylemleri listeler. Her
birinin arkasında en az bir LSM kancası vardır; o kanca anahtarı
üretir ve kararı verir.

| Eylem | Açıklama | LSM Kancası | Yol bazlı? |
|-------|----------|-------------|-------------|
| `file.read` | Dosya okuma | `file_open` | Evet |
| `file.write` | Dosya yazma | `file_open` | Evet |
| `file.execute` | Dosya çalıştırma | `bprm_check_security` | Evet |
| `net.connect` | Dışa bağlanma | `socket_connect` | Hayır (port) |
| `net.bind` | Port dinleme | `socket_bind` | Hayır (port) |
| `process.exec` | Process çalıştırma | `bprm_check_security` | Hayır (süreç) |

`inode_permission` kancası ayrıca **süreç bazlı** `file.read` /
`file.write` / `file.execute` kurallarını (yol boş) uygular.

### Henüz desteklenmeyen eylemler

Bu eylemler politikada yazılırsa `axctl` **açık hata** verir.
Kabul edilip sessizce etkisiz kalmaları, MAC'te en tehlikeli
durumdur: kural "yüklendi" der ama hiçbir şey olmaz.

| Eylem | Durum | Yerine ne kullanılmalı |
|-------|-------|------------------------|
| `file.delete` | Kanca yok | Dosya sistemi izinleri (`chmod`, ACL) |
| `file.create` | Kanca yok | Dizin izinleri (`chmod`) |
| `net.accept` | Kanca yok | Dinleyici tarafında denetim |
| `process.signal` | Planlandı | — |

Silme denetimi için `lsm/inode_unlink_at` kancasının eklenmesi
gerekir. Bu, AXlinux'un bilinen ve belgelenmiş bir
eksikliğidir; sürpriz bir hata değil, açık bir kapsam sınırıdır.

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
2. **Regex yok.** Sadece tam yol.
3. **Zaman kuralları yok.** (v2.0'da eklenebilir)
4. **Kullanıcı bazlı kural yok.** (v1.0'da eklenebilir)
5. **Dinamik politika yok.** Her değişiklik için `axctl reload` gerekir.

## Yol kurallari: tam yol ve mount noktalari

> **DIZIN KURALLARI CALISMAZ — `object:` TAM YOL OLARAK ELE ALINIR.**
>
> Politika dili eski metinlerde "prefix" diyordu. Bu bir sozlesme
> ihlali ve duzeltilmedi:
>
>   object: /home/u/.gnupg, action: file.read, effect: deny
>   cat /home/u/.gnupg/secret.gpg   ->  SERBEST   (sizinti)
>
> **Neden:** anahtar kodu yolun SONUNA hizalidir. `/a/b` kurali
> `[6]/a [5]/b` olarak yazilir; calisma anindaki `/x/y/a/b` yolu ise
> `[7]/x [6]/y [5]/a [4]/b` olur. Kisa yolun ayni blogu
> kullanabilmesi icin BPF tarafinda bloklarin KAYDIRILMASI
> gerekir. Sifirdan yazma, yigin tamponu (512 bayt siniri) ve
> harita degeri olmak uzere uc bicim de denendi; verifier
> sinirlariyla uyumlu, calisan bir yol bulunamadi.
>
> **Gecici olarak neden genisletme yapilmiyor:** kural basina 6-8
> anahtar yazilsaydi 10240 girişli haritada ~1450 kuralda reload
> basarisiz olurdu — sessiz bir bozulmadan kotu.
>
> **Kullanilacak yol:** korunacak dosyalari tam yol olarak yazin.
> Gerekirse birden fazla kural yazin. Ileride cozum, iki tarafi
> da degistiren "mutlak derinlik" kodlamaya gecmektir
> (`setKeyPath` + `ax_fill_path` birlikte).

Iki ayri mount durumu vardir ve **ikisi de cozulmustur**.

bpftrace ile olculen ham davranis:

| Konum | Dosya sistemi | Görünen dentry zinciri |
|---|---|---|
| `/etc/ax-dosya` | btrfs (kök) | `ax-dosya → etc → root(subvolume) → /` |
| `/tmp/ax-dosya` | tmpfs | `ax-dosya → /` — **`tmp` görünmez** |

### 1. btrfs alt birim kökü (gorunmez bilesen)

Fedora 33'den beri kok bir alt birim olarak baglanir ve dentry
zincirine `root` adli gorunmez bir bilesen girer. Politika
`/etc/ax-dosya` yazar, kernel `/root/etc/ax-dosya` gorur.

Cozum: `mount_artifact_map`. Daemon mountinfo'da `root=/root`
gordugu icin bu adi haritaya yazar; BPF mount kokune denk gelen
bileseni atar. `/etc`, `/var`, `/home`, `/root` kurallari calisir.

### 2. Ayrı mount (gorunmez ONEK)

`/tmp` bir tmpfs mount oldugu icin mount noktasinin adi (`tmp`) bir
dizin girdisi DEGILDIR; bir mount baglantisidir. Bu yuzden dentry
zincirinde hic bulunmaz ve onek kaybolur.

Cozum: `mount_point_map`. Daemon mountinfo'nun 3. alanindaki
(`MAJ:MIN`) superblock cihazini okuyup haritaya yazar; BPF mount
kokune ulastiginda bu haritayi arar ve oneki yolun **altina** ekler.

Anahtar neden yalniz superblock cihazidir:

- Inode mountinfo'da bulunmaz.
- `stat()` SELinux tarafindan reddedilir; 12 mount noktasi EACCES
  aliyordu (`/run/user/1000`, `/sys/fs/cgroup`, `/dev/pts`, ...).
  Bu yuzden `stat()`a bagimli bir cozum 12 mount'i sessizce
  birakirdi.
- Tum tmpfs kokleri inode 1'dir; ayirt edici yalniz `s_dev`'dir.

Dogrulama (Fedora 44, SELinux enforcing, RPM kurulumu):

```
cat /tmp/ax-dosya       -> Operation not permitted
cat /dev/shm/ax-dosya   -> Operation not permitted
cat /run/ax-dosya       -> Operation not permitted
cat /run/user/1000/x    -> Operation not permitted
cat /etc/hostname       -> serbest   (kural disi)
```

Kalan sinir: harita superblock cihazina anahtarlanir, bu yuzden ayni
superblocku iki ayri yola baglamak (orn. ayni tmpfs'i `/tmp` ve
`/var/tmp`'ye baglamak) tek kaydi paylasir. Pratikte bu olusmaz.
`axctl policy check` bu ayrımı doğrulamaz — kural geçerli sayılır,
çünkü sözdizimi doğrudur. Uygulama ölçülerek anlaşılır.
