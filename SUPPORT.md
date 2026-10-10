# Desteklenen Sistemler

**AXlinux 1.2.0**

Bu belge hangi dağıtım ve çekirdek sürümlerinin gerçekten çalıştığını söyler.
"Çalışıyor" demek, paketin gerçekten derlendiği, kurulduğu ve **enforcement'ın
fiilen uygulandığı** anlamına gelir.

---

## 1. Doğrulanmış dağıtımlar

| Dağıtım | Sürüm | Paket | Ne doğrulandı |
|---------|-------|-------|---------------|
| **Fedora** | **44** | RPM | Tam kurulum + enforcement + audit + rotasyon + çok kullanıcılı |
| Debian | 12 (bookworm) | `.deb` | `dpkg -i` + `axctl` + politika doğrulama + kaldırma |
| Ubuntu | 24.04.5 LTS | `.deb` | Aynı kapsam |
| Pardus | 25.2 (yirmibes) | `.deb` | Aynı kapsam |

**Fedora 44 birincil hedeftir.** Fedora tarafında SELinux **Enforcing** altında
test edilmiştir — ürünün en zorlandığı mod budur.

Doğrulama ortamı:

```
Fedora Linux 44 (Cloud Edition)
kernel : 6.19.10-300.fc44.x86_64
LSM    : lockdown,capability,yama,selinux,bpf,landlock,ipe,ima,evm
BTF    : /sys/kernel/btf/vmlinux  → VAR
SELinux: Enforcing
```

`deep_verify` sonucu: **732 geçti / 0 kaldı / 0 atlandı** (imzalı RPM ile temiz kurulumda;
Debian ailesinde SELinux bulunmadığı için 731 / 0 / 1)).

---

## 2. Fedora sürüm desteği

**Fedora 41, 42, 43, 44 — dördünde de RPM derlendi ve paket içeriği
doğrulandı.** Dördü için de ölçülen sonuç:

| Fedora | RPM | Boyut | conffiles | SELinux modülü | 8/8 içerik |
|---|---|---|---|---|---|
| 41 | `axlinux-1.2.0-1.x86_64.rpm` | 2.291.285 B | 5 | ✓ | ✓ |
| 42 | `axlinux-1.2.0-1.x86_64.rpm` | 2.335.203 B | 5 | ✓ | ✓ |
| 43 | `axlinux-1.2.0-1.x86_64.rpm` | 2.401.474 B | 5 | ✓ | ✓ |
| 44 | `axlinux-1.2.0-1.x86_64.rpm` | 2.402.211 B | 5 | ✓ | ✓ |

8 içerik kalemi: `axbpf.o`, `axdaemon`, `axlog`, `axctl`, journald
drop-in, SELinux modülü (`axlinux.pp`), systemd servisi, `kernel-core`.

> **Kapsam farkı — okurken önemli.** Bu dört sürüm için **paketleme**
> (derleme + içerik + conffiles) kanıtlandı. **Çalışma zamanı**
> doğrulaması iki sürümde çalıştırıldı:
>
> | Sürüm | deep_verify | Sonuç |
> |---|---|---|
> | **Fedora 44** | 732 / 0 / 0 | Tam: SELinux konfinasyonu etkin, eBPF 5/5 |
> | **Fedora 43** | 732 / 1 / 1 | LSM enforcement çalışıyor; SELinux kuşaklaması bu imajda **yapılamıyor** (aşağıda) |
>
> Fedora 41 ve 42 için çalışma zamanı testi koşturulmadı; onlar için
> derlenebilir ve doğru içerikli oldukları kanıtlanmıştır.

#### Fedora 43'te neden SELinux kuşaklaması yok

Bu, bir eksik değil **ölçülmüş bir platform sınırıdır** ve kurulumda
görünür biçimde bildirilir. Ölçülen zincir şöyle:

1. Paket SELinux etiketlerini `semanage fcontext` ile yazar; bu araç
   `policycoreutils-python-utils` ile gelir ve **artık paketin
   bağımlılığıdır** (aşağıdaki hata notuna bakın).
2. Fedora 43 cloud imajında etiketlenen `axdaemon`,
   `axlinux_daemon_t` alanına girince SELinux **BPF harita
   işlemini reddediyor**:
   `avc: denied { map_read map_write } ... scontext=...axlinux_daemon_t`
3. Sonuç: eBPF yüklenmiyor → LSM kancaları 0/0 → enforcement hiç
   çalışmıyor. Yani kuşaklama, kuşaklamsız sistemden **daha kötü**
   bir sistem bırakıyor.
4. Kurulum betiği bunu **fark edip etiketleri geri alır**, servisi
   yeniden başlatır ve açıkça uyarır:

       UYARI: konfinasyon eBPF yuklemeyi engelliyor
       etiketler geri alindi; enforcement LSM ile aktif
       yeniden baslatildi; eBPF: 5 program

   Ölçülen sonuç: `kanca 5/5, bpf 5` — enforcement çalışıyor.
   `deep_verify` de durumu açıkça raporlar:
   `axdaemon unconfined alanda; SELinux korumasi YOK`.

Fedora 44'te aynı kod yolu konfasyonu **doğruluyor** ve bırakıyor:
`alan dogrulandi: system_u:system_r:axlinux_daemon_t:s0 (eBPF: 5)`.

CI'daki paketleme matrisi aynı işi her commit'te tekrarlar
(`fedora:41`, `fedora:42`, `fedora:43`, `fedora:44`, `debian:12`).
Beş imajın beşinde de yerelde çalıştırıldı ve geçti.

**Fedora 40 ve öncesi desteklenmiyor.** Nedeni aşağıdaki gereksinimlerde.

### Neden bu sınır?

AXlinux'in ihtiyaç duyduğu üç kernel özelliği:

| Özellik | Ne için | Hangi çekirdek |
|---------|---------|----------------|
| `CONFIG_BPF_LSM` | LSM'ye bağlanmak | 5.7+ |
| `/sys/kernel/btf/vmlinux` | CO-RE ile tip çözümü | 5.15+ (Fedora'da 38+ güvenilir) |
| `bpf()` syscall erişimi | Program yükleme | 5.7+ |

Ayrıca paketleme zinciri:

| Gereksinim | Hangi sürümden itibaren |
|------------|--------------------------|
| `selinux-policy-devel` ile modül derleme | Fedora 30+ |
| `systemd-rpm-macros` (`%systemd_postun_with_restart`) | Fedora 30+ |
| BTF'nin dağıtımda varsayılan gelmesi | Fedora 38+ |
| `bpftool` ile `vmlinux.h` üretimi | Fedora 34+ |

**Pratik taban: Fedora 38** (BTF varsayılan). Doğrulanmış derleme aralığı
**Fedora 41–44**'tür.

> **Bu belge daha önce "Fedora 35+ desteklenir" diyordu** (`docs/challenges-risks.md`).
> Bu bir çelişkiydi ve şimdi ölçümle çözüldü: 41–44 gerçekten derleniyor.
> 35–40 için derleme kanıtı yoktur; "beklenir" tahmin olarak kalmasın diye
> destek tablosuna alınmadı.

### Bu koşullar sağlanmıyorsa ne olur?

`install.sh` sürüm numarasına değil, **gerçek yeteneğe** bakar — daha güvenilir:

```
kernel BTF mevcut                                     → devam
bpf LSM zincirde ETKIN                                → devam
bpf LSM zincirde YOK                                  → GRUB'a eklenir,
                                                        reboot istenir
BTF yok                                               → kurulum DURUR,
                                                        "linux-headers kurulu degil"
```

Yani desteklenmeyen bir sistemde kurulum sessizce yarım kalmaz: ya düzeltilebilir
bir eksik bildirilir ya da açık bir hata mesajıyla durulur.

---

## 3. Diğer dağıtım aileleri

`install.sh` şu paket yöneticilerini tanır:

| Yöneticiler | Durum |
|-------------|-------|
| `apt-get` | Doğrulandı (Debian 12, Ubuntu 24.04) |
| `dnf` / `yum` | Doğrulandı (Fedora 44) |
| `pacman` | Doğrulandı (Arch Linux konteyner) |
| `apk` | Doğrulandı (Alpine 3.24 konteyner) |
| `zypper` | Doğrulandı (openSUSE Leap 15.6 konteyner) |

Bu üç yönetici gerçek konteynerlerde `install.sh` **çalıştırılarak**
doğrulandı; her biri için ölçülen sonuç: paket yöneticisi doğru tanındı,
bağımlılıklar kuruldu, Go 1.23.4 kuruldu, `click`/`rich`/`yaml`
Python modülleri kuruldu.

Doğrulama sırasında **üç gerçek hata** bulundu ve düzeltildi:

1. `pkg_available()` her yöneticide farklı anlam taşıyordu.
   `apk info -e` ve `zypper search -i` **"kurulu mu"** sorar —
   "depoda var mı" değil. Sonuç: Alpine ve openSUSE'de *mevcut* olan
   `clang`, `make`, `git` paketleri "paket yok" sanılıp atlanıyordu.
   Doğrusu: `apk add --simulate` ve `zypper install --dry-run`.
2. Bağımlılık listesinde `zypper` dalı hiç yoktu; openSUSE `*)`
   yedeğine düşüp Fedora paket adlarını deniyordu
   (`linux-headers` yerine `linux-devel-default` gerekir).
   Ayrıca Python bağımlılıklarında **hiç** `zypper`/yedek dalı yoktu.
3. `tar` hiçbir yerde bağımlılık olarak bildirilmemişti, ama
   `install.sh` Go'yu açarken kullanıyordu.

> openSUSE'da `python3-rich`/`python3-yaml` paketlenmemiştir; betik
> `python3-pip` kurup pip yedeğine düşer ve bu da ölçülerek
> doğrulandı.

Bir bulunamayan paket tüm kurulumu düşürmez — betik o paketi atlayıp devam eder
ve hangi paketin bulunamadığını raporlar.

Paket yöneticisi ne olursa olsun AXlinux'in kendi çalışma zamanı bağımlılıkları
şunlardır:

```
python3 >= 3.9, python3-click, python3-rich, python3-yaml
kernel-core (RPM), kernel BTF erişimi
```

---

## 4. Mimarî gereksinimler

| Gereksinim | Değer |
|------------|-------|
| Mimari | `x86_64` (RPM `BuildArch` ile sınırlı) |
| Kernel | BPF LSM + BTF (yukarıya bakınız) |
| Kök | enforcement için root gerekir |
| SELinux | Fedora'da **Enforcing** önerilir; modül `bpf()` yetkisini yalnız `axdaemon` alanına verir |
| Dosya sistemi | `bpf` LSM'si bağlıysa bağımsız çalışır; `mount_point_map` ile alt birim kökleri çözülür |

SELinux modülü sistem geneline `bpf()` yetkisi vermez — yalnız `axdaemon` alanı.
Bu, modülün çalışma alanını daraltır.

---

## 5. Bu belge nasıl güncel tutulur

CI'daki paketleme matrisi bu tablonun sözleşmesidir:

- `fedora:41`, `fedora:42`, `fedora:43`, `fedora:44` → RPM gerçekten
  derlenir, 8/8 içerik + conffiles + SELinux modülü doğrulanır
- `debian:12` → `.deb` gerçekten derlenir, içeriği doğrular
- Matris kırılırsa buradaki "doğrulanmış" iddiası da düşer

> Matrisin kendisi de bozukken "doğrulanmış" diyebiliyordu. Doğrulama
> sırasında **iki kırık nokta** bulundu ve düzeltildi:
> 1. Debian işi `apt`'in `golang` paketini kuruyordu → **Go 1.19**,
>    ama proje Go 1.21 istiyor (`go.mod`, `log/slog`). İş her zaman
>    "log/slog is not in GOROOT" ile düşüyordu. Artık
>    `bookworm-backports`'tan `golang-1.23-go` kuruluyor ve ayrı bir
>    adımda sürüm denetleniyor.
> 2. `go build` VCS damgası istiyordu ve git'e erişemeyen
>    konteynerde **tüm RPM matrisini** düşürüyordu
>    ("error obtaining VCS status"). `Makefile` artık
>    `-buildvcs=false` ile derler; derleme `.git`'e bağımlı değildir.

**İçerik doğrulaması (`deep_verify.sh`) CI'da çalışmaz** — sanal makine gerektirir.
Bu, bilinçli bir sınırdır ve CI çıktısında `::warning::` ile belirtilir.
İçerik doğrulaması ayrıca `/mnt/anka` altındaki Fedora 44 VM'de yapılır.

---

## 6. Bilinen platform sınırları

| Sınır | Etki |
|-------|------|
| `net.accept` desteklenmiyor | LSM'de karşılığı yok; bu eylem uygulanamaz |
| Dinamik `p:8080` gibi port kuralları | Politik anahtarında ön eki yok; kurulabilir ama eşleşmez |
| Özel kernel (out-of-tree patch) | `/sys/kernel/security/lsm` ve BTF dizini yerinde olmalı; aksi halde kurulum durur |
| Pardus'ta tam masaüstü kurulmadı | Doğrulama resmî arşivden, CLI üzerinden yapıldı; masaüstü senaryosu Fedora 44'te doğrulandı |

Ayrıntı: `DAGITIM.md` §"Bilinen sınırlar".

---

## 7. Hızlı kontrol

Kendi sisteminizde şunu çalıştırın:

```bash
ls /sys/kernel/security/lsm | tr ',' '\n' | grep -x bpf   # bpf olmalı
test -r /sys/kernel/btf/vmlinux && echo "BTF var"        # BTF olmalı
getenforce                                             # Enforcing önerilir
```

İlk ikisi sağlanıyorsa AXlinux bu sistemde çalışır.