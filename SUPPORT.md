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

`deep_verify` sonucu: **732 geçti / 0 kaldı / 1 atlandı** (imzalı RPM ile temiz kurulumda).

---

## 2. Fedora sürüm desteği

**Kesin olarak doğrulanmış: Fedora 41, 42, 43, 44.**

Dördünde de RPM **gerçekten derlendi** ve 8/8 içerik kontrolü geçti
(`fedora:41/42/43/44` konteynerleri, `make rpm SKIP_SIGN=1`):

```
ok axbpf.o            ok journald drop-in      ok python3-click
ok axdaemon           ok SELinux modülü       ok kernel-core
ok axlog              ok axdaemon.service
→ SONUC: ICERIK TAMAM          (Release: 1.fc41 / 1.fc42 / 1.fc43 / 1.fc44)
```

CI'daki paketleme matrisi aynı işi her commit'te tekrarlar
(`fedora:42`, `fedora:43`, `fedora:44`). **Fedora 41** CI'a da eklenmelidir.

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
| `pacman`, `apk`, `zypper` | Tanınıyor, **doğrulanmadı** |

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

- `fedora:42`, `fedora:43`, `fedora:44` → RPM gerçekten derlenir, içeriği doğrulanır
- `debian:12` → `.deb` gerçekten derlenir, içeriği doğrular
- Matris kırılırsa buradaki "doğrulanmış" iddiası da düşer

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