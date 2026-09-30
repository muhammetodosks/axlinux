# Changelog

## 0.1.0 - 2026-09-29

Ilk gercek dogrulama: bloklu yol cozumleyici, kalici audit servisi ve
dort sanal makinede dogrulanmis enforcement.

### Dogrulama

Dogrulama sanal makinede yapildi (Ubuntu 24.04, kernel 6.8,
`lsm=...,bpf,...`). Ana makinede AXlinux hic calistirilmadi.

| Kontrol | Sonuc |
|---|---|
| `make -C src/bpf` | temiz |
| `make -C src/bpf verify` | 5/5 kanca, kanca->map sozlesmesi gecti |
| `go vet` (axdaemon + axlog) | temiz |
| `go test` | 11 paket, 0 hata |
| `make test` | rc=0 (78 Python + 36 statik) |
| `file_open` DENY | curl rc=37, kontrol grubu rc=0 |
| `bprm` (exec) DENY | rc=1, kontrol grubu rc=0 |
| `socket_connect` DENY | nc 4444 rc=1, 5555 rc=0 |
| Kalici audit | 18 gecerli JSONL kaydi, `rule_id` ile izlenebilir |
| Kilitlenme korumasi | cat/head/bash/apt/ssh saglam |

### Duzeltilen sessiz hatalar

Bunlarin hicbiri derleme hatasi degildi; hepsi "calisiyor gibi
gorunup is yapmayan" siniftan. Yeni kod bu dosyalarla hicbir zaman
derlenmemisti.

**Ciddi / sessiz no-op**

- **merged-usr yol uyusmazligi.** Modern Debian/Ubuntu'da `/bin`,
  `/lib`, `/sbin`, `/lib64` symlink'tir. Kernel her zaman COZULMUS
  yolu bildirir, bu yuzden `/bin/ls` yazan politika `["/bin","/ls"]`
  anahtari uretirken kernel `["/usr/bin","/ls"]` ariyordu. Kural
  yukleniyor, "1 kural yuklendi" deniyor ve HICBIR ZAMAN eslesmiyordu.
  Politika yollari artik yukleme aninda kanoniklestiriliyor.
  (Bu hatayi bulmak 3 yeniden baslatma ve kancaya gecici tani probu
  gerektirdi; probu temizlendi.)
- **`net.*` kuralinda port opsiyoneldi.** Port verilmezse anahtar
  `p:0` olur ve hicbir baglantiyla eslesmez. Artik Go kapisinda
  zorunlu; Python zorunlu kiliyordu ama politika dogrudan RPC ile
  gelince Python devre disi kaliyordu.
- **`effect=deny` filtresi hicbir kaydi donduruyordu.** Satirdaki
  deger numeric, filtre metin; karsilastirma yapilmadan once
  isimlere cevrilmiyordu. `subject` takma adi ve `hook` alani da
  hic uretilmiyordu.
- **Ogrenme `get_logs` sorgusundan besleniyordu.** Ayni olaylar her
  sorguda tekrar sayiliyor, kimse sorgulamazsa hicbir sey
  gozlenmiyordu. Gozlemci artik olayin URETILDIGI ana baglaniyor.
- **`Makefile` axlog testlerini yutuyordu** (`|| true`): iki derleme
  hatasi hicbir zaman gorunmedi.
- **`test_contracts_static` bolum 3, 4 ve 13 hic calismiyordu.**
  Bosluk iceren regex `eval("")` ile cokuyor, kanca adlari
  `.inc.inc` aranip bulunamıyordu, C kodu icin `func ax_set_port`
  araniyordu.
- **Python dogrulayici liste subject'li her politika ile cokuyordu**
  (`unhashable type: 'list'`) - en sik kullanilan kural bicimi.
- **`compiler.py` sozdizimi hatasi** (`f"` oneki unutulmus): Python
  CLI tamamen kullanilamaz haldeydi.

**Kurulum ve servis**

- `axctl` hicbir yere kurulmuyordu ("axctl hazir" yaziyordu ama
  dosya yoktu).
- `axdaemon.service`, var olmayan `sys-fs-bpf.mount` birimine
  `Requires` veriyordu: servis hic baslayamiyordu.
- `ExecStartPre` `[Unit]` bolumundeydi; systemd sessizce yoksayiyordu.
- `ReadWritePaths` var olmayan dizini isaret ediyordu (226/NAMESPACE).
- Her iki sunucu da sabit `/run/axlinux` yaziyordu; socket baska bir
  yola konulunca acilamiyor ve normal kullanicida hic acilmiyordu.
- Dokumanlar var olmayan dizine kuruluyordu (`|| true` ile sessiz).

**Dogrulama araclari**

- `make verify` nesnede sembol adi ariyordu; `ax_fill_path`,
  `ax_protected` ve `ax_set_port` `__always_inline` olduklari icin
  gomuluyor ve HICBIR ZAMAN gorunmuyor. Kontrol kanca basina
  relocation sozlesmesiyle degistirildi: bir kanca map'lerine
  bagli degilse hicbir sey yapmiyor demektir.
- `axctl status` ve `axctl logs` cokuyordu: rich markup'te
  kapatilmamis etiket, ve audit goruntuleyici sunucunun DUZ
  satir semasini beklerken ic ice axlog semasi bekliyordu.
  Enforcement calisiyor olsa bile operator kayitlari hicbir zaman
  goremiyordu.

### Bilinen sinirlar

- Exec kancasinda `file.execute` icin yalnizca `deny` uygulanir.
  Beyaz liste exec icin guvenlik acidandir; `effect: allow`
  yazan kurallar sessizce islevsizdir.
- Yorumlayicilar (python3, node, perl) koruma disi birakilmistir:
  MAC bir yorumlayiciyi hedeflediginde kullanici oturumunu
  kilitleyebilir. Denetim birimi yorumlayicinin calistirdigi
  programdir.

### Dogrulama sirasinda bulunan ek hatalar

- **`axctl reload --mode` hicbir sey yapmiyordu.** `mode` parametresi
  yalnizca `--force-empty` dalinda kullaniliyordu; normal yolda policy
  dosyasindaki "mode: enforcing" gecerli kaliyordu. Komut "Yukleme
  tamam" yaziyor ve sistem engellemeye devam ediyordu. Bu konfor
  hatasi degil: acil durumda enforcement'i durdurmanin yolu bu
  komut. Artik `--mode` uygulaniyor ve dogrulanip bildiriliyor
  (VM'de enforcing/permissive/disabled ucu de test edildi).
- **Restart sonrasi politika yuklenmiyor**, ama `axctl status`
  "5/5 kanca aktif" gosteriyordu. Artik kural yokken ve map'ler
  bosken durum "POLITIKA YOK: HICBIR KURAL UYGULANMIYOR" uyarisi
  verir; kurallar yuklu ama mod permissive ise ayrica uyari cikar.
- **Harita pinleme uyarisi** her yeniden baslatmada cikiyordu.
  `os.IsExist` bu hatada `false` donuyordu; beklenen durum
  `errors.Is(err, os.ErrExist)` ile ayrilir. Pin'lenmis haritalar
  yeniden kullanildigi icin bu bir hata degil.
- **`cli.py` girintisi bozuktu** (dekorator ile `def` ayni
  satirda, blok girintileri tutarsiz). Dosya hic derlenmiyordu;
  `make install` hatayi `>/dev/null 2>&1` ile gizledigi ici
  fark edilmemisti. `reload` fonksiyonu yeniden yazildi.

## 0.1.1 - Tek komut kurulum

- `install.sh`: tek komutla kurulum. Ortam denetimi, bagimliliklar,
  derleme, kurulum, servis baslatma ve **dogrulama** yapar.
  "Dosyalar kopyalandi" demekle yetinmez; kancalarin baglanip
  baglanmadigini ve soketlerin acilip acilmadigini olcer.
- `update-grub` Ubuntu cloud image'da `lsm=` yazmadigi icin
  bootloader'a dogrudan yazilir. Kurtarma modu girdisine `lsm=`
  YAZILMAZ; bpf LSM boot'u kirarsa sistem rescue ile kurtarilir.
- GRUB degistirilmeden once `.axlinux-backup` alinir. Otomatik
  yeniden baslatma YAPILMAZ.
- Kurulum araci kendini onarir: zincirdeki tekrar eden `bpf`
  girdileri temizlenir, ayni komut tekrar calistirilabilir.

Sanal makinede dogrulandi (Ubuntu 24.04, kernel 6.8, KVM):
sifirdan kurulum 10/10, ikinci calistirma 10/10, kurulum sonrasi
enforcement file_open rc=37 ve bprm rc=1 (kontrol gruplari rc=0),
kilitlenme korumasi saglam, acil kapatma rc=0.

Test sirasinda bulunan kurulum betigi hatalari:
- `/sys/kernel/btf/vmlinux` bir dosyadir; `-d` (dizin) ile
  kontrol edildigi icin "kernel BTF yok" deyip kurulum
  durduruyordu
- `summary()` adimlardan sonra tanimliydi; once cagrildigi icin
  "command not found" veriyordu
- `done_step` bos argumanla cagrilinda `$2` unbound oluyordu
  (`set -u` altinda script cokuyordu)
- zincirde bpf zaten varken yine ekleniyordu; ikinci calistirmada
  `lsm=...,bpf,bpf,...` olusuyordu

### Guvenlik korumasi: verify_all.sh fiziksel makinede calismaz

`tests/verify_all.sh` gercek enforcement uygular. Gelistirme ortaminda
enforcement yalnizca sanal makinede dogrulandigi icin betik artik
fiziksel makinede calistirilmayi reddediyor:

    HATA: fiziksel makine (sanal: none).
    AXLINUX_ALLOW_PHYSICAL=1 tests/verify_all.sh   # bilerek atlamak icin

Bu koruma iki kez sessizce calismadi ve ikisi de duzeltildi:

1. `systemd-detect-virt` fiziksel makinede "none" YAZAR ve **cikis
   kodu 1 doner**. `$(systemd-detect-virt || echo bilinmiyor)` yazildigi
   icin `_VIRT` iki satirlik "none\nbilinmiyor" oluyor ve `case "none"`
   ile ESLESMIYORDU. Koruma hic tetiklenmedi.
2. Korumanin kendi regresyon testi `verify_all.sh`'i SANAL MAKİNEDE
   calistiriyordu. Betik enforcement uygulayip adim sonunda modu
   "disabled"a cekiyor; yani test, denetledigi seyi bozuyordu. Test
   artik yalnizca fiziksel makinede subprocess calistiriyor, sanal
   makinede atlaniyor.

### Yeni regresyon testleri

`tests/test_install_guard.py` (13 test). Daha once sessizce gecmis
veya yanlis calismis her seyi sabitler:

- vmlinux bir dosyadir (`-d` degil)
- `summary()` adimlardan once tanimlidir
- `done_step`/`warn_step`/`fail_step` bos argumanla cagirilabilir
- adim sayaci ile gercek adim sayisi esittir (cift `TOTAL` tanimi
  kaldirildi)
- LSM zinciri idempotenttir (bpf iki kez eklenmez)
- kurulum araci otomatik reboot yapmaz
- GRUB degistirilmeden once yedek alinir
- recovery girdisine lsm= yazilmaz (boot kirarsa kurtarma yolu acik)

## Dagitimlar arasi test (Devam - tamamlanmadi)

Pardus 25.2 ve Debian 12 uzerinde kurulum denendi. Ubuntu'da calisan
install.sh'in baska dagitimlarda kirildigi yerler bulundu ve duzeltildi:

- **Tek bulunamayan paket tum kurulumu dusuruyordu.** apt/dnf, listede
  var olmayan bir paket buldugunda (Debian 12'de `linux-tools-common`
  "no installation candidate") ISLEMI TAMAMEN BIRAKIR. Sonuc: hicbir
  paket kurulmuyor, "kurulamayan araclar: git" ile kurulum duruyor ve
  axctl hic kurulmuyordu - 69 test basarisiz oluyordu. Artik paketler
  TEK TEK kurulur, bulunamayanlar atlanir.
- **Kontrol edilen araclar kurulum listesinde degildi.** `git` gerekli
  arac sayiliyordu ama `install_pkgs` cagrisinda gecmiyordu. Ubuntu'da
  git onceden kurulu oldugu icin sorun gorunmedi.
- **apt kilidi beklenmiyordu.** cloud-init, unattended-upgrades veya
  apt-daily kilidi tutuyorsa kurulum sessizce basarisiz oluyordu;
  gercek sebep "kurulamayan araclar" mesajiyla gizleniyordu.

### KAPSAMLI TEST PAKETI

`tests/deep_verify.sh`: 9 bolum, CLI komutlari, ogrenme modu,
bes LSM kanca, kalici audit, modlar, kilitlenme korumasi, hata
yollari, politika dili kenar durumlari.

### ACIK KALAN ISLER

- `axctl status` Debian 12'de hata veriyor; nedeni henuz
  tespit edilmedi. Kapsamli test 40/95 geciyor.
- Pardus'un TAM paket deposu kurulamadi: kurulum ISO'su yalnizca
  Debian 13 tabanini tasiyor (`dists/yirmibes-deb/main` = Debian),
  gercek Pardus paketleri `contrib` altinda ve ISO'da bos.
  Bu yuzden Pardus 25.2 UZERINDE tam dogrulama YAPILAMADI.
