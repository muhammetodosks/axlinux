# Changelog

## 1.1.0 - Fedora 44 Workstation (masaustu)

Fedora 44 uzerinde **masaustu** hedefi icin dogrulama. Bu surum sessiz
kalan alti gercek hatayi duzeltir; ilk ucu urunun ISLEVINI dogrudan
etkiliyordu.

### Kritik: politika yeniden baslatmadan sonra KAYBOLUYORDU

Politika yalnizca `axctl` API'siyle, calisan kullanicinin
`~/.axlinux/policy.yaml` dosyasindan yukleniyordu. Acilista hicbir sey
okunmuyordu; BPF haritalari bos basliyordu. Reboot sonrasi **tum
kurallar kayboluyor** ve sistem sessizce "hicbir sey kisitlanmiyor"
durumuna donuyordu.

Duzeltme: `/etc/axlinux/policies.d/*.yaml` dizini acilista okunuyor
(lexical sira ile birlestirilerek). Tek uygulama yolu `ApplyPolicy`:
hem RPC hem boot ayni kodu kullaniyor, iki yol zamanla ayrisamaz.

Politika bozuksa **hicbir kural yazilmaz** ve sistem kisitlamasiz
kalir; daemon gunluge belirgin uyari yazar. Sistemi yanlislikla
kilitlemektense bilincli bir secim.

### Kritik: audit rotasyonu HIC calismiyordu

`openCurrent()` dosya adini her zaman bugunun tarihinden uretiyordu.
10 MB siniri tetiklendiginde ayni dosya `O_APPEND` ile yeniden
aciliyordu: doska hicbir zaman donmuyor, yalnizca buyuyordu.
VM'de 10.798.351 bayta ulasmis bir dosya kullanici bunu fark
etmeden buyumeye devam ediyordu.

Ayrica saklama ust siniri HIC YOKTU: her gun yeni dosya birikiyordu.

Duzeltme: numarali segment (`audit-GUN.1.jsonl`), gun degisiminde tum
segmentleri kapsayan sikistirma, 14 gunluk saklama. `writer` paketinde
hic test yoktu; 4 regresyon testi eklendi ve **eski kodda basarisiz
olduklari dogrulandi**.

### Kritik: `audit_healthy` kalici olarak `false` kaliyordu

`axlog` yeniden basladiginda bir kez "broken pipe" olusuyor, sonraki
denemede baglanti kendiliginden kuruluyor ve kayitlar akmaya devam
ediyordu - ama `lastErr` hafizada kaliyordu. Sistem saglikliyken
`audit_healthy=false` bildiriliyordu: surekli yanlis alarm.

Duzeltme: basarili gonderim `lastErr`'i temizler.

### `axlog` yanlis surum bildiriyordu

`axlog/main.go` icinde `"1.0.0"` sabiti vardi: RPM 1.1.0 derlenirken
log servisi kendini 1.0.0 olarak raporluyordu. Ayrica `Makefile`
surumu `axdaemon/main.go`'dan kaziyordu; tanim `const` -> `var`
olsaydi kazima sessizce bos string donerdi.

Duzeltme: surum tek kaynaktan (`axlinux.spec`) geliyor ve `-ldflags`
ile iki ikiliye de enjekte ediliyor.

### `deep_verify` kendi durumundan etkileniyordu

Test sabit `/tmp/axctl-cli.txt` yolunu kullaniyordu. Root olmayan bir
kullanici testi biraktiginda dosya o kullaniciya ait kaliyor; sonraki
calistirmada root yazamiyor ve awk hatali cikiyordu - gercek bir
regresyon olmadigi halde test FAIL ediyordu.

Duzeltme: gecici dosya calistirma kimligine bagli.

### Fedora Workstation masaustu kanitlari

- Gercek GNOME 50 oturumu (gdm + Wayland + `systemd --user`)
- Enforcement acikken gercek GUI uygulamasi (gedit, Wayland istemcisi)
- Enforcement acikken gercek paket kurulumu (`dnf install`, 13 paket)
- Reboot sonrasi otomatik giris + politikanin kendiliginden yuklenmesi
- 4 kurallik gercekci enforcing politika (4/4 uygulandi)

### Olcumler

- **Dosya acma gecikmesi:** LSM kanaci yok 11.3 us -> enforcing 17.7 us.
  Kanca takma maliyeti +5.8 us, politika sorgusu yalnizca +0.6 us.
  50.000 acma: 0.25 sn yerine 0.44 sn (fark 0.19 sn, algilanamaz).
- **Audit disk:** izinli islem **0 bayt**; engellenen islem ~252
  bayt. Maliyet toplam etkinlige degil IHLAL sayisina bagli.

### Dogrulama

- `deep_verify.sh`: **716 gecti / 0 kaldi / 2 atlandi**
- Go: 13 paket gecti · Python: 179 gecti + 20 subtest
- RPM 2.189.772 bayt; temiz kurulum + kaldirma + yeniden kurulum

## 1.1.0 - Fedora 44 uyumlulugu

Fedora 44 (en gecerli kararli Fedora surumu) uzerinde tam dogrulama.
Bu surum sessiz kalan bir dizi gercek hatayi kalici olarak duzeltir.

### Kritik duzeltmeler (enforcement hic calismiyordu)

- **eBPF programlari Fedora cekirdeginde yuklenmiyordu.**
  Fedora 44 (clang 22, kernel 6.19) dogrulayicisi coklu `return`
  iceren LSM kancalarini reddediyordu:
  `At program exit the register R0 has smin=0 smax=4294967295`.
  Sonuc: hicbir kanca baglanmiyor, daemon "ebpf yuklenemedi" deyip
  enforcement OLMADAN calisiyordu; kurulum "basarili" gorunuyordu.
  Kalan tek sayisal PID korumasi kaldirildi (PID 1/2 adla zaten
  korunuyor: systemd/init/kthreadd/swapper/migration).
  `src/go/axdaemon/internal/protected` artik tek dogruluk kaynagi;
  `contract_test.go` BPF listesiyle ayniligini dogrular.

- **`process.exec` ve `file.execute` kurallari hic uygulanmiyordu.**
  Iki ayri sebep:
  1. Koruma kontrolu EBVEYN sureci uzerinde yapiliyordu; "bash",
     "sudo" korumali oldugu icin kanca her zaman erken donuyordu.
     Artik hedef binary uzerinde kontrol edilir.
  2. Yol cozumlemesi btrfs alt birim kokunde ("root") takiliyordu.
     Fedora 33'ten beri kok bir alt birim; kernel yolu
     "/root/etc/secret" veriyor, politika "/etc/secret" yaziyor.
     Cozum: daemon `/proc/self/mountinfo`den gorunmez mount
     koklerini okuyup `mount_artifact_map` ile BPF'ye verir
     (`internal/maps/artifacts.go`).
     `/etc`, `/var`, `/home`, `/root`, `/usr/bin` dogrulandi.

- **Sembolik baglar yanlis degerlendiriliyordu.** Kurallar cagrilan
  ada degil GERCEK calistirilan dosyaya uygulanir. Bu korunur:
  aksi halde `ln -s /bin/ls /tmp/ok` ile tum kurallar atlanirdi.

- **`vmlinux.h` bayat kopyadan derleniyordu.** Depoda Eylul'den
  kalma, gelistirme makinesinin cekirdeginden uretilmis dosya
  vardi ve `install.sh` yalniz "yoksa" uretiyordu. Artik her
  kurulumda calisan cekirdegin BTF'sinden yeniden uretilir.

- **`ax_lookup2` joker aramasi yapmiyordu.** `subject: "*"` +
  `object:` ile yazilan `file.execute` kurallari bprm kancasinda
  hic bulunamiyordu.

### SELinux

- Politika modulunun **her kurulumda yeniden derlenmesi** sart.
  Yoksa sisteme kurulmus eski modul kullaniliyor ve kaynaga eklenen
  yeni kurallar hic yuklenmiyordu.
- `selinux-setup.sh` adaylar arasinda **en yeni** modulu secer.
- `bpffs` (`/sys/fs/bpf`) yazma izinleri eklendi.
- `axlog` icin fcontext yanlislikla `axctl`e veriliyordu; dogru
  tip `axlinux_log_exec_t` ve yeni `axlinux_cli_exec_t`.
- Modul arama yolu duzeltildi; kaynak agacindaki derlenmis modul
  once degerlendiriliyor.

### Dogrulama tutarliligi

- `axctl policy check` ve `axctl reload` **ayni dogrulayicilari**
  kullanir. Ikisi celisiyordu: yinelenen kural `id` Go'da
  reddediliyor, Python'da kabul ediliyordu.
- `..` iceren yollar her iki dogrulayicida da reddedilir.
- `axctl status --json` artik `protected_processes` yayinlar;
  `install.sh` sabit "29 surec" yazmak yerine GERCEK sayimi
  gosterir.
- Kilitlenme korumasi 31 surec (eski metin 29 diyordu).

### Cozulmus sinirlar

- **Ayrilmis mount noktalari artik yol kurallarina giriyor.**
  `/tmp` mount noktasinin adi dentry zincirinde gorunmez; kernel
  `/ax-dosya` verir, politika `/tmp/ax-dosya` yazar. Cozum:
  `mount_point_map`. Daemon mountinfo'dan superblock cihazini
  (3. alan `MAJ:MIN`) okuyup haritaya yazar; BPF mount kokune
  ulastiginda oneki yolun altina ekler. Dogrulama (Fedora 44):
  `/tmp`, `/dev/shm`, `/run`, `/run/user/1000` uzerinde deny
  kurallari uygulandi, kural disi yol serbest kaldi.
- **Harita pinleme calisiyor.** `bpf_obj_pin` EPERM donuyordu.
  Kok neden SELinux: modul `bpf_t:filesystem getattr/associate`
  izni vermiyordu. `/sys/fs/bpf/axlinux/` altinda `allow_map`,
  `deny_map` ve `mode_map` kalici olarak pinleniyor.

### Cozulmeyen, belgelenmis sinir

- **Dizin kurallari (`object:`) TAM YOL olarak ele alinir.**
  `object: /home/u/.gnupg` dizinin kendisini korur, icindeki
  dosyalari korumaz. Politika metni "prefix" diyordu; bu bir sozlesme
  ihlalidir. Kok neden: anahtar kodu yolun sonuna hizali
  (`/a/b` -> `[6]/a [5]/b`), kisa yolun ayni blogu kullanabilmesi
  icin BPF tarafinda blok kaydirma gerekiyor; uc farkli bicim
  denendi ve verifier sinirlariyla uyumlu calisan yol bulunamadi.
  Kural basina 6-8 anahtar yazmak 10240 girişli haritada ~1450
  kuralda reload'u dusuruyordu. Gecici cozum: tam yol yazin.
  Gercek cozum `setKeyPath` + `ax_fill_path` kodlamasini birlikte
  "mutlak derinlik" bicimine cevirmektir.

### Kalan sinirlar

- **Mount ad alani basina calisir.** `mount_point_map` superblock
  cihazina gore anahtarlanir (inode mountinfo'da yoktur ve
  `stat()` SELinux tarafindan reddedilir). Ayni superblocku iki
  ayri yola baglamak tek kaydi paylasir; pratikte bu olusmaz.
- **Audit yol alani bos.** JSONL kayitlarinda `"object":{}` geliyor;
  hangi dosya icin karar verildigi kayitta gorunmuyor. Ihlaller
  sayilabiliyor ama denetim dosyasi incelemesi yapilamiyor.

## 1.0.0 - 2026-10-02

AXlinux 1.0.0. Bu surum "deneysel" etiketini kaldirir: paket
kurulabilir, guncellenebilir ve geri yuklenebilir bir dagitim
haline gelir.

Semantik surumleme: `MAJOR.MINOR.PATCH`. Surum tek kaynaktan
okunur (`axctl version`), Python (`__init__.py`), paket
(`pyproject.toml`) ve Go (`main.go`) arasindaki uyumsuzluk
test ile yakalanir.

### TESLIM: gercek paketleme

Kaynak + `install.sh` tek dagitim yoluydu. Bu gercek bir dagitim
degildi: kullanici "kuruldu mu" diye soramaz, paket yoneticisi
guncellemez, geri yuklemez. Simdi `.deb` paketi uretiliyor:

```bash
make package     # -> axlinux_1.0.0_amd64.deb
sudo dpkg -i axlinux_1.0.0_amd64.deb
```

- Derlenmis ikililer pakete gomulur; hedefte clang/Go GEREKMEZ
- `control.bin`, `postinst`, `prerm`, `postrm` ile dogru yasam
  dongusu: kurulumda servisleri acar, kaldirmada kapatir
- Ornek politikalar `/etc/axlinux`, belgeler `/usr/share/doc`
- Politika ve audit pakete GIRMEZ, kaldirmada SILINMEZ
- `make install` ile ayni dizin duzeni ve ayni sonuc

### Bu turda paketlemede bulunan ve duzeltilen hatalar

Yalnizca gercek `dpkg -i` ile ortaya cikan hatalar; hicbiri
`make package` ciktisinda gorunmuyordu.

**CLI sarmalayicisi hic calismiyordu.** `Makefile` icinde `printf`
ile uretiliyordu; `sh -> printf -> python -c` tirnak katmanlarinda
tek tirnaklar kayboluyordu:

```
$ axctl version
  File "<string>", line 1
    sys.path.insert(0, /usr/lib/axlinux)
SyntaxError: invalid syntax
```

Artik `packaging/axctl` gercek bir dosya.

**Paket eski surumu calistiriyordu.** Python dosyalari DUZ
kopyalaniyordu (`/usr/lib/axlinux/cli.py`) ama kod `axctl.cli`
bekliyor; bu yuzden eski kurulumun alt dizini ice aliniyordu:

```
$ axctl version
  Error: No such command 'version'.
```

Artik `make install` ile ayni duzen: `/usr/lib/axlinux/axctl/`.

**Yardim ciktisi yanlitti.** `python -c` modunda `sys.argv[0]`
`axctl` degil `-c` idi; `Usage: -c [OPTIONS]` yaziyordu.

**postinst daemon hazir olmadan bitiyordu.** eBPF yukleme ve 5 LSM
kancasini baglama ~2 saniye suruyor. Kurulumdan hemen sonra
`axctl status` calistirilirsa:

```
x axdaemon calismiyor veya socket bulunamadi
```

Sistem calisirken calismiyor gorunuyordu. postinst artik soketleri
bekliyor.

**Installed-Size bos kaliyordu.** make her recipe satirini AYRI bir
shell'de calistirdigi icin `$SIZE` bir sonraki satira tasinmiyordu;
sonuc `Installed-Size: ` (deger yok) oluyordu. Bos degerle paket
`duplicate value for Installed-Size` ile reddedilir. Artik staging
TUM bitince hesaplaniyor ve bos kalirsa paket uretilmez.

**Kaldirmada `__pycache__` kaliyordu.** Python'un calisma aninda
urettigi dosyalar paket dosyasi degil, dpkg izlemiyor; `dpkg -r`
sonrasi `/usr/lib/axlinux/axctl/__pycache__` artik duruyordu.
postrm temizliyor.

### Dogrulama: paketten kurulu sistem, uc dagitim

Kaynak agaci degil, `.deb` paketi kurulup dogrulandi:

| Dagitim | dpkg -i | axctl version | bpf | kanca | audit | deep_verify |
|---------|---------|---------------|-----|-------|-------|-------------|
| Ubuntu 24.04.5 | basarili | axctl 1.0.0 | 5/5 | 5/5 | saglikli | 100/0/0 |
| Debian 12 | basarili | axctl 1.0.0 | 5/5 | 5/5 | saglikli | 100/0/0 |
| Pardus 25.2 (yirmibes) | basarili | axctl 1.0.0 | 5/5 | 5/5 | saglikli | 100/0/0 |

Pardus resmi arsivden kuruldu: `bilgemdepo.pardus.org.tr/pardus`
(Origin: Pardus, imzali), `base-files 13.8+pardus25.2.1` ->
`Pardus GNU/Linux 25 (yirmibes)`.

Kaldirma dogrulamasi (Ubuntu 24.04.5):

| Kontrol | Sonuc |
|---------|-------|
| `dpkg -r` sonrasi `/usr/lib/axlinux` | yok (temiz) |
| `dpkg -r` sonrasi audit logu | KORUNDU |
| `dpkg -r` sonrasi `~/.axlinux` | KORUNDU |
| yeniden kurulum | 1.0.0, axdaemon active, 100/0/0 |

### Testler

- Python: 154 test + 20 alt test
- Go: 9 paket
- `tests/deep_verify.sh`: 10 bolum / 100 denetim (0.1.0'da 99)

### Notlar

Politika imzalama ve trust yonetimi bilincli olarak UYGULANMADI.
Yarim imzali politika guvenlik acigi yaratir; sistem su an
imzasiz politika kabul ediyor ve bunu belgelerde acikca yaziyor.

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

## 0.1.2 - Dagitimlar arasi test (tamamlanmadi, sonra cozuldu)

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

### ACIK KALAN ISLER (1.0.0'da COZULDU)

- `axctl status` Debian 12'de hata veriyordu -> cozuldu, 100/0/0.
- Pardus'un TAM paket deposu kurulamiyordu (ISO `dists/yirmibes-deb/main`
  = Debian, gercek Pardus paketleri `contrib` altinda ve ISO'da bos)
  -> resmi depodan (`bilgemdepo.pardus.org.tr`) paket alarak cozuldu;
  Pardus 25.2 UZERINDE tam dogrulama YAPILDI.
## Dogrulama: Ubuntu 24.04 + Debian 12 + GERCEx Pardus 25.2

Uc dagitimda ayni kapsamli test paketi (`tests/deep_verify.sh`,
10 bolum / 100 denetim) YESIL. Ana makinede AXlinux hic
calistirilmadi; her sey sanal makinede yapildi.

| Dagitim | Yerel+Go test | Kapsamli test | bpf | audit |
|---------|---------------|---------------|-----|-------|
| Ubuntu 24.04.5 | 125 gecen | 99/0/0 | 5/5 | saglikli |
(kaynak kurulumla; paket dogrulamasi 1.0.0 bolumunde)
| Debian 12 (bookworm) | 125 gecen | 99/0/0 | 5/5 | saglikli |
(kaynak kurulumla; paket dogrulamasi 1.0.0 bolumunde)
| Pardus 25.2 (yirmibes) | 125 gecen | 99/0/0 | 5/5 | saglikli |
(kaynak kurulumla; paket dogrulamasi 1.0.0 bolumunde)

Pardus, resmi arsivden kuruldu: bilgemdepo.pardus.org.tr/pardus
(Origin: Pardus, imzali). base-files 13.8+pardus25.2.1 ->
`Pardus GNU/Linux 25.2 (yirmibes)`; pardus-backgrounds,
pardus-bilge-grub-theme, desktop-base kurulu.

### Bu turda bulunan ve duzeltilen gercek hatalar

**Ogrenme modu hicbir sey toplamiyordu.** Kancalar olayi yalnizca
DENY kurali eslesen operasyonlarda uretiyordu; normal isler
tanim geregi IZIN VERILEN operasyonlar oldugu icin hicbiri olay
uretmiyordu. "axctl learn start" basari diyor, "3 gun kayit
tutulacak" yaziyor, sifir gozlem toplaniyordu. Yeni `learn_map`
bayragi ve bes kancada izinli operasyon gozlemi: 0 -> 192 gozlem.

**ACIL KURTARMA YOLU calismiyordu.** `axctl reload --force-empty`
kotu bir politika yuzunden kilitlenen operatorun enforcement'i
durdurma yoludur; bos politika reddedildigi icin komut KENDISI
basarisiz oluyordu. Ayni dogrulama "axctl init" + reload ilk
kurulum akisini da kiriyordu.

**Calisma zamani bagimliliklari hic kurulmuyordu.** click/rich/yaml
hic tanimli degildi; Ubuntu'da baska paketler sayesinde zaten
vardi, Debian'da "ModuleNotFoundError" ile kurulum "calisiyor"
diyordu.

**/run/axlinux iki servis arasinda paylasiliyordu.** axdaemon
`RuntimeDirectory=axlinux` tasiyordu; systemd servisi baslarken
dizini SILIP YENIDEN OLUSTURUYOR, bir saniye once olusan
axlog.sock'u yok ediyordu. "axlog: active" yaziyordu, audit
kayitlari hicbir yere gitmiyordu. Dizin artik tmpfiles'a tasindi.

**Rapor onerileri ekranda kirpilip YAML'i boszuyordu.** rich
metni ekran genisligine gore kaydiriyor, tek satirlik YAML
degerlerinden biri 82 karaktere yakin oldugu icin dosya
ayrişiyordu; CLI "policy.yaml'a yapistirip policy check ile
dogrulayin" diyordu.

**Kurulum kullanicinin deposunu silinemez hale getiriyordu.**
`sudo make install` root'a ait derleme ciktilari birakiyordu;
`rm -rf axlinux` "Permission denied" veriyor, yeni kaynak
aktarimi sessizce gerceklesmiyordu.

**Bazi hatalar sessizce etkisiz kalmisti.** Korumali surece
(bash, sudo, sshd...) yazilan kural ve 8'den derin yol yalnizca
uyari uretiyordu; politika yukleniyor, "N kural" cikiyor, hicbir
sey engellenmiyordu. Artik PolicyError.

**Netcat hicbir yerde kurulmuyordu.** socket_connect ve
socket_bind kancalarinin tek kullanan test araci; Pardus'ta
yoktu ve iki ag kancasi atlandi.

**Daemon hatalari kullanicya ham Python sozlugu gosteriyordu.**
`Daemon hatası: {'code': -32000, 'message': '...'}`. Ayrica
"zaten aktif" bir altyapi hatasi degil, uygulama seviyesinde bir
ret; ama exit code 4 ile cikiyordu.

### CLI bosluklari kapatildi

- `policy check` / `policy simulate` artik `--file/-f` kabul
  ediyor: aday politika UYGULAMADAN once dogrulanabiliyordu
- `logs`: `--json`, `--subject`, `--action`, `--effect` eklendi
- `label rm` eklendi (once etiket ekleniyor ama silinemiyordu)
- `init` yarim kurulumu tamamliyor (dizin var, politika yok)
- Politika dosyasi yokken `reload` 2 donuyor (dogru kod)
- Cikis kodu semasi kodda belgeli: 0/1/2/4/5
