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
