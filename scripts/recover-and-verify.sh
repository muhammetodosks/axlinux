#!/usr/bin/env bash
# Reboot sonrasi: AXlinux'i derle, dogrula ve kalici olarak kaydet.
#
# Bu betik su sirayi garanti eder:
#   1) bpf LSM zincirde mi
#   2) egitilmis kodu derle (bpf + go)
#   3) sozlesme ve koruma testlerini calistir
#   4) GERCEK enforcement'i kanitla (5 kanca)
#   5) kilitlenme korumasini kanitla
#   6) gecerse git commit
#
# Kullanim: sudo bash scripts/recover-and-verify.sh
set -uo pipefail

GRN=$'\033[32m'; RED=$'\033[31m'; YEL=$'\033[33m'; CYN=$'\033[36m'; RST=$'\033[0m'
say(){ printf '%s\n' "${CYN}==>${RST} $*"; }
ok(){  printf '%s\n' "${GRN}  ok${RST} $*"; }
bad(){ printf '%s\n' "${RED}  FAIL${RST} $*"; }
warn(){ printf '%s\n' "${YEL}  !${RST} $*"; }
die(){ bad "$*"; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || die "repo bulunamadi"
export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"

FAILED=0
step_fail() { bad "$*"; FAILED=1; }

# ------------------------------------------------------------------ 0
say "0) ortam"
if [[ ! -r /sys/kernel/security/lsm ]]; then
    die "/sys/kernel/security/lsm okunamadi"
fi
CHAIN="$(cat /sys/kernel/security/lsm)"
echo "   LSM: $CHAIN"
if [[ ",$CHAIN," != *,bpf,* ]]; then
    die "bpf LSM zincirde YOK. GRUB'a ekleyin:
    sudo sed -i 's/\"/\"/; s/lsm=\\(.*\\)\"/lsm=\\1,bpf\"/' /etc/default/grub
    sudo update-grub && sudo reboot"
fi
ok "bpf LSM aktif"
command -v clang >/dev/null || die "clang yok"
command -v go    >/dev/null || die "go yok (PATH'e /usr/local/go/bin ekleyin)"
ok "arac zinciri hazir"

# ------------------------------------------------------------------ 1
say "1) eBPF LSM nesnesi derleniyor"
if make -C src/bpf clean >/dev/null 2>&1; then :; fi
if make -C src/bpf 2>&1 | tail -20; then
    ok "axbpf.o derlendi ($(stat -c%s src/bpf/axbpf.o) bayt)"
else
    die "eBPF derlemesi basarisiz"
fi
if make -C src/bpf verify 2>&1 | tail -10; then
    ok "bolum dogrulamasi gecti"
else
    step_fail "bolum dogrulamasi basarisiz"
fi

# ------------------------------------------------------------------ 2
say "2) Go bilesenleri derleniyor"
if go build -C src/go/axdaemon -o /tmp/axdaemon-verify . 2>&1 | tail -10; then
    ok "axdaemon derlendi"
else
    step_fail "axdaemon derlenemedi"
fi

# ------------------------------------------------------------------ 3
say "3) sozlesme testleri"
if go test -C src/go/axdaemon ./... 2>&1 | tail -25; then
    ok "Go testleri gecti"
else
    step_fail "Go testleri basarisiz"
fi

if python3 tests/test_protection.py 2>&1 | tail -20; then
    ok "kilitlenme korumasi testleri gecti"
else
    step_fail "koruma testleri basarisiz"
fi

if python3 tests/test_contracts_static.py 2>&1 | tail -30; then
    ok "statik sozlesme testleri gecti"
else
    step_fail "statik sozlesme testleri basarisiz"
fi

if python3 -m pytest tests/test_axctl.py tests/test_paths.py \
        tests/test_silent_failure.py -q 2>&1 | tail -10; then
    ok "python birim testleri gecti"
else
    step_fail "python birim testleri basarisiz"
fi

# NOT: pytest'in varsayilan toplama kurali "test_*.py" ve *_test.py'dir.
# test_protection.py ve test_contracts_static.py pytest sinifi
# ICERMEZ; main() tasiyan betiklerdir ve pytest onlari 0 test olarak
# toplar. Bu yuzden yukarida AYRI calistiriliyorlar. Burada
# "pytest tests/" demek sessizce 0 test kosup gecerdi.

# ------------------------------------------------------------------ 4
# ONCE KURULUM. verify_all.sh /usr/bin/axdaemon calistirir;
# kurulum yapilmadan once test ESKI ikiliyi dogrular ve yeni
# kodun calistigini kanitlamaz. Bu sira once ters birti:
# test (4) kurulumdan (5) once geliyordu.
say "4) kurulum"
systemctl stop axdaemon 2>/dev/null
systemctl stop axlog 2>/dev/null
if make install 2>&1 | tail -12; then
    ok "sistem dizinine kuruldu"
else
    step_fail "install basarisiz; dogrulama anlamsiz"
fi
systemctl daemon-reload 2>/dev/null

# ------------------------------------------------------------------ 5
say "5) gercek enforcement dogrulamasi"
if [[ $FAILED -ne 0 ]]; then
    warn "derleme/kurulum hatasi var; enforcement testine gecilmiyor"
else
    # AXLOG ONCE BASLATILMALI.
    #
    # verify_all.sh audit kaydinin DISKE dustugunu dogrular. axlog
    # ayakta degilse kayit yazilmaz ve bu adim zorunlu olarak
    # basarisiz olur: test dogru davranir ama elimizde hata gibi
    # gorunur.
    systemctl start axlog 2>/dev/null
    for _ in $(seq 1 20); do
        [ -S /run/axlinux/axlog.sock ] && break
        sleep 0.25
    done
    if [ -S /run/axlinux/axlog.sock ]; then
        ok "axlog ayakta (kalici audit icin)"
    else
        warn "axlog baslatilamadi; audit kayitlari diske yazilmayacak"
        step_fail "axlog ayakta degil"
    fi

    # verify_all.sh kendi trap'inde daemon'i oldurur ve modu kapatir.
    # Donus kodu dogrudan yakalanmali; "bash ...; if [[ $? ]]"
    # deseni araya giren herhangi bir komutla kirilir.
    if bash tests/verify_all.sh; then
        ok "kancalar + audit + mod gecisleri dogrulandi"
    else
        step_fail "enforcement dogrulamasi basarisiz"
    fi
fi
systemctl daemon-reload 2>/dev/null
# AXLOG AYNI ZAMANDA ETKINLESTIRILMELIDIR.
#
# axdaemon audit kayitlarini axlog'a yazar. axlog etkin degilse
# kayitlar bellekte kalir, /var/log/axlinux bos olur ve daemon
# yeniden baslayinca kaybolur. Denetim izinin kalici olmasi icin
# iki servis birlikte etkin olmalidir.
if systemctl enable axlog 2>/dev/null; then
    ok "axlog servisi etkinlestirildi (kalici audit kaydi)"
else
    warn "axlog servisi etkinlestirilemedi; audit kayitlari yazilmayacak"
    step_fail "axlog etkin degil: audit kayitlari kalici olmaz"
fi
if systemctl enable axdaemon 2>/dev/null; then
    ok "axdaemon servisi etkinlestirildi"
else
    warn "servis etkinlestirilemedi"
fi

# KURULAN ARTEFAKTIN GERCEKTEN CALISTIGINI DOGRULA.
#
# Onceki surumde yalnizca "make install" ciktisina bakiliyordu.
# Oysa kurulum sessizce yarim kalabilir: eski axbpf.o kalsaydi
# (Makefile'da LIBDIR uzerine yaziliyor ama derleme basarisiz
# olup hedef atlanirsa) kullanici yeni yazilan kodun calistigini
# sanardi. Burada hem nesnenin varligi hem de surum tutarliligi
# kontrol edilir.
say "5b) kurulan artefakt dogrulamasi"
if [[ -x /usr/bin/axdaemon ]]; then
    ok "axdaemon kuruldu"
else
    step_fail "/usr/bin/axdaemon yok"
fi
if [[ -r /usr/lib/axlinux/axbpf.o ]]; then
    ok "axbpf.o kuruldu ($(stat -c%s /usr/lib/axlinux/axbpf.o) bayt)"
else
    step_fail "/usr/lib/axlinux/axbpf.o yok"
fi
# axlog binary'si ve servisi kurulmus mu? Eksikse audit kayitlari
# sessizce kaybolur: daemon baglanmayi dener, hata alir, sayac
# artar ama operator bunu kontrol edene kadar iz bos kalir.
if [[ -x /usr/bin/axlog ]]; then
    ok "axlog kuruldu"
else
    step_fail "/usr/bin/axlog yok; audit kayitlari yazilmayacak"
fi
if [[ -r /lib/systemd/system/axlog.service ]]; then
    ok "axlog.service kuruldu"
else
    step_fail "/lib/systemd/system/axlog.service yok"
fi
# Kurulan nesne, bu calistirmada derlenen nesneyle ayni mi?
# Farkliysa enforcement ESKI kod ile calisiyor demektir; tum
# dogrulamalar yaniltici olur.
if [[ -r /usr/lib/axlinux/axbpf.o && -r src/bpf/axbpf.o ]]; then
    if cmp -s src/bpf/axbpf.o /usr/lib/axlinux/axbpf.o; then
        ok "kurulan axbpf.o bu calistirmada derlenen nesneyle ayni"
    else
        step_fail "kurulan axbpf.o FARKLI (eski nesne kurulmus?)"
    fi
fi

# ------------------------------------------------------------------ 6
say "6) commit"
if [[ $FAILED -ne 0 ]]; then
    die "dogrulama basarisiz; commit YAPILMADI. Yukaridaki FAIL satirlarina bakin."
fi
git add -A || die "git add basarisiz"
if git diff --cached --quiet; then
    ok "degisiklik yok, commit gerekmiyor"
else
    # Kaydedilecek dosyalari GOSTER. "git add -A" her seyi
    # yakalar; test artigi, hesap notu ya da yanlislikla eklenmis
    # bir dosya sessizce commit'e giremez. Kullanici ne
    # kaydedildigini gorerek onaylamali.
    say "commit icin hazirlanan dosyalar:"
    git diff --cached --name-status | sed 's/^/    /'
    printf '\n'
    git -c user.name=AXlinux -c user.email=dev@axlinux commit -q -F - <<'MSG' && ok "commit edildi"
AXlinux: LSM enforcement sessiz basarisizligini gider

bpf_d_path bu projede hedef tampona iki konuma birden yaziyor
(dogru offset + 242 byte kaymis). Sonuc: yol alani bozuluyor,
hash eslesmesi hicbir zaman tutmuyor, yol kurallari sessizce
uygulanmiyordu. Yerine blok tabanli yol cozumleyici (8x32)
getirildi; blok ofseti ve okuma boyutu sabit oldugu icin
verifier hedef+boyut sinirlarini statik goruyor.

Sessiz basarisizlik siniflari (hepsi "yuklendi" der, hicbir sey
olmaz):

  Yol ve anahtar
  - cok derin/uzun yol kirpiliyordu; artik acik hata verir
  - socket portu sabit 5 hane yaziyordu (p:00080), Go degisken
    uretiyordu (p:80): 80/443 gibi GERCEK portlarda ag kurallari
    hicbir zaman tutmuyordu, yalnizca 5 haneli test portlari tutuyordu
  - audit boyut kontrolu 316 != EventSize 304 idi; HER kayit dusepi
    sessizce reddediliyordu
  - set_mode yalnizca Go bellegini guncelliyordu, mode_map'e
    yazmiyordu: ACIL CIKIS YOLU CALISMIYORDU
  - socket_bind IPv6'yi hic ele almiyordu (cift yiginda varsayilan)
  - file_open action'i sabit FILE_READ idi: yol bazli file.write
    kurallari hicbir kanca tarafindan uygulanmiyordu
  - socket_connect IP adresi hic yazmiyordu

  Kapsam ve guvenlik
  - file.delete / file.create / net.accept kabul ediliyordu ama
    HICBIR kanca uretmiyordu: "kimse bu dosyayi silemez" yazilip
    dosya siliniyordu. Artik yukleme aninda reddedilir
  - reload_policy reddedilen kurallarda modu degistiriyordu:
    kullanici "enforcing aktif" gorup hicbir sey engellenmiyordu
  - enforcement_active yalnizca LSM zincirine bakiyordu; 2/5 kanca
    baglansa bile true donuyordu
  - audit okuma dongusu kalici hatada sonsuz mesgul kaliyordu;
    audit sessizce OLMEYE devam ediyordu. Simdi saglik alani var

  Koruma listesi
  - liste python3/node/perl/ruby gibi yorumlayicilari da iceriyordu;
    MAC'in en sik kurallari (python3 /etc/shadow okuyamaz) yazilamiyordu
  - liste artik yalnizca kurtarma yoludur: kabuk, oturum acma, yetki
    yukseltme, init zinciri

  Testlerin kendisi
  - verify_all.sh'de iki test hicbir sey kanitlamadan geciyordu
  - baglanti testleri ECONNREFUSED ile EPERM'i karistiriyordu
  - bprm testi okuma yapip "exec" saniyordu
  - make test koruma ve sessiz-basarisizlik testlerini hic
    calistirmiyordu
MSG
    git log --oneline -1
fi

printf '\n%s\n' "========================================"
if [[ $FAILED -eq 0 ]]; then
    printf '%s\n' "${GRN}AXlinux dogrulandi ve kaydedildi.${RST}"
else
    printf '%s\n' "${RED}Bazi adimlar basarisiz oldu.${RST}"
fi
printf '%s\n' "========================================"
exit $FAILED
