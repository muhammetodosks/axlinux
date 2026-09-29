#!/usr/bin/env bash
# AXlinux uctan uca dogrulama
#
# Bu betik SISTEMI KILITLEMEZ. Iki onlem:
#   1) Kurtarma yolundaki sureclere (kabuk, oturum acma, yetki
#      yukseltme) kural uygulanmaz - ax_protected, axbpf.h
#   2) Buradaki kurallar yalnizca KORUMA DISI sureclere uygulanir
#      (dd, python3) ve her adimdan sonra mod "disabled"a cekilir
#
# NOT: python3 artik korumali DEGILDIR. Dil kosullari MAC'in en
# sik hedefi oldugu icin listeden cikarildi; bprm ve ag
# testleri python3'u hedef surec olarak kullanir. KORUMALI olan
# tek kabuktur (bash) ve 8. adimda reddedildigi dogrulanir.
set -uo pipefail

GRN=$'\033[32m'; RED=$'\033[31m'; YEL=$'\033[33m'; CYN=$'\033[36m'; RST=$'\033[0m'
say(){ printf '%s\n' "${CYN}==>${RST} $*"; }
ok(){  printf '%s\n' "${GRN}  ok${RST} $*"; PASS=$((PASS+1)); }
bad(){ printf '%s\n' "${RED}  FAIL${RST} $*"; FAIL=$((FAIL+1)); }
# warn yalnizca BILGI yazdirir, sayac degistirmez. Tanimli degilse
# bash "command not found" der ve o kontrol sessizce kaybolur.
# Sessiz basarisizlik, acik basarisizliktan kotudur.
warn(){ printf '%s\n' "${YEL}  dikkat${RST} $*"; }
PASS=0; FAIL=0
check(){ if [ "$2" = "$3" ]; then ok "$1 ($3)"; else bad "$1 (beklenen: $2, gelen: $3)"; fi; }

SOCK=/run/axlinux/axdaemon.sock
TARGET=/etc/hostname          # denenecek dosya
FREE=/etc/os-release          # serbest birakilacak dosya

rpc() {
    sudo python3 - "$1" "${2:-{\}}" <<'PY'
import json, socket, sys
method, params = sys.argv[1], json.loads(sys.argv[2])
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(15)
s.connect('/run/axlinux/axdaemon.sock')
s.sendall((json.dumps({'method': method, 'params': params, 'id': 1})+'\n').encode())
buf = b''
while b'\n' not in buf:
    c = s.recv(65535)
    if not c: break
    buf += c
print(json.dumps(json.loads(buf.decode().strip())))
PY
}

mode_off() { rpc set_mode '{"mode":"disabled"}' >/dev/null 2>&1; }

cleanup() {
    say "temizlik: mod kapatiliyor"
    mode_off
    sudo pkill -9 axdaemon 2>/dev/null
    sudo rm -rf /sys/fs/bpf/axlinux 2>/dev/null
    ok "sistem temizlendi"
}
trap cleanup EXIT

load_policy() { rpc reload_policy "$(printf '{"policy":%s}' "$1")"; }

# ---------------------------------------------------------------- 0) LSM
say "0) LSM zinciri"
CHAIN="$(cat /sys/kernel/security/lsm)"
echo "   $CHAIN"
if [[ ",$CHAIN," == *,bpf,* ]]; then ok "bpf LSM aktif"; else bad "bpf LSM YOK"; exit 1; fi

# ---------------------------------------------------------------- 1) daemon
say "1) daemon baslatiliyor"
sudo pkill -9 axdaemon 2>/dev/null; sleep 1
sudo rm -rf /sys/fs/bpf/axlinux 2>/dev/null
sudo mkdir -p /sys/fs/bpf/axlinux /run/axlinux
sudo setsid /usr/local/bin/axdaemon --socket "$SOCK" > /tmp/axd-verify.log 2>&1 < /dev/null &
for _ in $(seq 1 40); do [ -S "$SOCK" ] && break; sleep 0.25; done
[ -S "$SOCK" ] || { bad "socket acilmadi"; tail -5 /tmp/axd-verify.log; exit 1; }
ok "socket acildi"

HOOKS=$(grep -oE 'kancalari baglandi" aktif=[0-9]+ toplam=[0-9]+' /tmp/axd-verify.log | head -1)
if [ -n "$HOOKS" ]; then ok "LSM kancalari: $HOOKS"; else bad "kanca baglanmadi"; tail -5 /tmp/axd-verify.log; fi

ST=$(rpc get_status)
ENF=$(printf '%s' "$ST" | sudo python3 -c "import json,sys; print(json.load(sys.stdin)['result'].get('enforcement_active'))" 2>/dev/null)
check "enforcement_active" "True" "$ENF"

# KISMI BAGLANMA KONTROLU
#
# Attach() tek tek hatalari yutup devam eder; 3/5 kanca baglanirsa
# enforcement yine "aktif" gorunur. Bu durumda bir dosya kurali
# yazilan kullanici, yalnizca ag kancalari bagli oldugu icin
# KORUNMADIGINI bilmeden korundugunu sanir. Bu, projenin
# yakalamayi hedefledigi sessiz basarisizligin ta kendisidir.
#
# Bu yuzden 5/5 olmadan test devam etmez.
HACT=$(printf '%s' "$ST" | sudo python3 -c "import json,sys; print(json.load(sys.stdin)['result'].get('lsm_hooks_active',0))" 2>/dev/null)
HTOT=$(printf '%s' "$ST" | sudo python3 -c "import json,sys; print(json.load(sys.stdin)['result'].get('lsm_hooks_total',0))" 2>/dev/null)
if [ "${HACT:-0}" = "${HTOT:-0}" ] && [ "${HACT:-0}" != "0" ]; then
    ok "tum kancalar bagli ($HACT/$HTOT)"
else
    bad "KISMI BAGLANMA: $HACT/$HTOT kanca bagli - enforcement TAM DEGIL"
    HMISS=$(printf '%s' "$ST" | sudo python3 -c "
import json,sys
r=json.load(sys.stdin)['result']
print(', '.join(r.get('hooks_missing') or ['?']))" 2>/dev/null)
    [ -n "$HMISS" ] && bad "baglanmayan kancalar: $HMISS"
    HNOT=$(printf '%s' "$ST" | sudo python3 -c "
import json,sys
print(json.load(sys.stdin)['result'].get('enforcement_notice',''))" 2>/dev/null)
    [ -n "$HNOT" ] && warn "daemon bildirimi: $HNOT"
    exit 1
fi

# ---------------------------------------------------------------- 2) file_open
say "2) lsm/file_open  (hedef: dd, koruma disi)"
#
# ONCE YETENEK: kural yokken hedef dosya gercekten okunabilmeli.
# Aksi halde "okunamadi" ciktisi LSM'den degil ortamdan gelir
# (dosya yok, yanlis yol) ve test LSM'i suclamadan gecer.
if dd if="$TARGET" of=/dev/null 2>/dev/null; then
    ok "okuma yetenegi var ($TARGET, kural yokken)"
else
    bad "kural YOKKEN $TARGET okunamadi - test gecersiz"
    exit 1
fi
load_policy "{\"version\":1,\"mode\":\"enforcing\",\"labels\":{\"t\":[\"dd\"]},\"rules\":[{\"id\":\"rule_001\",\"name\":\"x\",\"subject\":[\"dd\"],\"object\":\"$TARGET\",\"action\":\"file.read\",\"effect\":\"deny\",\"port\":0,\"priority\":50}]}" >/dev/null
# dd hata mesajinda "not permitted" arariz. Bu EPERM(1) anlamina
# gelir; LSM -EPERM dondurunce dd tam olarak bunu yazar.
if dd if="$TARGET" of=/dev/null 2>&1 | grep -q "not permitted"; then
    ok "dd $TARGET ENGELLENDI"
else
    bad "dd $TARGET engellenmedi"
    # Neden oldugunu goster: dosya yok mu, kural yuklenmemis mi?
    dd if="$TARGET" of=/dev/null 2>&1 | sed 's/^/     /'
fi
# Serbest dosya: once YAZILABILIR oldugunu dogrula, sonra
# ICERIGINI kontrol et. Eski hata: "dd ...; echo Ubuntu" yazimi
# dd basarisiz olsa bile her zaman "Ubuntu" donduruyordu, yani
# test hicbir sey kanitlamadan gecuyordu.
if dd if="$FREE" of=/dev/null 2>/dev/null; then
    ok "dd $FREE serbest"
else
    bad "dd $FREE engellenmemeliydi"
fi
if dd if="$FREE" bs=64 count=1 2>/dev/null | grep -qi "ubuntu\|debian\|linux"; then
    ok "dd $FREE icerigi okundu"
else
    bad "dd $FREE icerigi beklenenden farkli"
fi
check "head $TARGET serbest (baska surec)" "ok" "$(head -c1 "$TARGET" >/dev/null 2>&1 && echo ok)"

# ---------------------------------------------------------------- 3) audit
say "3) audit akisi"
sleep 1
A=$(sudo python3 - <<'PY'
import json, socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(10)
s.connect('/run/axlinux/axdaemon.sock')
s.sendall(b'{"method":"get_logs","params":{"limit":40},"id":1}\n')
d = json.loads(s.recv(65535).decode())['result']
print(d.get('count', 0))
for l in (d.get('logs') or []):
    print('%s|%s|%s' % (l.get('comm'), l.get('path'), l.get('decision')))
PY
)
CNT=$(printf '%s' "$A" | head -1)
if [ "${CNT:-0}" -gt 0 ] 2>/dev/null; then ok "audit kaydi: $CNT"; else bad "audit kaydi yok"; fi
# Audit kaydi dogru OLMALI. Bu bir uyari degil FAIL'dir: yanlis
# yol/comm/decision yazilan bir audit, operator'a yanlis bilgi
# verir ve hedefin geregindendir.
if printf '%s' "$A" | grep -q "^dd|$TARGET|1$"; then
    ok "audit kaydi dogru: comm=dd path=$TARGET decision=1"
else
    bad "audit kaydi beklenen bicimde degil (dd|$TARGET|1)"
    warn "gelen kayitlar:"
    printf '%s\n' "$A" | head -6 | sed 's/^/     /'
fi
# Ayrica ENGELLENMEYEN islem de kaydedilmemeli; audit yalnizca
# karar noktalarini yazar, her acik yazmaz.
if printf '%s' "$A" | grep -q "^dd|$FREE|"; then
    bad "serbest erisim de audit'e yazildi (filtre islevsiz olabilir)"
else
    ok "serbest erisim audit'e yazilmadi"
fi

# Audit sagligi: sayim sifir oldugunda "hicbir olay olmadi" ile
# "okuma dongusu oldu" ayirt edilemez. audit_healthy bu ayrimi
# yapar; dongu olmus olsaydi sayfa sifir gorunur ve kullanici
# sessizce korunuyor sanardi.
AH=$(rpc get_status | sudo python3 -c "
import json,sys
print(json.load(sys.stdin)['result'].get('audit_healthy'))" 2>/dev/null)
check "audit dongusu sagli" "True" "$AH"
AN=$(rpc get_status | sudo python3 -c "
import json,sys
print(json.load(sys.stdin)['result'].get('audit_notice','-'))" 2>/dev/null)
if [ -n "$AN" ] && [ "$AN" != "-" ]; then
    bad "audit uyarisi: $AN"
else
    ok "audit uyarisi yok"
fi
SF=$(rpc get_status | sudo python3 -c "
import json,sys
print(json.load(sys.stdin)['result'].get('audit_send_failures',0))" 2>/dev/null)
check "audit yazma hatasi yok" "0" "${SF:-0}"

# KALICILIK
#
# Buraya kadar get_logs yalnizca BELLEKTEKI tamponu okuyordu.
# Audit izinin anlami diskte kaldigindadir: daemon yeniden
# baslayinca kayitlar gider. Daha onemlisi, sender nil iken
# hicbir sey yazilmazken de bu adim gecerdi.
#
# Burada ayni kaydin axlog tarafinda dosyaya dustugunu
# dogrulanir. axlog calismiyorsa bu adim basarisiz olmali.
LOGDIR=/var/log/axlinux
if sudo test -d "$LOGDIR"; then
    ok "axlog dizini var ($LOGDIR)"
    # Bekleyip dosyanin buyumesini bekle: gonderim asenkron.
    FOUND=""
    for _ in $(seq 1 20); do
        FOUND=$(sudo find "$LOGDIR" -name 'audit-*.jsonl' -size +0c 2>/dev/null | head -1)
        [ -n "$FOUND" ] && break
        sleep 0.5
    done
    if [ -n "$FOUND" ]; then
        ok "audit kaydi DISKE YAZILDI: $FOUND"
        # Icerik gercekten bizim engelledigimiz islemi mi iceriyor?
        if sudo grep -q "\"comm\":\"dd\"" "$FOUND" 2>/dev/null; then
            ok "kayit dogru sureci iceriyor (comm=dd)"
        else
            bad "kayit icerigi beklenen degil; ilk satir:"
            sudo head -1 "$FOUND" 2>/dev/null | sed 's/^/     /'
        fi
        # Zaman damgasi duvar saati mi? 1970 ise kirtime yanlis.
        if sudo grep -qE '"timestamp":"(19|20)[0-9]{2}-' "$FOUND" 2>/dev/null; then
            ok "zaman damgasi duvar saati (kernel ktime'i degil)"
        else
            bad "zaman damgasi 1970/bozuk; kirtime yanlis yorumlanmis olabilir"
            sudo head -1 "$FOUND" 2>/dev/null | sed 's/^/     /'
        fi
    else
        bad "audit kaydi diske YAZILMADI - axlog calismiyor veya baglanilamiyor"
    fi
else
    bad "axlog dizini yok ($LOGDIR); audit kayitlari kalici degil"
fi
mode_off

# ---------------------------------------------------------------- 4) inode_permission
say "4) lsm/inode_permission"
#
# DOGRULUK NOTU
# -------------
# Bu adim yalnizca "kural etkili" oldugunu gosterir, ozel olarak
# inode_permission KANCASINI kanitlamaz. "dd if=..." Once
# lsm/file_open'a takilir ve dosya hicc acilmaz; inode_permission
# yalnizca inode uzerinde yetki soruldugunda (stat, chmod, open
# inode_permission acesi) tetiklenir.
#
# Kanca-bazli ayrim icin farkli bir yol gerekir. Burada iki durum
# olculur:
#   a) hedef dosya okunabilir (yetenek)
#   b) kural yuklendikten sonra ayni islem engelleniyor
# Kancalarin ikisi de bagli oldugu icin (bolum 1'de 5/5 dogrulanir)
# bu, zincirin saglam oldugunu gosterir. inode_permission'in AYRI
# tetiklendigi varsayimi test edilmez; bunu iddia etmiyoruz.
if dd if="$TARGET" of=/dev/null 2>/dev/null; then
    ok "okuma yetenegi var ($TARGET, kural yokken)"
else
    bad "kural YOKKEN $TARGET okunamadi - test gecersiz"
fi
load_policy "{\"version\":1,\"mode\":\"enforcing\",\"labels\":{\"t\":[\"dd\"]},\"rules\":[{\"id\":\"rule_005\",\"name\":\"x\",\"subject\":[\"dd\"],\"object\":\"$TARGET\",\"action\":\"file.read\",\"effect\":\"deny\",\"port\":0,\"priority\":50}]}" >/dev/null
if dd if="$TARGET" of=/dev/null 2>&1 | grep -q "not permitted"; then
    ok "kural etkili: $TARGET erisimi engellendi"
else
    bad "kural etkisiz: $TARGET engellenmedi"
fi
# inode_permission'in stat uzerinden de gorunur olup olmadigi
# belirsizdir; burada YALNIZCA erisim sonucunu olcuyoruz.
mode_off

# ---------------------------------------------------------------- 4b) yol bazli YAZMA
say "4b) lsm/file_open yazma (file.write)"
#
# Bu adim, daha once HICBIR KANCA tarafindan uygulanmayan bir
# seyi test eder. file_open kancasi eskiden key->action'i sabit
# ACTION_FILE_READ olarak yaziyordu; bu yuzden yol bazli
# file.write kurallari hicbir zaman tutmazdi. Kullanici
# "/etc/shadow yazilamaz" yaziyor, daemon "1 kural yuklendi"
# diyor, dosya degistirilebiliyordu.
#
# inode_permission yol cozumlemedigi icin bu turden kurallarin
# baska bir kanacasi da yoktur: yazma korumasi ancak burada
# calisir.
WRITETEST=/tmp/ax-write-test.$$
rm -f "$WRITETEST" 2>/dev/null
# Once yetenek: kural yokken dosya yazilabilmeli.
if dd if=/dev/zero of="$WRITETEST" bs=1 count=1 2>/dev/null && [ -f "$WRITETEST" ]; then
    ok "yazma yetenegi var (kural yokken)"
else
    bad "yazma yetenegi yok - test gecersiz"
    rm -f "$WRITETEST" 2>/dev/null
    mode_off
fi
load_policy "{\"version\":1,\"mode\":\"enforcing\",\"labels\":{\"t\":[\"dd\"]},\"rules\":[{\"id\":\"rule_006\",\"name\":\"x\",\"subject\":[\"dd\"],\"object\":\"$WRITETEST\",\"action\":\"file.write\",\"effect\":\"deny\",\"port\":0,\"priority\":50}]}" >/dev/null
rm -f "$WRITETEST" 2>/dev/null
if dd if=/dev/zero of="$WRITETEST" bs=1 count=1 2>&1 | grep -q "not permitted"; then
    ok "yol bazli file.write kurali ENGELLEDI"
else
    bad "yol bazli file.write kurali ETKISIZ - kural yazildi ama uygulanmadi"
fi
# Kontrol: yalnizca hedef yol engellendi, baska dosya serbest.
if dd if=/dev/zero of=/tmp/ax-write-ok.$$ bs=1 count=1 2>/dev/null; then
    ok "diger dosya yazmaya devam ediyor (kural dar)"
    rm -f /tmp/ax-write-ok.$$ 2>/dev/null
else
    bad "diger dosya da engellendi - kural cok genis"
    rm -f /tmp/ax-write-ok.$$ 2>/dev/null
fi
rm -f "$WRITETEST" 2>/dev/null
mode_off

# ---------------------------------------------------------------- 5) socket_bind
say "5) lsm/socket_bind  (hedef: python3, koruma disi)"
# python3 artik KORUMALI DEGIL: dil kosullari MAC'in en sik hedefi
# oldugu icin listeden cikarildi. Yerel surec adi python3'tur ve
# LSM'de gorunen de budur.
#
# OLÇUM DÜZENI: once YETENEK, sonra ENGELLEME.
# Kural yuklenmeden once portun gercekten baglanabilir oldugunu
# dogrulariz. Aksi halde "baglanamadi" ciktisi LSM'den degil
# ortamdan (yanlis port, firewall, eksik yigin) gelebilir ve test
# LSM'i suclamadan gecer.
PRE=$(python3 -c '
import socket
try:
    s = socket.socket()
    s.bind(("127.0.0.1", 45678))
except OSError as e:
    print("hata:%s" % e.errno)
else:
    print("baglandi")' 2>&1 | tail -1)
check "bind yetenegi var (45678 serbest, kural yokken)" "baglandi" "$PRE"

load_policy '{"version":1,"mode":"enforcing","labels":{"t":["python3"]},"rules":[{"id":"rule_002","name":"x","subject":["python3"],"object":"","action":"net.bind","effect":"deny","port":45678,"priority":50}]}' >/dev/null
B=$(python3 -c '
import socket
try:
    s = socket.socket()
    s.bind(("127.0.0.1", 45678))
except OSError as e:
    # EPERM(1) LSM engellemesidir; EADDRINUSE(98) degildir.
    print("ep:%d" % (e.errno or 0))
else:
    print("baglandi")' 2>&1 | tail -1)
check "bind 45678 engellendi (EPERM)" "ep:1" "$B"
B2=$(python3 -c '
import socket
try:
    s = socket.socket()
    s.bind(("127.0.0.1", 45679))
except OSError:
    print("engellendi")
else:
    print("baglandi")' 2>&1 | tail -1)
check "bind 45679 serbest" "baglandi" "$B2"
# IPv6 da destekleniyor. Daha once socket_bind yalnizca AF_INET
# ele aliyordu; cift yigin sistemlerde varsayilan bu oldugu icin
# IPv6 dinleyiciler hicbir kurala tabi degildi.
#
# Daha onemli: IPv6 YETENEGINI once olcmeliyiz. Aksi halde "bind
# basarisiz" ciktisi, gercekte IPv6'nin olmamasi ya da baska bir
# hatadan kaynaklanir ve test LSM'i suclamadan gecer. Yani
# once yetenek, sonra engelleme olculur.
B6FREE=$(python3 -c '
import socket
try:
    s = socket.socket(socket.AF_INET6)
    s.bind(("::1", 45679))
except OSError:
    print("yok")
else:
    print("baglandi")' 2>&1 | tail -1)
if [ "$B6FREE" = "baglandi" ]; then
    ok "IPv6 bind yetenegi var (altyapı saglam)"
    B6=$(python3 -c '
import socket
try:
    s = socket.socket(socket.AF_INET6)
    s.bind(("::1", 45678))
except OSError as e:
    print("ep:%d" % (e.errno or 0))
else:
    print("baglandi")' 2>&1 | tail -1)
    check "bind IPv6 45678 engellendi (EPERM)" "ep:1" "$B6"
else
    warn "IPv6 bind yetenegi yok; IPv6 bind testi atlaniyor"
fi
# Kural yalnizca 45678'i yasaklar; hedef surec baska portlara ve
# unix socket'e (bu betigin RPC kanali) erismeye devam edebilmeli.
# Aksi halde bir sonraki mode_off cagrisi yapamaz.
if rpc get_status >/dev/null 2>&1; then
    ok "bind: hedef surec RPC'ye erisebiliyor (kanal saglam)"
else
    bad "bind: hedef surec RPC'ye erisemiyor - kural cok genis"
fi
mode_off

# ---------------------------------------------------------------- 6) socket_connect
say "6) lsm/socket_connect"
#
# Dinleyici CIFT YIGIN (IPv4 + IPv6) acilir. Sadece IPv4 acilirsa
# IPv6 baglantisi ECONNREFUSED alir ve bu, LSM engellemesinden
# AYIRT EDILEMEZ; test yanlis pozitif verir. Bu yuzden once
# serbestlik dogrulanir, sonra kural yuklenir.
python3 -c '
import socket, time
srv4 = socket.socket(socket.AF_INET)
srv4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv4.bind(("127.0.0.1", 45700))
srv4.listen(1)
try:
    srv6 = socket.socket(socket.AF_INET6)
    srv6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv6.bind(("::1", 45700))
    srv6.listen(1)
except OSError:
    pass
time.sleep(25)' >/dev/null 2>&1 &
LISTENER=$!
sleep 2
# Once kanit: her iki yigin da SERBEST baglanabiliyor mu?
# Bu olmadan asagidaki "engellendi" sonucu anlamsiz olur.
PRE4=$(python3 -c '
import socket
try:
    c = socket.socket(); c.connect(("127.0.0.1", 45700))
except OSError:
    print("hata")
else:
    print("baglandi")' 2>&1 | tail -1)
check "dinleyici IPv4 erisilebilir" "baglandi" "$PRE4"
PRE6=$(python3 -c '
import socket
try:
    c = socket.socket(socket.AF_INET6); c.connect(("::1", 45700))
except OSError:
    print("yok")
else:
    print("baglandi")' 2>&1 | tail -1)
if [ "$PRE6" = "baglandi" ]; then
    ok "dinleyici IPv6 erisilebilir (cift yigin)"
    HAVE6=1
else
    warn "IPv6 dinleyici acilamadi; IPv6 connect testi atlaniyor"
    HAVE6=0
fi

load_policy '{"version":1,"mode":"enforcing","labels":{"t":["python3"]},"rules":[{"id":"rule_004","name":"x","subject":["python3"],"object":"","action":"net.connect","effect":"deny","port":45700,"priority":50}]}' >/dev/null
# EPERM(1) = LSM engellemesi. ECONNREFUSED(111) LSM DEGIL, dinleyici
# yok demektir; ikisi karistirilirsa test yanlis pozitif verir.
C=$(python3 -c '
import socket
try:
    c = socket.socket()
    c.connect(("127.0.0.1", 45700))
except OSError as e:
    print("ep:%d" % (e.errno or 0))
else:
    print("baglandi")' 2>&1 | tail -1)
check "connect 45700 engellendi (EPERM)" "ep:1" "$C"
# IPv6 connect de engellenmeli (yalnizca dinleyici IPv6'da aciksa).
if [ "$HAVE6" = "1" ]; then
    C6=$(python3 -c '
import socket
try:
    c = socket.socket(socket.AF_INET6)
    c.connect(("::1", 45700))
except OSError as e:
    print("ep:%d" % (e.errno or 0))
else:
    print("baglandi")' 2>&1 | tail -1)
    check "connect IPv6 45700 engellendi (EPERM)" "ep:1" "$C6"
fi
if rpc get_status >/dev/null 2>&1; then
    ok "connect: hedef surec RPC'ye erisebiliyor (kanal saglam)"
else
    bad "connect: hedef surec RPC'ye erisemiyor - kural cok genis"
fi
kill $LISTENER 2>/dev/null; wait $LISTENER 2>/dev/null
mode_off

# ---------------------------------------------------------------- 7) bprm (exec)
say "7) lsm/bprm_check_security (file.execute)"
#
# NEDEN python3 HEDEF, NEDEN /bin/echo KISITLANIYOR
# -------------------------------------------------
# bprm_check_security yalnizca execve() sirasinda tetiklenir; bir
# dosyayi okumak calistirmak degildir. Testin gercek bir exec
# yapmasi gerekir.
#
# exec yapabilen bir surucu secilmeli. sh KORUMALI oldugu icin
# "sh -c 'exec /bin/echo'" calismaz. python3 KORUMA DISI ve
# os.execv ile gercek exec yapar, bu yuzden hedef olarak secildi.
#
# Kritik ayrinti: kural python3'UN TAMAMINI degil, yalnizca
# /bin/echo YOLUNU yasaklar. Bu iki seyi birden kanitlar:
#   1) bprm kancasi gercekten engelliyor (/bin/echo calismaz)
#   2) kural dar kaldi (/bin/true calisir, python3 calisir)
# (2) olmadan test kendini kilitleyebilirdi: kural tum python3
# exec'ini yasaklarsa asagidaki "yasiyor" kontrolu de duser ve
# bir sonraki mode_off cagrisi yapamaz. Bu yuzden her adimdan
# sonra ayrica "hedef hala calisiyor mu" kontrolu yapilir.
load_policy '{"version":1,"mode":"enforcing","labels":{"t":["python3"]},"rules":[{"id":"rule_003","name":"x","subject":["python3"],"object":"/bin/echo","action":"file.execute","effect":"deny","port":0,"priority":50}]}' >/dev/null
if python3 -c 'import os; os.execv("/bin/echo", ["echo","calistim"])' >/dev/null 2>&1; then
    bad "bprm: /bin/echo exec EDILMEMELIYDI ama calisti"
else
    ok "bprm: /bin/echo exec ENGELLENDI"
fi
# Kontrol: yasakli olmayan yol calismaya devam etmeli.
if python3 -c 'import os; os.execv("/bin/true", ["true"])' >/dev/null 2>&1; then
    ok "bprm: /bin/true exec serbest"
else
    bad "bprm: /bin/true exec ENGELLENMEMELIYDI"
fi
# Kontrol: hedef surecun kendisi saglam kalmali. Aksi halde kural
# cok genis ve testin kontrol kanalini (bu betigin rpc cagrilari)
# kapatmis olur.
if python3 -c 'print(1)' >/dev/null 2>&1; then
    ok "bprm: hedef surec hala calisiyor (kontrol kanali saglam)"
else
    bad "bprm: hedef surec de engellendi - kural cok genis"
fi
mode_off

# ---------------------------------------------------------------- 8) KORUMA
say "8) kilitlenme korumasi (ax_protected)"
#
# IKI YONLU TEST. Koruma listesi ne cok ne az olmalidir:
#
#   (a) Kabuk gibi kurtarma yolu reddedilmeli. Kabul edilirse
#       "bash hicbir sey calistiramaz" sistemi kilitler.
#   (b) Dil kosullari (python3) KABUL edilmeli. Reddedilirse
#       MAC'in en sik kurallari yazilamaz ve urun islevsizlesir.
#       (b) olmadan (a) tek basina yeterli degildir: koruma
#       listenin her seyi yutmasini da yakalamamiz gerekir.
#
REJ_JSON=$(rpc reload_policy '{"policy":{"version":1,"mode":"enforcing","labels":{"t":["bash"]},"rules":[{"id":"rule_100","name":"x","subject":["bash"],"object":"","action":"process.exec","effect":"deny","port":0,"priority":50}]}}' 2>&1)
if printf '%s' "$REJ_JSON" | grep -q "korumali"; then
    ok "kabuk kurali REDDEDILDI (kilitlenme imkansiz)"
else
    bad "kabuk kurali KABUL EDILDI - kilitlenme riski"
    warn "yanit: $REJ_JSON"
fi

# (b) Kabul testi "korumali" kelimesinin YOKLUĞUNA dayanir; bu
# zayif bir kanittir, cunku baska bir hatada da kelime olmaz.
# Bu yuzden yanitin gercekten BASARILI oldugunu da dogrulariz:
# hata alani null olmali. Aksi halde test, reddedilme sebebinin
# yanlis oldugunu gormezden gelir.
ACC_JSON=$(rpc reload_policy '{"policy":{"version":1,"mode":"enforcing","labels":{"t":["python3"]},"rules":[{"id":"rule_101","name":"x","subject":["python3"],"object":"/etc/shadow","action":"file.read","effect":"deny","port":0,"priority":50}]}}' 2>&1)
if printf '%s' "$ACC_JSON" | grep -q '"error":null'; then
    ok "dil kosulu kurali KABUL EDILDI (MAC calisiyor)"
else
    bad "dil kosulu kurali REDDEDILDI - MAC islevsiz"
    warn "yanit: $ACC_JSON"
fi
# Bu satira ulasabilmek, kabugun yasadigini kanitlar.
check "kabuk yasamaya devam etti" "er" "$(cut -c1-2 < "$TARGET")"
mode_off

# ---------------------------------------------------------------- 9) mod gecisleri
say "9) mod gecisleri (acil cikis yolu)"
load_policy "{\"version\":1,\"mode\":\"enforcing\",\"labels\":{\"t\":[\"dd\"]},\"rules\":[{\"id\":\"rule_001\",\"name\":\"x\",\"subject\":[\"dd\"],\"object\":\"$TARGET\",\"action\":\"file.read\",\"effect\":\"deny\",\"port\":0,\"priority\":50}]}" >/dev/null
if dd if="$TARGET" of=/dev/null 2>&1 | grep -q "not permitted"; then ok "enforcing: engellendi"; else bad "enforcing: engellenmedi"; fi
rpc set_mode '{"mode":"disabled"}' >/dev/null
if dd if="$TARGET" of=/dev/null 2>&1 | grep -q "not permitted"; then bad "disabled: engellenmemeliydi"; else ok "disabled: engellenmedi"; fi
rpc set_mode '{"mode":"permissive"}' >/dev/null
if dd if="$TARGET" of=/dev/null 2>&1 | grep -q "not permitted"; then bad "permissive: engellenmemeliydi"; else ok "permissive: engellenmedi"; fi
rpc set_mode '{"mode":"enforcing"}' >/dev/null
if dd if="$TARGET" of=/dev/null 2>&1 | grep -q "not permitted"; then ok "enforcing: tekrar engellendi"; else bad "enforcing: tekrar engellenmedi"; fi

# GECERSIZ MOD REDDI
#
# modeNumeric bilinmeyen bir modu sessizce permissive'a esliyordu.
# Once Go bellegi degistirilir, sonra haritaya yazilirken hata
# olursa iki taraf ayrilir: kullanici "enforcing" gorur, kernel
# "disabled"da kalir. Burada gecersiz bir modun (a) reddedildigini
# ve (b) mevcut modu BOZMADIGINI dogruluyoruz.
BADMODE=$(rpc set_mode '{"mode":"block"}' 2>&1)
if printf '%s' "$BADMODE" | grep -q '"error":null'; then
    bad "gecersiz mod KABUL EDILDI"
else
    ok "gecersiz mod reddedildi"
fi
# Reddetme mevcut durumu bozmamali: enforcing kalmali, kural yine
# uygulanmali.
MM=$(rpc get_status | sudo python3 -c "
import json,sys
print(json.load(sys.stdin)['result'].get('mode'))" 2>/dev/null)
check "gecersiz moddan sonra mod bozulmadi" "enforcing" "$MM"
if dd if="$TARGET" of=/dev/null 2>&1 | grep -q "not permitted"; then
    ok "gecersiz mod denemesi enforcement'i bozmadi"
else
    bad "gecersiz mod denemesi enforcement'i bozdu"
fi

# ---------------------------------------------------------------- sonuc
printf '\n%s\n' "========================================"
printf 'SONUC: %d gecti, %d kaldi\n' "$PASS" "$FAIL"
printf '%s\n' "========================================"
[ "$FAIL" -eq 0 ]
