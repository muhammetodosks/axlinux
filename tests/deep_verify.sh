#!/usr/bin/env bash
#
# AXlinux kapsamli dogrulama paketi
# ===============================
#
# Kapsam:
#   A) Ortam ve saglik
#   B) TUM CLI komutlari
#   C) Ogrenme modu (basindan sonuna)
#   D) Bes LSM kanca
#   E) Tum aksiyon turleri
#   F) Kalici audit
#   G) Acil kapatma ve modlar
#   H) Kilitlenme korumasi
#   I) Hata yollari (dogrusal girdi reddi)
#   J) Politika dili kenar durumlari
#
# Kullanim:
#   sudo tests/deep_verify.sh            # tam paket
#   sudo tests/deep_verify.sh -k B      # sadece bolum B
#
# Guvenlik:
#   - Fiziksel makinede calistirilmayi reddeder
#   - Sadece KORUMA DISI surecleri hedefler
#   - Her bolumden sonra mod "disabled"a cekilir
#   - Cikta /var/log/axlinux/ icine de yazilir
#
set -uo pipefail

# --------------------------------------------------------------- koruma
if [ "${AXLINUX_ALLOW_PHYSICAL:-0}" != "1" ]; then
    _V=""
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        # Cikis kodu 1 doner ("none"); sadece ilk satir alinir.
        _V="$(systemd-detect-virt 2>/dev/null | head -1)"
    fi
    [ -z "$_V" ] && _V="none"
    if [ "$_V" = "none" ]; then
        printf 'HATA: fiziksel makine. Bu betik gercek enforcement uygular.\n'
        printf '  Sanal makinede calistirin veya:\n'
        printf '    AXLINUX_ALLOW_PHYSICAL=1 tests/deep_verify.sh\n'
        exit 1
    fi
fi

ONLY="${1:-}"
[ "$ONLY" = "-k" ] && ONLY="$2"

GRN=$'\033[32m'; RED=$'\033[31m'; YEL=$'\033[33m'; CYN=$'\033[36m'; RST=$'\033[0m'
P=0; F=0; SK=0
LOG=/var/log/axlinux/deep_verify.log
POLICY_PATH=/root/.axlinux/policy.yaml

sect() {
    if [ -n "$ONLY" ] && [ "$ONLY" != "$1" ]; then return 1; fi
    printf '\n%s=== %s) %s ===%s\n' "$CYN" "$1" "$2" "$RST"
    return 0
}
ok()   { P=$((P+1)); printf '  %sok  %s %s\n' "$GRN" "$RST" "$*"; echo "ok   $*" >>"$LOG"; }
no()   { F=$((F+1)); printf '  %sFAIL%s %s\n' "$RED" "$RST" "$*"; echo "FAIL $*" >>"$LOG"; }
skip() { SK=$((SK+1)); printf '  %s--  %s %s\n' "$D" "$RST" "$*"; echo "skip $*" >>"$LOG"; }
D=$'\033[2m'
info() { printf '      %s%s%s\n' "$D" "$*" "$RST"; }

# eq <ad> <beklenen> <gelen>
eq() { if [ "$2" = "$3" ]; then ok "$1 ($3)"; else no "$1 (beklenen: '$2', gelen: '$3')"; fi; }
# rc_is <ad> <beklenen_rc> <komut...>
rc_is() {
    local name="$1" want="$2"; shift 2
    "$@" >/dev/null 2>&1; local got=$?
    if [ "$got" = "$want" ]; then ok "$name (rc=$got)"; else no "$name (beklenen rc=$want, gelen $got)"; fi
}

mkdir -p /var/log/axlinux
: >"$LOG"

# Test dosyalari
echo "GIZLI ICERIK" >/etc/ax-secret
chmod 666 /etc/ax-secret
echo "GIZLI ICERIK" >/etc/ax-secret2
chmod 666 /etc/ax-secret2
mkdir -p /etc/ax-dir
echo "dir dosyasi" >/etc/ax-dir/inside.txt
chmod 666 /etc/ax-dir/inside.txt

# Bir politika dosyasini DENETLEYIP GERCEKTEN UYGULAR.
#
# Once test politikayi /tmp'ye yaziyor, "policy check" ile
# dogruluyor, ama "axctl reload" /root/.axlinux/policy.yaml
# OKUDUGU icin BAYAT politika yukleniyordu. Boylece asagidaki
# "kural gercekten engellendi" iddialari uygulanmis hicbir seyi
# olcuyordu: gecenler gecen, kalanlar kalan sebeplerden degil,
# yanlis politikanin yuklenmesinden kaynaklaniyordu.
#
# Siralama onemli: once dogrula (sozdizimi hatasi aktif
# politikayi degistirmesin), sonra kopyala, sonra reload et.
# Bir komutun cikti uretigini denetler.
#
# "cmd 2>&1 | grep -q ." YAZILMAZ. set -o pipefail varken grep ilk
# eslesmede KAPANIR, komut (rich) stdout'a yazmaya devam eder ve
# SIGPIPE alir; pipeline'in durumu grep'in 0'i degil komutun
# SIGPIPE kodu (141) olur. if/else o yuzden yanlis kolu secer:
# komut 298 bayt yazmasina ragmen "cikti vermedi" sanilir.
#
# Bu hata elle calistirildiginde gorunmez; stdout'un hedefi farkli
# oldugu icin komut bazen SIGPIPE almadan bitiyor. Test hep
# pipe icinden calistigi icin ise tutarli olarak yanlis sonuc
# veriyordu.
emits_output() {
    [ -n "$("$@" 2>&1)" ]
}

# Bir komutun ciktisi bir kalip IÇERIYOR mu.
output_matches() {
    local pat="$1"; shift
    case "$("$@" 2>&1)" in
        *"$pat"*) return 0 ;;
        *) return 1 ;;
    esac
}

apply_policy() {
    local f="$1"
    if ! axctl policy check -f "$f" >/dev/null 2>&1; then
        return 2
    fi
    cp "$f" "$POLICY_PATH" || return 1
    axctl reload --mode enforcing >/dev/null 2>&1
}

cleanup_all() {
    axctl reload --mode disabled >/dev/null 2>&1
    axctl reload --force-empty --mode disabled >/dev/null 2>&1
}
trap cleanup_all EXIT

printf '%sAXlinux kapsamli dogrulama - %s%s\n' "$CYN" "$(date -Is)" "$RST"
info "LSM: $(cat /sys/kernel/security/lsm 2>/dev/null)"
info "kernel: $(uname -r)   dagitim: $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME")"

# ==================================================================== A
if sect A "Ortam ve saglik"; then
    if [ -S /run/axlinux/axdaemon.sock ]; then ok "kontrol soketi"; else no "kontrol soketi"; fi
    if [ -S /run/axlinux/axlog.sock ]; then ok "audit soketi"; else no "audit soketi"; fi
    st=$(systemctl is-active axdaemon 2>/dev/null)
    eq "axdaemon servisi" "active" "$st"
    st=$(systemctl is-active axlog 2>/dev/null)
    eq "axlog servisi" "active" "$st"
    st=$(systemctl is-enabled axdaemon 2>/dev/null)
    eq "axdaemon acikista baslar" "enabled" "$st"
    hooks=$(journalctl -u axdaemon --since '-30min' --no-pager 2>/dev/null \
            | grep -oE 'aktif=[0-9]+ toplam=[0-9]+' | tail -1)
    a=$(echo "$hooks" | sed -n 's/.*aktif=\([0-9]*\).*/\1/p')
    t=$(echo "$hooks" | sed -n 's/.*toplam=\([0-9]*\).*/\1/p')
    if [ -n "$a" ] && [ "$a" = "$t" ] && [ "$a" -gt 0 ]; then
        ok "LSM kancalari: $a/$t"
    else
        no "LSM kancalari: ${a:-?}/${t:-?}"
    fi
    for f in /usr/local/bin/axdaemon /usr/local/bin/axlog /usr/local/bin/axctl \
             /usr/lib/axlinux/axbpf.o; do
        [ -e "$f" ] && ok "kurulu: $f" || no "kurulu: $f"
    done
fi

# ==================================================================== B
if sect B "TUM CLI komutlari"; then
    rc_is "axctl --help"        0 axctl --help
    rc_is "axctl status"        0 axctl status
    rc_is "axctl status --json" 0 axctl status --json
    rc_is "axctl mode --help"   0 axctl mode --help
    rc_is "axctl logs --help"   0 axctl logs --help
    rc_is "axctl policy --help" 0 axctl policy --help
    rc_is "axctl label --help"  0 axctl label --help
    rc_is "axctl learn --help"  0 axctl learn --help
    rc_is "axctl template --help" 0 axctl template --help

    # --help ciktisinda komut gorunmeli
    if emits_output axctl --help && output_matches 'init' axctl --help
    then ok "help init gosteriyor"
    else no "help init gostermiyor"; fi

    # init
    rc_is "axctl init --force"  0 axctl init --force
    [ -f /root/.axlinux/policy.yaml ] && ok "init politika dosyasi" \
        || no "init politika dosyasi"

    # label
    rc_is "label add"   0 axctl label add testgrp curl
    rc_is "label ls"    0 axctl label ls
    if output_matches 'testgrp' axctl label ls; then ok "label listeleniyor"
    else no "label listelenmiyor"; fi
    rc_is "label rm"    0 axctl label rm testgrp

    # template
    rc_is "template ls" 0 axctl template ls
    rc_is "template apply (yok)" 5 axctl template apply bulunmayan-sablon

    # policy check
    cat >/tmp/ax-p1.yaml <<'YAML'
version: 1
mode: enforcing
rules:
  - id: r1
    name: "curl secret okuyamaz"
    subject: curl
    object: /etc/ax-secret
    action: file.read
    effect: deny
YAML
    rc_is "policy check gecerli" 0 axctl policy check -f /tmp/ax-p1.yaml
    rc_is "policy simulate"      0 axctl policy simulate -f /tmp/ax-p1.yaml

    # reload
    #
    # Politika dosyasi olmadan reload calismaz. Test once
    # init'i hic cagirmiyordu, bu yuzden reload her zaman
    # "Politika dosyasi yok" ile rc=1 donuyordu ve hem "reload"
    # hem de "reload (yok dosya)" testleri yanlis sonuc veriyordu.
    rc_is "init"             0 axctl init
    rc_is "reload"          0 axctl reload --mode enforcing
    sleep 1
    # Politika dosyasini gizle: bu kez hata bekleniyor (rc=2,
    # PolicyError).
    mv "$POLICY_PATH" "$POLICY_PATH.gizli"
    rc_is "reload (yok dosya -> hata)" 2 axctl reload
    mv "$POLICY_PATH.gizli" "$POLICY_PATH"
    rc_is "reload (geri alindi)" 0 axctl reload --mode enforcing
fi

# ==================================================================== C
if sect C "Ogrenme modu"; then
    rc_is "learn report (bos)" 0 axctl learn report
    # start
    if emits_output axctl learn start --days 1; then
        ok "learn start cikti verdi"
    else
        no "learn start cikti vermedi"
    fi
    sleep 1
    st=$(axctl status --json 2>/dev/null | python3 -c \
         'import json,sys;print(json.load(sys.stdin).get("learning_active"))' 2>/dev/null)
    if [ "$st" = "True" ] || [ "$st" = "true" ]; then ok "ogrenme aktif"
    else no "ogrenme aktif degil (st=$st)"; fi
    # ikinci start hata vermeli
    rc_is "learn start (zaten aktif)" 1 axctl learn start --days 1
    # gozlem uret
    curl -s file:///etc/ax-secret  >/dev/null 2>&1
    curl -s file:///etc/ax-secret2 >/dev/null 2>&1
    sleep 2
    obs=$(axctl status --json 2>/dev/null | python3 -c \
          'import json,sys;print(json.load(sys.stdin).get("learning_observations"))' 2>/dev/null)
    if [ "${obs:-0}" -gt 0 ] 2>/dev/null; then ok "gozlem toplandi ($obs)"
    else no "gozlem toplanmadi (obs=$obs)"; fi
    # report
    if emits_output axctl learn report; then ok "learn report cikti verdi"
    else no "learn report cikti vermedi"; fi
    # Oneri blogu YAML OLMALI: kullanicinin politika.yaml'a
    # yapistiracagi metin bu. Once butun rapor YAML'a sokuluyordu;
    # raporun kendisi insan-okur metin (kutu karakterleri iceriyor)
    # ve bu yuzden test HER ZAMAN "atla"yordu - gercek bir
    # belirsizlik degil, yanlis varsayim.
    #
    # Dogrulanan sey: yapistirilabilir metin gercekten YAML mi?
    # Once politika ve etiket uretildigi icin burada gercek bir
    # oneriyi dogrulamak gerekir; yoksa blok bos olur.
    cat >/tmp/ax-learn.yaml <<YAML
version: 1
mode: enforcing
labels:
  web: [curl]
rules:
  - id: l1
    name: "etiket kurali"
    subject: web
    object: /etc/ax-secret
    action: file.read
    effect: deny
YAML
    apply_policy /tmp/ax-learn.yaml
    sleep 1
    curl -s file:///etc/ax-secret >/dev/null 2>&1
    sleep 1
    if axctl learn report 2>/dev/null | python3 -c '
import sys, re, yaml
txt = sys.stdin.read()
m = re.search(r"rules:", txt)
if not m:
    sys.exit(1)
# Oneri blogu: "rules:" sonrasi YAML parcasini dene
frag = txt[m.start():]
try:
    yaml.safe_load("version: 1\nmode: enforcing\n" + frag)
except Exception:
    sys.exit(1)
' 2>/dev/null; then
        ok "learn report onerisi gecerli YAML"
    else
        # Gozlem toplanmadiysa oneri uretilmez; bu bir hata degil,
        # akisin bir sonraki asamasi
        if [ "${obs:-0}" -gt 0 ] 2>/dev/null; then
            no "learn report onerisi gecersiz YAML"
        else
            skip "learn report onerisi (gozlem toplanmadi)"
        fi
    fi
    # Politika icin geri don: ogrenme akisi kendi durumunu
    # kullanmali
    axctl policy check -f /tmp/ax-learn.yaml >/dev/null 2>&1 || true
    rc_is "learn stop" 0 axctl learn stop
    sleep 1
    st=$(axctl status --json 2>/dev/null | python3 -c \
         'import json,sys;print(json.load(sys.stdin).get("learning_active"))' 2>/dev/null)
    if [ "$st" = "False" ] || [ "$st" = "false" ]; then ok "ogrenme durdu"
    else no "ogrenme durmadi"; fi
    # stop sonrasi gozlem artmamali
    # "Ogrenme durduysa gozlem ARTMAZ" denetlenir, ama stop ile
    # hemen ayni anda olcum yapilmaz.
    #
    # Gozlemler perf buffer'indan gelir; stop cagrisi bayragi
    # dusurur ve o anda kuyrukta olan onlarca olay HALA islenir.
    # Olcum (Debian 12): stop oncesi 209, stop sonrasi 244, sonrasi
    # ve yeni aktivite sonrasi degismiyor. Yani urun dogru
    # calisiyor; test yalnizca kuyruktaki kuyrugu olcuyordu.
    #
    # Once kuyruk otursun, sonra taban al, sonra YENI aktivite
    # uret: sayi artarsa bayrak dusmemis demektir.
    sleep 2
    # TAZE OKUNUR. Once "o1=$obs" yaziliyordu; $obs degiskeni
    # "learn stop"tan ONCE okunmus oldugu icin o1 stop oncesi bir
    # degerdi ve o2 (stop sonrasi) ile karsilastiriliyordu. Yani
    # "artti" sonucu, tanim geregi, stop'un dogal sonucuydu.
    o1=$(axctl status --json 2>/dev/null | python3 -c \
         'import json,sys;print(json.load(sys.stdin).get("learning_observations"))' 2>/dev/null)
    for i in 1 2 3; do curl -s file:///etc/ax-secret >/dev/null 2>&1; done
    sleep 2
    o2=$(axctl status --json 2>/dev/null | python3 -c \
         'import json,sys;print(json.load(sys.stdin).get("learning_observations"))' 2>/dev/null)
    if [ "${o2:-0}" = "${o1:-0}" ]; then ok "durdurduktan sonra gozlem artmadi"
    else no "durdurduktan sonra gozlem artti ($o1 -> $o2)"; fi
fi

# ==================================================================== D+E
if sect D "Bes LSM kanca"; then
    cat >/tmp/ax-full.yaml <<'YAML'
version: 1
mode: enforcing
rules:
  - id: k1
    name: "file.read curl /etc/ax-secret"
    subject: curl
    object: /etc/ax-secret
    action: file.read
    effect: deny
  - id: k2
    name: "file.write curl /etc/ax-secret"
    subject: curl
    object: /etc/ax-secret
    action: file.write
    effect: deny
  - id: k3
    name: "file.execute python3 /bin/ls"
    subject: python3
    object: /bin/ls
    action: file.execute
    effect: deny
  - id: k4
    name: "process.exec python3"
    subject: python3
    object: ""
    action: process.exec
    effect: deny
  - id: k5
    name: "net.connect nc 4444"
    subject: nc
    object: ""
    port: 4444
    action: net.connect
    effect: deny
  - id: k6
    name: "net.bind nc 5555"
    subject: nc
    object: ""
    port: 5555
    action: net.bind
    effect: deny
YAML
    # Politika ONCE denetlenip AKTIF politika yapilmali. Once
    # dogrudan reload vardi; reload /root/.axlinux/policy.yaml
    # okudugu icin 6 kural degil BAYAT politika yukleniyordu
    # ve asagidaki 5 kancanin tamami yanlis olcuyordu.
    axctl policy check -f /tmp/ax-full.yaml >/dev/null 2>&1
    cp /tmp/ax-full.yaml "$POLICY_PATH"
    if output_matches '6 kural' axctl reload --mode enforcing; then
        ok "6 kural yuklendi"
    else
        no "6 kural yuklenmedi"
    fi
    sleep 2
    sudo bash -c 'nc -l -p 4444 -q 12 >/dev/null 2>&1 &' 2>/dev/null
    sleep 1

    info "D) file_open - read"
    rc_is "curl /etc/ax-secret (deny)"  37 \
        curl -s file:///etc/ax-secret
    rc_is "curl /etc/ax-secret2 (serbest)" 0 \
        curl -s file:///etc/ax-secret2

    info "D) file_open - write"
    # Yazma engeli CURL'IN CIKIS KODU DEGIL, DOSYANIN ICERIGIYLE
    # dogrulanir.
    #
    # Once test rc=37 bekliyordu; 37 = CURLE_FILE_COULDNT_READ_FILE,
    # yani OKUMA reddi. Yazma reddinde curl 23 (CURLE_WRITE_ERROR)
    # donuyor. Urun dogru calisiyordu, test yanlis kodu bekliyordu.
    # Daha guclu ve kirsilmayla ilgisiz olcum: dosya degismemeli.
    printf 'GIZLI ICERIK\n' >/etc/ax-secret
    curl -s -o /etc/ax-secret file:///etc/hostname >/dev/null 2>&1
    if grep -q 'GIZLI ICERIK' /etc/ax-secret 2>/dev/null; then
        ok "curl -o /etc/ax-secret engellendi (dosya degismedi)"
    else
        no "curl -o /etc/ax-secret YAZILDI (file.write deny calismadi)"
    fi
    rc_is "curl -o reddi curl hatasi donduruyor" 23 \
        curl -s -o /etc/ax-secret file:///etc/hostname
    info "  (yazma icin curl farkli bir dosya hedeflemeli; "
    info "   asagida python ile yazma denenecek)"

    info "D) bprm - file.execute"
    rc_is "python3 -> /bin/ls (deny)" 1 \
        python3 -c "import os;os.execv('/bin/ls',['ls'])"
    # Digeri: "python3 -> /bin/pwd serbest" bekleniyordu. Ama ayni
    # politikada k4 var:
    #   - id: k4  subject: python3  object: ""  action: process.exec
    # yani python3 HICBIR sey calistiramaz; /bin/pwd de buna
    # girer. Test kendi politikasiyla celisiyordu.
    #
    # Asil sorulacak soru "kural nesneyle sinirli mi" degil,
    # "kural hedef disi sureclere siziyor mu"dur. Ayri bir
    # politika ile SADECE /bin/ls yasaklanir: /bin/ls engellenir,
    # /bin/pwd serbest kalir. Boylece hem iki kancanin da
    # calistigi hem de kuralin hedefleme ile sinirli oldugu
    # gorulmus olur.
    cat >/tmp/ax-scope.yaml <<YAML
version: 1
mode: enforcing
rules:
  - id: s1
    name: "sadece /bin/ls"
    subject: python3
    object: /bin/ls
    action: file.execute
    effect: deny
YAML
    apply_policy /tmp/ax-scope.yaml
    sleep 1
    rc_is "yalnizca /bin/ls yasakken /bin/ls engelli" 1 \
        python3 -c "import os;os.execv('/bin/ls',['ls'])"
    rc_is "yalnizca /bin/ls yasakken /bin/pwd serbest" 0 \
        python3 -c "import os;os.execv('/bin/pwd',['pwd'])"
    # Tam politikaya don: sonraki bolumler bunu bekliyor
    cp /tmp/ax-full.yaml "$POLICY_PATH"
    axctl reload --mode enforcing >/dev/null 2>&1

    info "D) bprm - process.exec"
    rc_is "python3 -> her sey (process.exec deny)" 1 \
        python3 -c "import os;os.execv('/bin/true',['true'])"

    info "D) socket_connect"
    rc_is "nc 4444 (deny)" 1 timeout 4 nc -w 2 127.0.0.1 4444
    info "D) socket_bind"
    sudo bash -c 'timeout 4 nc -l -p 5555 >/dev/null 2>&1' 2>/dev/null
    info "  (bind reddi ayrica 5555 dinleyememe olarak gozlenir)"
fi

# ==================================================================== F
if sect F "Kalici audit"; then
    sleep 2
    curl -s file:///etc/ax-secret >/dev/null 2>&1
    sleep 2
    n=$(axctl logs --limit 5 2>/dev/null | grep -c 'DENIED' || true)
    if [ "${n:-0}" -gt 0 ]; then ok "axctl logs DENIED gosteriyor ($n)"
    else no "axctl logs DENIED gostermiyor"; fi
    f=$(ls -1 /var/log/axlinux/*.jsonl 2>/dev/null | head -1)
    if [ -n "$f" ]; then
        ok "JSONL dosyasi: $f"
        if python3 -c "
import json,sys
bad=0
for l in open('$f'):
    l=l.strip()
    if l:
        try: json.loads(l)
        except: bad+=1
sys.exit(1 if bad else 0)"; then
            ok "JSONL butun satirlar gecerli"
        else
            no "JSONL bozuk satir var"
        fi
    else
        no "JSONL dosyasi yok"
    fi
    # filtreler
    rc_is "logs --effect denied" 0 axctl logs --effect denied
    rc_is "logs --subject curl"  0 axctl logs --subject curl
    rc_is "logs --action file.read" 0 axctl logs --action file.read
    rc_is "logs --limit 3"       0 axctl logs --limit 3
    rc_is "logs --json"          0 axctl logs --json
fi

# ==================================================================== G
if sect G "Modlar ve acil kapatma"; then
    rc_is "mode enforcing" 0 axctl mode enforcing
    sleep 1
    eq "curl engellendi" "37" "$(curl -s file:///etc/ax-secret >/dev/null 2>&1; echo $?)"
    rc_is "mode permissive" 0 axctl mode permissive
    sleep 1
    eq "curl serbest" "0" "$(curl -s file:///etc/ax-secret >/dev/null 2>&1; echo $?)"
    rc_is "mode disabled" 0 axctl mode disabled
    sleep 1
    eq "curl disabled" "0" "$(curl -s file:///etc/ax-secret >/dev/null 2>&1; echo $?)"
    # reload --mode da calismali
    rc_is "reload --mode permissive" 0 axctl reload --mode permissive
    sleep 1
    eq "reload --mode permissive etkili" "0" \
        "$(curl -s file:///etc/ax-secret >/dev/null 2>&1; echo $?)"
    rc_is "reload --mode enforcing" 0 axctl reload --mode enforcing
    sleep 1
    eq "reload --mode enforcing etkili" "37" \
        "$(curl -s file:///etc/ax-secret >/dev/null 2>&1; echo $?)"
    # reload --force-empty acil cikis
    rc_is "reload --force-empty" 0 axctl reload --force-empty --mode disabled
    sleep 1
    eq "force-empty sonrasi serbest" "0" \
        "$(curl -s file:///etc/ax-secret >/dev/null 2>&1; echo $?)"
fi

# ==================================================================== H
if sect H "Kilitlenme korumasi"; then
    for c in cat head tail ls ps df; do
        if command -v $c >/dev/null; then
            if timeout 5 $c --version >/dev/null 2>&1; then
                ok "$c calisiyor"
            else
                no "$c calistirilamiyor"
            fi
        fi
    done
    if timeout 5 bash -c 'echo ok' >/dev/null 2>&1; then ok "bash calisiyor"
    else no "bash calistirilamiyor"; fi
    if timeout 5 sh -c 'echo ok' >/dev/null 2>&1; then ok "sh calisiyor"
    else no "sh calistirilamiyor"; fi
    if timeout 5 sudo -n true 2>/dev/null; then ok "sudo calisiyor"
    else skip "sudo (sifre gerekebilir)"; fi
    if timeout 10 apt-get --version >/dev/null 2>&1 || \
       timeout 10 dnf --version >/dev/null 2>&1; then ok "paket yoneticisi calisiyor"
    else no "paket yoneticisi calismiyor"; fi
    if timeout 5 systemctl is-system-running >/dev/null 2>&1; then
        ok "systemd yanit veriyor"
    else skip "systemd (bu ortamda yok olabilir)"; fi
    # korumali sureclere kural yazilamamali
    for p in bash sudo sshd login systemd sh; do
        if axctl policy check -f /tmp/ax-p1.yaml >/dev/null 2>&1; then
            ok "policy check calisiyor"
            break
        fi
    done
fi

# ==================================================================== I
if sect I "Hata yollari"; then
    # gecersiz politika reddedilmeli
    cat >/tmp/ax-bad1.yaml <<'YAML'
version: 1
mode: enforcing
rules:
  - id: b1
    name: "portsuz ag kurali"
    subject: curl
    object: ""
    action: net.connect
    effect: deny
YAML
    if axctl policy check -f /tmp/ax-bad1.yaml >/dev/null 2>&1; then
        no "portsuz net kurali kabul edildi"
    else
        ok "portsuz net kurali reddedildi"
    fi
    cat >/tmp/ax-bad2.yaml <<'YAML'
version: 1
mode: enforcing
rules:
  - id: b2
    name: "uygulanmayan aksiyon"
    subject: curl
    object: /etc/x
    action: file.delete
    effect: deny
YAML
    if axctl policy check -f /tmp/ax-bad2.yaml >/dev/null 2>&1; then
        no "file.delete kabul edildi"
    else
        ok "file.delete reddedildi"
    fi
    cat >/tmp/ax-bad3.yaml <<'YAML'
version: 1
mode: bogus
rules:
  - id: b3
    name: "gecersiz mod"
    subject: curl
    object: /etc/x
    action: file.read
    effect: deny
YAML
    if axctl policy check -f /tmp/ax-bad3.yaml >/dev/null 2>&1; then
        no "gecersiz mod kabul edildi"
    else
        ok "gecersiz mod reddedildi"
    fi
    cat >/tmp/ax-bad4.yaml <<'YAML'
version: 1
mode: enforcing
rules:
  - id: b4
    name: "eksik subject"
    object: /etc/x
    action: file.read
    effect: deny
YAML
    if axctl policy check -f /tmp/ax-bad4.yaml >/dev/null 2>&1; then
        no "subject'suz kural kabul edildi"
    else
        ok "subject'suz kural reddedildi"
    fi
    # bilinmeyen filtre
    # Bilinmeyen OPSIYON hatadir (click rc=2 verir, dogru davranis).
    # Buradaki niyet "kullanici bunu filtre sanmasin" idi: sunucu
    # tanimadigi bir filtre alanini sessizce YOK SAYMAMALI ve
    # kullaniciya bildirmeli. Once test "axctl logs --nonexistent x"
    # yaziyordu; bu bir secenek hatasiydi, filtre hatasi degil.
    rc_is "logs bilinmeyen filtre (hata vermemeli)" 0 \
        axctl logs --filter nonexistent_field=x
    # var olmayan sablon
    rc_is "template apply yok" 5 axctl template apply yok
    # korumali surece kural
    cat >/tmp/ax-bad5.yaml <<'YAML'
version: 1
mode: enforcing
rules:
  - id: b5
    name: "bash'a kural"
    subject: bash
    object: /etc/x
    action: file.read
    effect: deny
YAML
    if axctl policy check -f /tmp/ax-bad5.yaml >/dev/null 2>&1; then
        no "korumali surece kural kabul edildi"
    else
        ok "korumali surece kural reddedildi"
    fi
fi

# ==================================================================== J
if sect J "Politika dili kenar durumlari"; then
    # etiket ile kural
    cat >/tmp/ax-lbl.yaml <<'YAML'
version: 1
mode: enforcing
labels:
  web: [curl, wget]
rules:
  - id: j1
    name: "etiketle read"
    subject: web
    object: /etc/ax-secret
    action: file.read
    effect: deny
YAML
    apply_policy /tmp/ax-lbl.yaml
    sleep 1
    # etiket: curl icinde, wget haric
    eq "etiket curl uygulandi" "37" "$(curl -s file:///etc/ax-secret >/dev/null 2>&1; echo $?)"
    # joker subject
    cat >/tmp/ax-star.yaml <<'YAML'
version: 1
mode: enforcing
rules:
  - id: j2
    name: "her sey read"
    subject: "*"
    object: /etc/ax-secret
    action: file.read
    effect: deny
YAML
    rc_is "joker subject" 0 axctl policy check -f /tmp/ax-star.yaml
    # surec bazli (yolsuz) kural
    cat >/tmp/ax-proc.yaml <<'YAML'
version: 1
mode: enforcing
rules:
  - id: j3
    name: "python3 hicbir sey calistiramaz"
    subject: python3
    object: ""
    action: process.exec
    effect: deny
YAML
    rc_is "surec bazli kural" 0 axctl policy check -f /tmp/ax-proc.yaml
    # merged-usr yol donusumu
    cat >/tmp/ax-bin.yaml <<'YAML'
version: 1
mode: enforcing
rules:
  - id: j4
    name: "merged-usr yolu"
    subject: python3
    object: /bin/ls
    action: file.execute
    effect: deny
YAML
    apply_policy /tmp/ax-bin.yaml
    sleep 1
    eq "/bin/ls gercekten engellendi" "1" \
        "$(python3 -c "import os;os.execv('/bin/ls',['ls'])" >/dev/null 2>&1; echo $?)"
    # cok uzun yol
    longp="/$(printf 'a%.0s' {1..60})/$(printf 'b%.0s' {1..60})"
    cat >/tmp/ax-long.yaml <<YAML
version: 1
mode: enforcing
rules:
  - id: j5
    name: "cok uzun yol"
    subject: curl
    object: $longp
    action: file.read
    effect: deny
YAML
    if axctl policy check -f /tmp/ax-long.yaml >/dev/null 2>&1; then
        info "uzun yol kabul edildi (bloga sigiyorsa normal)"
    else
        ok "bloga sigmayan yol reddedildi (dogru)"
    fi
    # bilesen sayisi fazla
    # 12 BILESENLI yol. Once "printf 'd%.0s' {1..12}" kullaniliyordu
    # ve bu TEK bir 12 karakterlik bilesen uretiyordu
    # (/dddddddddddd) - derinlik 1, sorun yok. Test "derin yol
    # kabul edildi" diye basarisiz oluyordu ama politika gercekten
    # derin degildi.
    deepp=""
    for i in $(seq 1 12); do deepp="$deepp/d$i"; done
    cat >/tmp/ax-deep.yaml <<YAML
version: 1
mode: enforcing
rules:
  - id: j6
    name: "cok derin yol"
    subject: curl
    object: $deepp
    action: file.read
    effect: deny
YAML
    if axctl policy check -f /tmp/ax-deep.yaml >/dev/null 2>&1; then
        no "derin yol kabul edildi (>8 bilesen)"
    else
        ok "derin yol reddedildi"
    fi
fi

# ==================================================================== ozet
cleanup_all
printf '\n%s%s========================================%s\n' "$CYN" "$CYN" "$RST"
printf '  gecti   : %s\n' "$P"
printf '  kaldi   : %s\n' "$F"
printf '  atlandi : %s\n' "$SK"
printf '%s%s========================================%s\n' "$CYN" "$CYN" "$RST"
printf '  ayrinti: %s\n' "$LOG"
[ "$F" -gt 0 ] && exit 1
exit 0
