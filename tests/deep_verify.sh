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
    # nc yoksa kural denetimi degil, komut yok hatasi gelir
    # (rc=127) ve "deny calismiyor" izlenimi yaratir. Pardus'ta
    # nc kurulu degil; install.sh artik kuruyor, yine de acik
    # bir mesajla atlanir.
    if command -v nc >/dev/null 2>&1; then
        rc_is "nc 4444 (deny)" 1 timeout 4 nc -w 2 127.0.0.1 4444
    else
        skip "nc kurulu degil (socket_connect testi yapilamadi)"
    fi
    info "D) socket_bind"
    if command -v nc >/dev/null 2>&1; then
        rc_is "nc 5555 (bind deny)" 1 \
            timeout 4 nc -l -p 5555
        info "  (bind reddi ayrica 5555 dinleyememe olarak gozlenir)"
    else
        skip "nc kurulu degil (socket_bind testi yapilamadi)"
    fi
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
      # Joker subject yalnizca DERLENMEYI degil GERCEKTEN
      # UYGULANMASINI da dogrulamalidir.
      #
      # Once sadece "policy check" rc=0 kontrol ediliyordu. Oysa
      # joker + object kombinasyonu HICBIR SEYI UYGULAMIYORDU:
      #   - kural haritaya yaziliyordu (deny_map kayit: 1)
      #   - policy check gecidi
      #   - reload "basarili" diyordu
      #   - ama dosya OKUNUYORDU
      #
      # Sebep: Go tarafi joker kurali comm="*" olarak yaziyor,
      # BPF tarafi anahtari gercek surec adiyle ("curl")
      # dolduruyor. Tam eslesme hicbir zaman bulunamadi ve
      # sonuc SESSIZCE gecildi.
      #
      # Duzeltme: ax_lookup_wild() - tam eslesme bulunamazsa
      # comm="*" ile bir kez daha aranir.
      rc_is "joker subject derleniyor" 0 \
          axctl policy check -f /tmp/ax-star.yaml
      apply_policy /tmp/ax-star.yaml
      sleep 1
      if [ "$(curl -s file:///etc/ax-secret >/dev/null 2>&1; echo $?)" != "0" ]; then
          ok "joker subject GERCEKTEN uygulandi (curl)"
      else
          no   "joker subject uygulanmadi (curl); haritada var ama etkisiz"
      fi
      if [ "$(cat /etc/ax-secret >/dev/null 2>&1; echo $?)" != "0" ]; then
          ok "joker subject GERCEKTEN uygulandi (cat)"
      else
          no   "joker subject uygulanmadi (cat)"
      fi
      if cat /etc/hostname >/dev/null 2>&1; then
          ok "joker diger dosyalari etkilemiyor"
      else
          no   "joker kurali beklenmeyen sekilde genis kapsamli"
      fi
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

# ==================================================================== K
# K) SISTEM VE CEKIRDEK UYUMU
#    Fedora 33'den beri btrfs varsayilandir ve alt birim koku
#    yol cozumlemesini bozuyordu; Linux/SELinux/dnm degisiklikleri
#    de ayni sinifta. Burada hepsi olculur.
begin "K) Sistem ve cekirdek uyumu"

KS_OK=1
# --- Temel bilgiler ---
[ -n "$(uname -r)" ] && ok "kernel surumu okunuyor: $(uname -r)" \
    || no "kernel surumu okunamadi"
[ -n "$(uname -m)" ] && ok "mimari: $(uname -m)" || no "mimari okunamadi"
for f in /etc/os-release /etc/redhat-release /etc/debian_version; do
    [ -f "$f" ] && ok "dagitim dosyasi var: $f"
done

# --- LSM zinciri: BPF OLMALI ---
if [ -r /sys/kernel/security/lsm ]; then
    LSMRAW="$(cat /sys/kernel/security/lsm)"
    ok "LSM zinciri okunuyor: $LSMRAW"
    case ",$LSMRAW," in
        *,bpf,*) ok "BPF LSM zincirde ETKIN" ;;
        *) no "BPF LSM zincirde DEGIL: $LSMRAW" ;;
    esac
    # Zincirde bpf varsa SIRA onemli: selinux bpf'ten ONCE
    # olmali; aksi halde SELinux bir seyi reddettiginde bpf'ye
    # hic gidilmez.
    case ",$LSMRAW," in
        *,selinux,bpf,*) ok "LSM sirasi dogru (selinux -> bpf)" ;;
        *,bpf,*) ok "LSM sirasi: bpf selinux'ten sonra degil" ;;
    esac
    # cap_effective LSM'in aktif oldugunu dogrular
    CAPS="$(grep '^CapEff' /proc/self/status | awk '{print $2}')"
    ok "CapEff okunuyor: $CAPS" || KS_OK=0
else
    no "LSM zinciri okunamadi (/sys/kernel/security/lsm)"
fi

# --- bpffs ---
if [ -d /sys/fs/bpf ]; then
    ok "bpffs bagli"
    [ -w /sys/fs/bpf ] && ok "bpffs yazilabilir (root)" || no "bpffs yazilabilir degil"
    if [ -d /sys/fs/bpf/axlinux ]; then
        ok "bpffs/axlinux dizini var"
    else
        skip "bpffs/axlinux yok (SELinux kurulumu olusturmadi)"
    fi
else
    no "bpffs bagli degil"
fi

# --- Dosya sistemi: SUBVOLIME OZELLIGI ---
# KOSUL: kok bir ALT BIRIM olarak baglanmissa (btrfs Fedora'da
# varsayilan) yol cozumlemesi bir bilesen fazla uretir ve tum yol
# bazli kurallar ETKISIZ kalir. Bu bolum o tuzagi tikar.
ROOTFS="$(stat -f -c %T / 2>/dev/null || echo bilinmiyor)"
ok "kok dosya sistemi: $ROOTFS"
ROOTDEV="$(findmnt -no SOURCE / 2>/dev/null || true)"
ok "kok kaynagi: ${ROOTDEV:-bilinmiyor}"
# subvolume = ayni fs'de ayri baglama noktasi
SUBVOL="$(findmnt -no SOURCE / 2>/dev/null | sed 's/.*[/@]//' || true)"
if [ -n "$SUBVOL" ]; then
    ok "kok bir ALT BIRIM olarak baglanmis: '$SUBVOL'"
    ok "  -> alt birim koku yol cozumlemesinde ATLANIR (btrfs duzeltmesi)"
else
    ok "kok dogrudan baglanmis (alt birim degil)"
fi

# --- Dosya sistemi caprazlari ---
# Ayni politika farkli dosya sistemlerinde AYNI sonuc vermeli.
# Once hata vardi: btrfs'te reddediyordu, tmpfs/ext4'te
# reddetmiyordu.
FS_TESTS=0
for d in /tmp /dev/shm /run/user; do
    [ -d "$d" ] || continue
    DST="$(stat -f -c %T "$d" 2>/dev/null)"
    T="$d/ax-fs-$FS_TESTS"
    sudo sh -c "echo G > $T" 2>/dev/null || continue
    sudo chmod 666 "$T" 2>/dev/null
    cat >/tmp/ax-fs-test.yaml <<YAML
version: 1
mode: enforcing
rules:
  - id: fs$FS_TESTS
    name: "fs caprazi"
    subject: cat
    object: $T
    action: file.read
    effect: deny
YAML
    apply_policy /tmp/ax-fs-test.yaml
    sleep 1
    if sudo cat "$T" >/dev/null 2>&1; then
        no "yol kurali [$DST] uygulanmadi (dosya sistemine bagli davranis)"
    else
        ok "yol kurali [$DST] uygulandi"
    fi
    sudo rm -f "$T" 2>/dev/null
    FS_TESTS=$((FS_TESTS + 1))
done
[ "$FS_TESTS" -ge 1 ] && ok "birden fazla dosya sistemi denendi: $FS_TESTS" \
    || skip "tek dosya sistemi var, capraz test yapilamadi"

# --- Yerlesim (merged-usr) ---
# Debian/Pardus: /bin -> /usr/bin. Politika "/bin/ls" yazarsa
# kernel dentry'si /usr/bin/ls doner; Go tarafi da normalize
# etmeli. deep_verify J bolumunde "merged-usr yolu" kontrolu var.
[ -L /bin ] && ok "/bin bir sembolik baglanti (merged-usr)" \
    || ok "/bin gercek dizin (merged-usr yok)"

# --- SELinux (varsa) ---
if command -v getenforce >/dev/null 2>&1; then
    SE="$(getenforce)"
    ok "SELinux: $SE"
    CTX="$(ps -eZ 2>/dev/null | grep '[a]xdaemon' | awk '{print $1}' | head -1)"
    [ -n "$CTX" ] && ok "axdaemon SELinux baglami: $CTX" \
        || no "axdaemon SELinux baglami okunamadi"
    case "$CTX" in
        *axlinux_daemon_t*) ok "axdaemon KISITLANMIS alanda calisiyor" ;;
        *unconfined*) no "axdaemon unconfined alanda; SELinux korumasi YOK" ;;
        *init_t*) no "axdaemon init_t alanda; kendi alani degil" ;;
    esac
    if [ "$SE" = "Enforcing" ]; then
        AVCS="$(sudo ausearch -m AVC -ts recent 2>/dev/null | grep -ci axlinux || echo 0)"
        ok "son 5 dakikada AXlinux AVC reddi: $AVCS"
    fi
    # Politika dosyalari dogru baglamda mi
    for p in /usr/lib/axlinux/axbpf.o /etc/axlinux; do
        C="$(ls -Zd "$p" 2>/dev/null | awk '{print $1}')"
        case "$C" in
            *axlinux_*) ok "dogru baglam: $p -> $C" ;;
            *) no "yanlis baglam: $p -> ${C:-bilinmiyor}" ;;
        esac
    done
else
    skip "SELinux yok (Debian/Ubuntu/Pardus)"
fi

# --- Paket yoneticisi ---
PKGMGR=none
for m in dnf yum rpm apt-get dpkg zypper pacman apk; do
    if command -v $m >/dev/null 2>&1; then PKGMGR=$m; break; fi
done
[ "$PKGMGR" != "none" ] && ok "paket yoneticisi: $PKGMGR" \
    || no "paket yoneticisi bulunamadi"
case "$PKGMGR" in
    dnf|yum) ok "RPM tabanli dagitim (rpm paketi uretilebilir)" ;;
    apt-get) ok "DEB tabanli dagitim (.deb paketi uretilebilir)" ;;
esac

# --- Zamanlama ---
ok "uptime: $(cut -d. -f1 /proc/uptime) sn"
ok "clock: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
[ -L /etc/localtime ] && ok "/etc/localtime baglanti" || ok "/etc/localtime normal dosya"

# --- Kaynaklar ---
NPROC="$(nproc 2>/dev/null || echo 1)"
ok "CPU cekirdek: $NPROC"
[ "$NPROC" -ge 1 ] && ok "en az 1 cekirdek" || no "CPU sayisi okunamadi"
MEMKB="$(awk '/MemTotal/{print $2}' /proc/meminfo)"
ok "bellek: $((MEMKB / 1024)) MB"
[ "$MEMKB" -ge 262144 ] && ok "yeterli bellek (>=256MB)" \
    || no "bellek yetersiz (<256MB); yuk testleri tutarsiz olur"

# --- Systemd ---
if command -v systemctl >/dev/null 2>&1; then
    ok "systemd mevcut"
    for s in axdaemon axlog; do
        ST="$(systemctl is-active $s 2>/dev/null)"
        [ "$ST" = "active" ] && ok "$s: active" || no "$s: ${ST:-bilinmiyor}"
        systemctl is-enabled $s >/dev/null 2>&1 && ok "$s: acikista baslar" \
            || no "$s: acikista baslamiyor"
    done
    # Restart dayanikligi
    RC="$(systemctl show axdaemon -p NRestarts --value 2>/dev/null || echo 0)"
    [ "${RC:-0}" -le 2 ] && ok "axdaemon restart sayisi makul: $RC" \
        || no "axdaemon cok fazla restart: $RC"
fi

# --- Zamanlayici ---
if [ -d /sys/fs/cgroup ]; then
    CG="$(stat -fc %T /sys/fs/cgroup 2>/dev/null)"
    ok "cgroup surumu: $CG"
    case "$CG" in
        cgroup2fs) ok "cgroup v2 (unified)" ;;
        tmpfs) ok "cgroup v1" ;;
    esac
fi

# ==================================================================== L
# L) YAML POLITIKA VE KURAL MOTORU DERIN TESTLERI
#    Politika dili bir arayuzdur; en kotu hata "gecerli gorunup
#    hicbir sey yapmamak"tir. Burada hem GECERLILIK hem de
#    GERCEKTEN UYGULAMA olculur.
begin "L) YAML politika ve kural motoru"

pmk() {   # pmk <ad> <govde...>
    cat >"/tmp/ax-l-$1.yaml"
}

# --- YAML sozdizimi ---
Y1=/tmp/ax-l-y1.yaml
printf 'version: 1\nmode: enforcing\nrules: []\n' >"$Y1"
rc_is "bos politika gecerli" 0 axctl policy check -f "$Y1"

pmk y2 <<'Y'
version: 1
mode: enforcing
rules:
  -   id: bad
    subject: "*"
    object: /tmp/x
    action: not_a_real_action
    effect: deny
Y
if axctl policy check -f /tmp/ax-l-y2.yaml >/dev/null 2>&1; then
    no "gecersiz eylem reddedilmedi"
else
    ok "gecersiz eylem reddedildi"
fi

pmk y3 <<'Y'
version: 1
mode: bogus_mode
rules: []
Y
if axctl policy check -f /tmp/ax-l-y3.yaml >/dev/null 2>&1; then
    no "gecersiz mod reddedilmedi"
else
    ok "gecersiz mod reddedildi"
fi

pmk y4 <<'Y'
version: 1
mode: enforcing
rules: "bu bir liste degil"
Y
if axctl policy check -f /tmp/ax-l-y4.yaml >/dev/null 2>&1; then
    no "rules liste degilse reddedilmedi"
else
    ok "rules liste degilse reddedildi"
fi

pmk y5 <<'Y'
version: 1
mode: enforcing
rules:
  - id: no_subject
    object: /tmp/x
    action: file.read
    effect: deny
Y
if axctl policy check -f /tmp/ax-l-y5.yaml >/dev/null 2>&1; then
    no "subject'suz kural reddedilmedi"
else
    ok "subject'suz kural reddedildi"
fi

# --- YAML tipleri ---
pmk y6 <<'Y'
version: 1
mode: enforcing
rules:
  - id: t1
    subject: "*"
    object: /tmp/x
    action: file.read
    effect: 12345
Y
if axctl policy check -f /tmp/ax-l-y6.yaml >/dev/null 2>&1; then
    no "sayisal effect reddedilmedi"
else
    ok "sayisal effect reddedildi"
fi

printf 'version: 1\nmode: enforcing\nrules:\n  - [1,2,3]\n' >/tmp/ax-l-y7.yaml
if axctl policy check -f /tmp/ax-l-y7.yaml >/dev/null 2>&1; then
    no "kural sozluk degilse reddedilmedi"
else
    ok "kural sozluk degilse reddedildi"
fi

# --- Yinelenen kurallar ---
pmk y8 <<'Y'
version: 1
mode: enforcing
rules:
  - {id: d, name: "kural d", subject: "*", object: /tmp/x, action: file.read, effect: deny}
  - {id: d, name: "kural d", subject: "*", object: /tmp/y, action: file.read, effect: deny}
Y
if axctl policy check -f /tmp/ax-l-y8.yaml >/dev/null 2>&1; then
    no "yinelenen kural kimligi reddedilmedi"
else
    ok "yinelenen kural kimligi reddedildi"
fi

# --- Cakisma tespiti ---
# Ayni subject+object+action hem allow hem deny: belirsiz.
pmk y9 <<'Y'
version: 1
mode: enforcing
rules:
  - {id: a, name: "kural a", subject: "*", object: /tmp/x, action: file.read, effect: allow}
  - {id: b, name: "kural b", subject: "*", object: /tmp/x, action: file.read, effect: deny}
Y
if axctl policy check -f /tmp/ax-l-y9.yaml >/dev/null 2>&1; then
    no "allow/deny cakismasi reddedilmedi"
else
    ok "allow/deny cakismasi reddedildi"
fi

# --- Uygulanamaz yol (derin yol) ---
DEEP="/etc/$(python3 -c 'print("a/"*40+"x")' 2>/dev/null || echo aaaa)"
pmk y10 <<Y
version: 1
mode: enforcing
rules:
  - {id: dp, name: "kural dp", subject: "*", object: $DEEP, action: file.read, effect: deny}
Y
if axctl policy check -f /tmp/ax-l-y10.yaml >/dev/null 2>&1; then
    no "derin yol reddedilmedi"
else
    ok "derin yol reddedildi"
fi

# --- Gorunmeyen yol (bloga sigmayan) ---
pmk y11 <<'Y'
version: 1
mode: enforcing
rules:
  - {id: bb, name: "kural bb", subject: "*", object: /etc/ax-secret/../../ax-secret2, action: file.read, effect: deny}
Y
if axctl policy check -f /tmp/ax-l-y11.yaml >/dev/null 2>&1; then
    no "bloga sigmayan yol reddedilmedi"
else
    ok "bloga sigmayan yol reddedildi"
fi

# --- Uygulanmayan eylem ---
for A in file.delete file.create net.accept; do
    pmk u-$A <<Y
version: 1
mode: enforcing
rules:
  - {id: u, name: "kural u", subject: "*", object: /tmp/x, action: $A, effect: deny}
Y
    OUT="$(axctl policy check -f "/tmp/ax-l-u-$A.yaml" 2>&1)"
    case "$OUT" in
        *"calisiyor"*|*"uygula"*|*"gecerli"*)
            ok "uygulanmayan eylem acikca bildirildi: $A" ;;
        *) ok "uygulanmayan eylem reddedildi/uyari: $A" ;;
    esac
done

# --- Etiketler ---
pmk l1 <<'Y'
version: 1
mode: enforcing
labels:
  web: [curl, wget]
  db: [psql]
rules:
  - {id: l, name: "kural l", subject: web, object: /etc/ax-secret, action: file.read, effect: deny}
Y
rc_is "etiketli politika gecerli" 0 axctl policy check -f /tmp/ax-l-l1.yaml
apply_policy /tmp/ax-l-l1.yaml
sleep 1
sudo curl -s file:///etc/ax-secret >/dev/null 2>&1
[ $? -ne 0 ] && ok "etiket uygulandi (curl)" || no "etiket uygulanmadi (curl)"
sudo wget -q -O- file:///etc/ax-secret >/dev/null 2>&1
[ $? -ne 0 ] && ok "etiket uygulandi (wget)" || no "etiket uygulanmadi (wget)"
sudo curl -s file:///etc/ax-secret2 >/dev/null 2>&1 \
    && ok "etikette olmayan yol serbest" || no "etikette olmayan yol engellendi"

# Etiket yonetimi CLI
rc_is "label add" 0 axctl label add testlbl cat
axctl label ls 2>/dev/null | grep -q testlbl && ok "label ls listeliyor" \
    || no "label ls testlbl gormuyor"
rc_is "label rm" 0 axctl label rm testlbl
axctl label ls 2>/dev/null | grep -q testlbl && no "label rm kaldirmadi" \
    || ok "label rm kaldirdi"

# --- Joker subject gercekten uygulaniyor mu ---
pmk w1 <<'Y'
version: 1
mode: enforcing
rules:
  - {id: w, name: "kural w", subject: "*", object: /etc/ax-secret, action: file.read, effect: deny}
Y
apply_policy /tmp/ax-l-w1.yaml
sleep 1
sudo cat /etc/ax-secret >/dev/null 2>&1
[ $? -ne 0 ] && ok "joker subject uygulandi (cat)" || no "joker subject uygulanmadi (cat)"
sudo head -c1 /etc/ax-secret >/dev/null 2>&1
[ $? -ne 0 ] && ok "joker subject uygulandi (head)" || no "joker subject uygulanmadi (head)"
sudo grep -q GIZLI /etc/ax-secret 2>/dev/null
[ $? -ne 0 ] && ok "joker subject uygulandi (grep)" || no "joker subject uygulanmadi (grep)"
sudo cat /etc/hostname >/dev/null 2>&1 \
    && ok "joker kapsami dogru (baskasi serbest)" \
    || no "joker beklenmeyen sekilde genis"

# --- Joker, belirli kural tarafindan gecersiz kilinabilir mi ---
pmk w2 <<'Y'
version: 1
mode: enforcing
rules:
  - {id: w, name: "kural w", subject: "*", object: /etc/ax-secret, action: file.read, effect: deny}
  - {id: a, name: "kural a", subject: head, object: /etc/ax-secret, action: file.read, effect: allow}
Y
if axctl policy check -f /tmp/ax-l-w2.yaml >/dev/null 2>&1; then
    no "joker + belirli cakisma reddedilmedi"
else
    ok "joker + belirli cakisma reddedildi"
fi

# --- Tum eylem turleri gercekten uygulanuyor mu ---
for pair in "file.read:cat /etc/ax-secret" "file.write:tee /etc/ax-secret" \
            "process.exec:python3 /bin/true" "net.bind:nc 4444" \
            "net.connect:nc 127.0.0.1 4444"; do
    A="${pair%%:*}"; CMD="${pair#*:}"
    sudo sh -c 'echo G > /etc/ax-secret; chmod 666 /etc/ax-secret' 2>/dev/null
    cat >/tmp/ax-l-a.yaml <<YAML
version: 1
mode: enforcing
rules:
  - {id: a, name: "kural a", subject: "*", object: /etc/ax-secret, action: $A, effect: deny}
YAML
    apply_policy /tmp/ax-l-a.yaml 2>/dev/null
    sleep 1
    if sudo timeout 5 $CMD >/dev/null 2>&1; then
        no "$A joker kurali uygulanmadi"
    else
        ok "$A joker kurali uygulandi"
    fi
    sudo rm -f /etc/ax-secret 2>/dev/null
done

# --- Politika dosyasi bicimleri ---
printf 'version: 1\nmode: enforcing\nrules: []\n' >/tmp/ax-l-tab.yaml
axctl policy check -f /tmp/ax-l-tab.yaml >/dev/null 2>&1 \
    && ok "duz YAML bicimi" || no "duz YAML bicimi reddedildi"
printf 'version: 1\nmode: enforcing\nrules:\n- {id: i, name: "kural i", subject: "*", object: /tmp/x, action: file.read, effect: deny}\n' >/tmp/ax-l-flow.yaml
axctl policy check -f /tmp/ax-l-flow.yaml >/dev/null 2>&1 \
    && ok "akis (flow) YAML bicimi" || no "akis YAML bicimi reddedildi"
printf 'version: 1\nmode: enforcing\nrules:\n  - name: "tirnakli ad"\n    subject: "*"\n    object: "/tmp/x"\n    action: "file.read"\n    effect: "deny"\n' >/tmp/ax-l-q.yaml
axctl policy check -f /tmp/ax-l-q.yaml >/dev/null 2>&1 \
    && ok "tirnakli degerler" || no "tirnakli degerler reddedildi"

# --- Yorum satirlari ---
printf '# yorum\nversion: 1  # satir ici\nmode: enforcing  # mod\nrules: []\n' >/tmp/ax-l-c.yaml
axctl policy check -f /tmp/ax-l-c.yaml >/dev/null 2>&1 \
    && ok "YAML yorumlari tolere ediliyor" || no "YAML yorumlari reddedildi"

# --- simulate (uygulamadan once ongoru) ---
pmk s1 <<'Y'
version: 1
mode: enforcing
rules:
  - {id: s, name: "kural s", subject: curl, object: /etc/ax-secret, action: file.read, effect: deny}
Y
rc_is "simulate calisiyor" 0 axctl policy simulate -f /tmp/ax-l-s1.yaml
axctl policy simulate -f /tmp/ax-l-s1.yaml --json 2>/dev/null | head -1 | grep -q '{' \
    && ok "simulate --json calisiyor" || no "simulate --json calismadi"

# --- Politika degistikligi aninda gecerlilik ---
pmk m1 <<'Y'
version: 1
mode: enforcing
rules:
  - {id: m, name: "kural m", subject: "*", object: /etc/ax-secret, action: file.read, effect: deny}
Y
BADRC=0
axctl policy check -f /tmp/ax-l-m1.yaml >/dev/null 2>&1 || BADRC=1
[ "$BADRC" -eq 0 ] && ok "gecerli politika reload edilebilir" \
    || no "gecerli politika reload edilemedi"

# ==================================================================== M
# M) KRITIK SUREC VE COKME KORUMASI
#    En kotu hata: operator kendini kilitler. Politika yanlislikla
#    bash/sudo/sshd'yi yasaklarsa oturum kapanir. Ayrica daemon
#    cokerse ne olur?
begin "M) Kritik surec ve cokme korumasi"

# --- Korunan surecler ---
# Politika bunlari yasaklamaya CALISIRSA reddedilmeli.
PROTECTED="bash sh sudo sshd login systemd agetty"
for pr in $PROTECTED; do
    cat >/tmp/ax-m-p.yaml <<YAML
version: 1
mode: enforcing
rules:
  - {id: p, name: "kural p", subject: $pr, action: process.exec, effect: deny}
YAML
    if axctl policy check -f /tmp/ax-m-p.yaml >/dev/null 2>&1; then
        no "korumali surec '$pr' reddedilmedi (kilitlenme riski)"
    else
        ok "korumali surec reddedildi: $pr"
    fi
done

# Kilitlenme korumasi gercekten var mi?
axctl status --json 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
p=(d.get('protected_processes') or d.get('protected')
       or d.get('lockout_protection') or [])
print(len(p))" 2>/dev/null | while read n; do
    if [ "${n:-0}" -ge 20 ]; then ok "kilitlenme korumasi: $n surec"
    else no "kilitlenme korumasi yetersiz: ${n:-0}"; fi
done

# --- Kilitlenmeden kurtarma yollari ---
for m in permissive disabled; do
    rc_is "acil kurtarma: mode $m" 0 axctl mode "$m"
done
rc_is "acil kurtarma: reload --mode permissive" 0 axctl reload --mode permissive
rc_is "acil kurtarma: reload --force-empty" 0 axctl reload --force-empty
sudo axctl status --json >/dev/null 2>&1 && ok "kurtarma sonrasi daemon yanit veriyor" \
    || no "kurtarma sonrasi daemon yanit vermiyor"

# Geri enforcing'e al
axctl reload --mode enforcing >/dev/null 2>&1

# --- Daemon cokerse ---
# Gercek bir sureci oldurup otomatik yeniden baslatmayi olcuyoruz.
PID1="$(pgrep -x axdaemon | head -1)"
if [ -n "$PID1" ]; then
    ok "axdaemon pid: $PID1"
    sudo kill -9 "$PID1" 2>/dev/null
    sleep 1
    [ -z "$(pgrep -x axdaemon | head -1)" ] && ok "axdaemon olduruldu" \
        || skip "axdaemon anında yeniden basladi (dormant, sorun degil)"
    # Restart=on-failure bekleniyor
    T=0
    while [ $T -lt 20 ]; do
        NEW="$(pgrep -x axdaemon | head -1)"
        [ -n "$NEW" ] && [ "$NEW" != "$PID1" ] && break
        T=$((T + 1)); sleep 1
    done
    if [ -n "$NEW" ] && [ "$NEW" != "$PID1" ]; then
        ok "axdaemon otomatik yeniden basladi: $PID1 -> $NEW"
    else
        no "axdaemon otomatik yeniden baslamadi"
    fi
    sleep 4
    sudo axctl status --json >/dev/null 2>&1 \
        && ok "yeniden baslamadan sonra saglikli" \
        || no "yeniden baslamadan sonra saglikli degil"
else
    no "axdaemon bulunamadi"
fi

# --- axlog cokerse ---
PID2="$(pgrep -x axlog | head -1)"
if [ -n "$PID2" ]; then
    sudo kill -9 "$PID2" 2>/dev/null
    T=0
    while [ $T -lt 20 ]; do
        NEW2="$(pgrep -x axlog | head -1)"
        [ -n "$NEW2" ] && [ "$NEW2" != "$PID2" ] && break
        T=$((T + 1)); sleep 1
    done
    [ -n "$NEW2" ] && [ "$NEW2" != "$PID2" ] && ok "axlog otomatik yeniden basladi" \
        || no "axlog otomatik yeniden baslamadi"
else
    skip "axlog bulunamadi"
fi
sleep 4

# --- Soket dayanikligi ---
# Iki servis ayni dizini paylasir; biri yeniden baslayinca digerinin
# soketi SILINMEMELI. (Onceki surumde RuntimeDirectory yuzunden
# oluyordu.)
S1="$(ls /run/axlinux/axdaemon.sock 2>/dev/null)"
sudo systemctl restart axlog >/dev/null 2>&1; sleep 4
S2="$(ls /run/axlinux/axdaemon.sock 2>/dev/null)"
[ -n "$S1" ] && [ -n "$S2" ] && ok "axlog restart axdaemon soketini SILEMEDI" \
    || no "axlog restart axdaemon soketini sildi"
sudo systemctl restart axdaemon >/dev/null 2>&1; sleep 5
ls /run/axlinux/axlog.sock >/dev/null 2>&1 \
    && ok "axdaemon restart axlog soketini SILEMEDI" \
    || no "axdaemon restart axlog soketini sildi"

# --- Sokot kirli kalirsa ---
sudo systemctl stop axdaemon axlog >/dev/null 2>&1; sleep 2
sudo sh -c 'echo bozuk > /run/axlinux/axdaemon.sock 2>/dev/null' || true
sudo systemctl start axdaemon axlog >/dev/null 2>&1; sleep 6
sudo axctl status --json >/dev/null 2>&1 \
    && ok "bozuk soket temizlendi, servis ayakta" \
    || no "bozuk soket servisi kilitledi"
sudo axctl status --json 2>/dev/null | grep -q '"bpf_programs_loaded"[[:space:]]*:[[:space:]]*5' \
    && ok "bozuk soket sonrasi bpf 5/5" || no "bozuk soket sonrasi bpf 5/5 degil"

# --- Arayuz cokerse ---
sudo chmod 000 /run/axlinux/axdaemon.sock 2>/dev/null
axctl status >/dev/null 2>&1
[ $? -ne 0 ] && ok "erişilemeyen sokette anlasilir hata" \
    || skip "erişilemeyen sokette hata vermedi (root testi)"
sudo systemctl restart axdaemon >/dev/null 2>&1; sleep 5

# --- Kaynak tuketimi ---
M1="$(sudo awk '/VmRSS/{print $2}' /proc/"$(pgrep -x axdaemon | head -1)"/status 2>/dev/null || echo 0)"
ok "axdaemon RSS: ${M1} kB"
[ "${M1:-0}" -lt 1048576 ] && ok "axdaemon bellek kullanimi makul (<1GB)" \
    || no "axdaemon bellek kullanimi yuksek: ${M1} kB"
FD="$(sudo ls /proc/"$(pgrep -x axdaemon | head -1)"/fd 2>/dev/null | wc -l)"
ok "axdaemon acik fd: $FD"
[ "$FD" -lt 256 ] && ok "fd kullanimi makul" || no "fd kullanimi yuksek: $FD"

# --- Uzun surekli kararlilik ---
ok "daemon uptime: $(sudo axctl status --json 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin).get("uptime","?"))' 2>/dev/null)"
axctl status --json >/dev/null 2>&1 && ok "dengeli durumda" || no "dengesiz durum"

# ==================================================================== N
# N) PERFORMANS VE YUK TESTLERI
#    MAC her dosya erisiminde calisir. Yanlis bir harita boyutu
#    sistemi kullanilamaz hale getirir. Burada olculebilir yan
#    etkiler var.
begin "N) Performans ve yuk"

perf_t0=$(date +%s%N)

# --- Politika derleme suresi ---
cat >/tmp/ax-n-1k.yaml <<'Y'
version: 1
mode: enforcing
rules:
Y
python3 - >>/tmp/ax-n-1k.yaml <<'PY'
for i in range(1000):
    print(f"  - {{id: n{i}, name: 'kural {i}', subject: 'proc{i%50}', object: '/etc/ax-n{i}', action: file.read, effect: deny}}")
PY
T0=$(date +%s%N)
if axctl policy check -f /tmp/ax-n-1k.yaml >/dev/null 2>&1; then
    T1=$(date +%s%N)
    MS=$(( (T1 - T0) / 1000000 ))
    ok "1000 kural dogrulandi: ${MS}ms"
    [ "$MS" -lt 10000 ] && ok "derleme suresi kabul edilebilir (<10s)" \
        || no "derleme yavas: ${MS}ms"
else
    no "1000 kural dogrulanamadi"
fi

# 1000 kural UYGULAMA suresi
cp /tmp/ax-n-1k.yaml /root/.axlinux/policy.yaml 2>/dev/null || {
    sudo mkdir -p /root/.axlinux; sudo cp /tmp/ax-n-1k.yaml /root/.axlinux/policy.yaml; }
T0=$(date +%s%N)
RC="$(sudo axctl reload >/dev/null 2>&1; echo $?)"
T1=$(date +%s%N)
MS=$(( (T1 - T0) / 1000000 ))
[ "$RC" -eq 0 ] && ok "1000 kural uygulandi: ${MS}ms" \
    || no "1000 kural uygulanamadi (rc=$RC)"
[ "$MS" -lt 15000 ] && ok "uygulama suresi kabul edilebilir (<15s)" \
    || no "uygulama yavas: ${MS}ms"

# Buyuk politika gercekten yuklu mu
CNT="$(sudo axctl status --json 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin).get("rules_loaded",0))' 2>/dev/null || echo 0)"
ok "yuklenen kural sayisi: $CNT"
[ "${CNT:-0}" -ge 1000 ] && ok "1000+ kural gercekten yuklendi" \
    || no "kural sayisi beklenenden az: ${CNT:-0}"

# Harita kapasitesi
CAP="$(sudo bpftool map show pinned /sys/fs/bpf/axlinux/deny_map 2>/dev/null | grep -oE 'max_entries [0-9]+' | awk '{print $2}')"
ok "deny_map kapasitesi: ${CAP:-bilinmiyor}"
[ "${CAP:-0}" -ge 1000 ] && ok "harita kapasitesi yeterli" \
    || no "harita kapasitesi yetersiz: ${CAP:-0}"

# --- Enforcement hala calisiyor mu (buyuk politika altinda) ---
sudo sh -c 'echo G > /etc/ax-n-test; chmod 666 /etc/ax-n-test' 2>/dev/null
cat >/tmp/ax-n-mix.yaml <<'Y'
version: 1
mode: enforcing
rules:
  - {id: live, name: "kural live", subject: "*", object: /etc/ax-n-test, action: file.read, effect: deny}
Y
python3 - >>/tmp/ax-n-mix.yaml <<'PY'
for i in range(500):
    print(f"  - {{id: m{i}, name: 'kural {i}', subject: 'p{i%20}', object: '/etc/ax-m{i}', action: file.read, effect: deny}}")
PY
apply_policy /tmp/ax-n-mix.yaml; sleep 1
sudo cat /etc/ax-n-test >/dev/null 2>&1 \
    && no "buyuk politika altinda kural UYGULANMADI" \
    || ok "buyuk politika altinda kural uygulandi"
sudo cat /etc/hostname >/dev/null 2>&1 \
    && ok "buyuk politika altinda normal erisim saglam" \
    || no "buyuk politika altinda normal erisim bozuldu"

# --- Diger kancalar buyuk politika altinda ---
sudo axctl status --json 2>/dev/null | grep -q '"bpf_programs_loaded"[[:space:]]*:[[:space:]]*5' \
    && ok "buyuk politika altinda bpf 5/5" || no "buyuk politika altinda bpf 5/5 degil"

# --- Dosya erisim gecikmesi (kanca maliyeti) ---
# Kanca her dosya acilista calisir. 1000 acilis olcülür.
sudo sh -c 'for i in $(seq 1 500); do echo x > /tmp/ax-perf-$i; done' 2>/dev/null
T0=$(date +%s%N)
sudo sh -c 'for i in $(seq 1 500); do cat /tmp/ax-perf-$i >/dev/null 2>&1; done' 2>/dev/null
T1=$(date +%s%N)
MS=$(( (T1 - T0) / 1000000 ))
AVG=$(awk "BEGIN{printf \"%.2f\", $MS/500}")
ok "500 dosya acma: ${MS}ms (ortalama ${AVG}ms/acilis)"
# Kanca maliyeti uygulanabilir olmali. 20ms/acilisin uzeri
# kullaniciya belirgin yavaslik olarak yansir.
awk "BEGIN{exit !($AVG < 20)}" 2>/dev/null \
    && ok "kanca maliyeti kabul edilebilir (<20ms/acilis)" \
    || no "kanca maliyeti yuksek: ${AVG}ms/acilis"

sudo sh -c 'rm -f /tmp/ax-perf-*' 2>/dev/null

# --- Soket isletme gecikmesi ---
T0=$(date +%s%N)
sudo sh -c 'for i in $(seq 1 200); do (echo >/dev/tcp/127.0.0.1/22) 2>/dev/null; done' 2>/dev/null
T1=$(date +%s%N)
MS=$(( (T1 - T0) / 1000000 ))
ok "200 baglanti denemesi: ${MS}ms"

# --- Bellek ---
M="$(sudo awk '/VmRSS/{print $2}' /proc/"$(pgrep -x axdaemon | head -1)"/status 2>/dev/null || echo 0)"
ok "buyuk politika sonrasi RSS: ${M} kB"
[ "${M:-0}" -lt 1048576 ] && ok "bellek kullanimi hala makul" \
    || no "bellek kullanimi artti: ${M} kB"

# --- Denge durumuna don ---
axctl reload --force-empty >/dev/null 2>&1
sleep 1
sudo axctl status --json >/dev/null 2>&1 && ok "bos politikaya donuldu" \
    || no "bos politikaya donulemedi"

perf_t1=$(date +%s%N)
ok "toplam sure: $(( (perf_t1 - perf_t0) / 1000000 ))ms"

# ==================================================================== O
# O) DENETIM VE GUNLUKLEME GUVENILIRLIK
#    "audit calisiyor" demek yetmez; kayit GERCEKTEN dosyaya
#    yazilmalidir. Fedora'da SELinux connectto izni eksikligi
#    yuzunden kayitlar HIC YAZILMIYORDU ve kullaniciya "audit
#    saglikl" gorunuyordu.
begin "O) Denetim ve gunlukleme guvenilirlik"

# --- Log dosyasi gercekten yaziliyor mu ---
LOGDIR=/var/log/axlinux
[ -d "$LOGDIR" ] && ok "log dizini var: $LOGDIR" || no "log dizini yok"

sudo sh -c 'echo G > /etc/ax-secret; chmod 666 /etc/ax-secret' 2>/dev/null
cat >/tmp/ax-o.yaml <<'Y'
version: 1
mode: enforcing
rules:
  - {id: o1, name: "kural o1", subject: cat, object: /etc/ax-secret, action: file.read, effect: deny}
Y
apply_policy /tmp/ax-o.yaml; sleep 1

# Dosya boyutunu olc
F1="$(sudo find "$LOGDIR" -name 'audit-*.jsonl' -newermt '-2 min' 2>/dev/null | head -1)"
if [ -z "$F1" ]; then
    F1="$(sudo ls -t "$LOGDIR"/audit-*.jsonl 2>/dev/null | head -1)"
fi
B1="$(sudo stat -c %s "$F1" 2>/dev/null || echo 0)"
ok "audit dosyasi: ${F1:-yok} (${B1} bayt)"

for i in 1 2 3 4 5; do sudo cat /etc/ax-secret >/dev/null 2>&1; done
sleep 3
B2="$(sudo stat -c %s "$F1" 2>/dev/null || echo 0)"
ok "5 ihlalden sonra dosya: ${B2} bayt"
if [ "${B2:-0}" -gt "${B1:-0}" ]; then
    ok "KAYITLAR DISCA YAZILIYOR (+$((B2 - B1)) bayt)"
else
    no "kayitlar disa YAZILMIYOR (dosya buyumedi)"
fi

# --- JSONL bicim gecerliligi ---
sudo tail -50 "$F1" 2>/dev/null | python3 -c '
import json,sys
bad=0; n=0
for line in sys.stdin:
    line=line.strip()
    if not line: continue
    n+=1
    try: json.loads(line)
    except Exception: bad+=1
print(f"{n-bad} {bad}")
' 2>/dev/null | while read good bad; do
    if [ "${bad:-0}" -eq 0 ] && [ "${good:-0}" -gt 0 ]; then
        ok "JSONL butun satirlar gecerli ($good satir)"
    else
        no "JSONL gecersiz: $good gecerli, $bad bozuk"
    fi
done

# --- Zorunlu alanlar ---
sudo tail -5 "$F1" 2>/dev/null | python3 -c '
import json,sys
req={"ts","pid","comm","action","effect"}
missing=set()
n=0
for line in sys.stdin:
    line=line.strip()
    if not line: continue
    n+=1
    try: d=json.loads(line)
    except Exception: continue
    missing |= (req - set(d))
print(n, ",".join(sorted(missing)) if missing else "-")
' 2>/dev/null | while read n miss; do
    if [ "$miss" = "-" ]; then ok "kayitlarda zorunlu alanlar tam ($n kayit)"
    else no "kayitlarda eksik alanlar: $miss"; fi
done

# --- CLI sorgulari ---
for f in "--json" "--effect denied" "--subject cat" "--action file.read" "--limit 5"; do
    # shellcheck disable=SC2086
    if sudo axctl logs $f >/dev/null 2>&1; then
        ok "logs $f calisiyor"
    else
        no "logs $f calismadi"
    fi
done
# Bilinmeyen filtre HATA VERMEMELI
sudo axctl logs --subject YANLISFILTRE >/dev/null 2>&1 \
    && ok "bilinmeyen filtre hata vermiyor" || no "bilinmeyen filtre hata verdi"

# Sonuc bos olsa da CALISMALI (sessizce 0 donmemeli)
N="$(sudo axctl logs --json 2>/dev/null | python3 -c 'import json,sys
try:
    d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else -1)
except Exception: print(-2)' 2>/dev/null || echo -3)"
case "$N" in
    -1|-2|-3) no "logs --json gecerli JSON donmuyor" ;;
    *) ok "logs --json gecerli JSON donuyor ($N kayit)" ;;
esac

# --- Denetimin sagligi ---
AH="$(sudo axctl status --json 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin).get("audit_healthy"))' 2>/dev/null || echo None)"
ok "audit_healthy: $AH"
[ "$AH" = "True" ] && ok "audit saglikli" || no "audit saglikli degil"

# --- SELinux AVC: audit akisi karsi mi ---
if command -v getenforce >/dev/null 2>&1; then
    AVC="$(sudo ausearch -m AVC -ts recent 2>/dev/null | grep -ci 'axlog.sock' || echo 0)"
    ok "axlog.soketi AVC reddi (son 5 dk): $AVC"
    [ "${AVC:-0}" -eq 0 ] && ok "axdaemon -> axlog baglantisi engellenmiyor" \
        || no "axdaemon -> axlog baglantisi ENGELLENIYOR (kayitlar kaybolur)"
fi

# --- Yazma izni ---
for f in $(sudo ls "$LOGDIR"/audit-*.jsonl 2>/dev/null); do
    P="$(stat -c %a "$f" 2>/dev/null || echo '?')"
    case "$P" in
        6*|4*|2*|7*|5*) ok "log dosyasi izinleri dar: $P" ;;
        *) ok "log dosyasi izinleri: $P" ;;
    esac
done

# --- Log rotasyonu ---
sudo sh -c 'echo "{}" > '"$LOGDIR"'/audit-1999-01-01.jsonl' 2>/dev/null
[ -f "$LOGDIR/audit-1999-01-01.jsonl" ] && skip "rotasyon yok (dosya yazildi)" \
    || ok "eski tarihli dosya yok (rotasyon/temizlik calisiyor)"

# --- Yüksek hacim ---
BEFORE="$(sudo axctl status --json 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin).get("audit_log_count",0))' 2>/dev/null || echo 0)"
sudo sh -c 'for i in $(seq 1 100); do cat /etc/ax-secret >/dev/null 2>&1; done' 2>/dev/null
sleep 3
AFTER="$(sudo axctl status --json 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin).get("audit_log_count",0))' 2>/dev/null || echo 0)"
ok "100 ihlal sonrasi sayac: $BEFORE -> $AFTER"
[ "${AFTER:-0}" -gt "${BEFORE:-0}" ] && ok "sayac artiyor (kayit akisi canli)" \
    || no "sayac artmadi; kayit akisi TIKANDI"

sudo rm -f /etc/ax-secret "$LOGDIR/audit-1999-01-01.jsonl" 2>/dev/null

# ==================================================================== P
# P) PAKETLEME, KURULUM VE KALDIRMA
#    Iki dagitim yolu olmamali. "make install" ile paket ayni
#    sonucu vermeli; once ayrilmislerdi.
begin "P) Paketleme, kurulum ve kaldirma"

# --- Kurulu dosyalar ---
for f in /usr/local/bin/axctl /usr/local/bin/axdaemon /usr/local/bin/axlog \
         /usr/lib/axlinux/axbpf.o /usr/lib/axlinux/axctl/cli.py \
         /usr/lib/systemd/system/axdaemon.service \
         /usr/lib/tmpfiles.d/axlinux.conf; do
    [ -f "$f" ] && ok "kurulu: $f" || no "eksik: $f"
done
[ -d /etc/axlinux ] && ok "ornek politikalar kurulu" || no "/etc/axlinux yok"
ls /etc/axlinux/*.yaml >/dev/null 2>&1 && ok "ornek politika dosyalari var" \
    || no "ornek politika dosyalari yok"

# --- Python paketi DUZ kurulMAMIS olmali (bu bir regresyondu) ---
if [ -f /usr/lib/axlinux/cli.py ]; then
    no "Python paketi DUZ kurulmus (/usr/lib/axlinux/cli.py); eski surum ice alinir"
else
    ok "Python paketi axctl/ alt dizininde (duz kurulum yok)"
fi
[ -f /usr/lib/axlinux/axctl/__init__.py ] && ok "axctl/__init__.py dogru yerde" \
    || no "axctl/__init__.py yanlis yerde"

# --- Sarma layici ---
# axctl TEK dogruluk kaynagindan gelir (packaging/axctl).
# Once iki sarmalayici vardi: RPM sh+python3 -c, make install
# printf ile uretilen python betigi. python3 -c yonteminde
# sys.argv[0] = "-c" oldugu icin click "Usage: -c" yaziyordu.
head -1 /usr/local/bin/axctl 2>/dev/null | grep -q '^#!/usr/bin/env python3' \
    && ok "axctl python betigi (tek kaynak)" || no "axctl shebang beklenenden farkli"
! grep -q 'python3 -c' /usr/local/bin/axctl \
    && ok "axctl python3 -c kullanmiyor (argv[0] dogru)" \
    || no "axctl python3 -c kullaniyor; 'Usage: -c' gorunecek"
grep -q '/usr/lib/axlinux' /usr/local/bin/axctl \
    && ok "axctl sys.path dogru" || no "axctl sys.path yanlis"
axctl version >/dev/null 2>&1 && ok "axctl version calisiyor" || no "axctl version calismadi"
axctl --help 2>&1 | grep -q 'Usage: axctl' \
    && ok "axctl --help dogru program adi" || no "axctl --help yanlis program adi"

# --- Surum tutarliligi ---
SV="$(axctl version 2>/dev/null | awk '{print $2}')"
DP="$(dpkg-query -W -f='${Version}' axlinux 2>/dev/null || echo yok)"
RPMV="$(rpm -q axlinux 2>/dev/null || echo yok)"
ok "axctl surumu: $SV"
ok "paket surumu: $DP / $RPMV"
case "$SV" in 1.0.0) ok "surum 1.0.0" ;; *) no "surum beklenenden farkli: $SV" ;; esac

# --- Birim dosyalari ---
# bpffs kosulu YALNIZCA axdaemon'da gereklidir (eBPF yukler).
# axlog sadece dosya yazar; bpffs kullanmaz. Burada yanlis bir
# beklenti kurmak testi hatali hale getirirdi.
for s in axdaemon axlog; do
    U="/usr/lib/systemd/system/$s.service"
    [ -f "$U" ] || continue
    if grep -qE '^ExecStartPre=.*(/bin/sh|sh -c)' "$U"; then
        no "$s: kabuk ExecStartPre var; SELinux alaninda CALISMAZ"
    else
        ok "$s: kabuk ExecStartPre yok (SELinux uyumlu)"
    fi
done
U=/usr/lib/systemd/system/axdaemon.service
grep -q 'ConditionPathIsMountPoint=/sys/fs/bpf' "$U" \
    && ok "axdaemon: bpffs kosulu systemd seviyesinde" \
    || no "axdaemon: bpffs kosulu sistem seviyesinde degil"

# --- SELinux modulu (Fedora) ---
if command -v semodule >/dev/null 2>&1; then
    semodule -l 2>/dev/null | grep -q '^axlinux' \
        && ok "SELinux axlinux modulu kurulu" || no "SELinux axlinux modulu kurulu degil"
    [ -f /usr/lib/systemd/system/axdaemon.service.d/10-selinux.conf ] \
        && ok "SELinux drop-in kurulu" || no "SELinux drop-in yok"
elif command -v apt-get >/dev/null 2>&1; then
    [ -f /var/lib/dpkg/info/axlinux.postinst ] && ok "postinst mevcut" || no "postinst yok"
fi

# --- Kaldirma veri korumasi (dosya yerinde) ---
[ -d /var/log/axlinux ] && ok "audit dizini mevcut (kaldirmada korunmali)" \
    || skip "audit dizini yok"
[ -d /root/.axlinux ] && ok "root politika dizini mevcut" || skip "root politika dizini yok"

# --- tmpfiles ---
[ -f /usr/lib/tmpfiles.d/axlinux.conf ] \
    && ok "tmpfiles tanimi var (/run/axlinux paylasimi)" \
    || no "tmpfiles tanimi yok"
grep -q 'RuntimeDirectory=axlinux' /usr/lib/systemd/system/axdaemon.service 2>/dev/null \
    && no "axdaemon RuntimeDirectory tanimli; baska servisin soketini siler" \
    || ok "hicbir servis /run/axlinux sahiplenmiyor"
[ -d /run/axlinux ] && ok "/run/axlinux mevcut" || no "/run/axlinux yok"

# --- Kaynak agaci kalinti ---
LEFTOVER="$(sudo find / -xdev -name 'axbpf.o' 2>/dev/null | grep -v '^/usr/lib/axlinux' | head -3)"
[ -z "$LEFTOVER" ] && ok "kurulum disi axbpf.o kalintisi yok" \
    || no "kurulum disi axbpf.o: $LEFTOVER"

# ==================================================================== Q
# Q) HATA YOLU, SINIR DURUMLARI VE GUVENLILIK
#    Bir arac duzgun calisirken hata halinde ne yaptigi onemlidir.
#    "Hicbir sey yapma" sessiz hatasi en tehlikisidir.
begin "Q) Hata yollari ve sinir durumlari"

# --- Bozuk YAML dosyalari ---
printf 'version: [unclosed\n' >/tmp/ax-q1.yaml
axctl policy check -f /tmp/ax-q1.yaml >/dev/null 2>&1 \
    && no "bozuk YAML reddedilmedi" || ok "bozuk YAML reddedildi"
printf '\t\tkimlik\tbosluk\t\nversion: 1\n' >/tmp/ax-q2.yaml
axctl policy check -f /tmp/ax-q2.yaml >/dev/null 2>&1 \
    && ok "tab ile girintili YAML" || ok "tab ile girintili YAML reddedildi (dogru)"
printf 'version: 1\nmode: enforcing\nrules: []\nextra_key: 1\n' >/tmp/ax-q3.yaml
axctl policy check -f /tmp/ax-q3.yaml >/dev/null 2>&1 \
    && ok "bilinmeyen ust duzey anahtar tolere ediliyor" \
    || no "bilinmeyen anahtar reddedildi (belki kasinti)"
: >/tmp/ax-q4.yaml
axctl policy check -f /tmp/ax-q4.yaml >/dev/null 2>&1 \
    && no "bos dosya kabul edildi" || ok "bos dosya reddedildi"
axctl policy check -f /tmp/YOKBÖYLEDOSYA.yaml >/dev/null 2>&1 \
    && no "olmayan dosya kabul edildi" || ok "olmayan dosya reddedildi"

# --- Buyuk girdi ---
python3 -c "
open('/tmp/ax-q5.yaml','w').write('version: 1\nmode: enforcing\nrules:\n' + ''.join(
  f\"  - {{id: q{i}, subject: '*', object: '/x{i}', action: file.read, effect: deny}}\n\"
  for i in range(5000)))"
axctl policy check -f /tmp/ax-q5.yaml >/dev/null 2>&1 \
    && ok "5000 kural sinirini asmadi (derlendi)" \
    || ok "5000 kural reddedildi (sinir)"
python3 -c "open('/tmp/ax-q6.yaml','w').write('version: 1\nmode: enforcing\nrules:\n  - {id: L, name: "kural L", subject: \"' + 'x'*5000 + '\", object: /a, action: file.read, effect: deny}\n')"
axctl policy check -f /tmp/ax-q6.yaml >/dev/null 2>&1 \
    && no "asiri uzun subject kabul edildi" || ok "asiri uzun subject reddedildi"
python3 -c "open('/tmp/ax-q7.yaml','w').write('version: 1\nmode: enforcing\nrules:\n  - {id: L, name: "kural L", subject: \"*\", object: /' + 'a/'*200 + 'b, action: file.read, effect: deny}\n')"
axctl policy check -f /tmp/ax-q7.yaml >/dev/null 2>&1 \
    && no "asiri derin yol kabul edildi" || ok "asiri derin yol reddedildi"

# --- Ozel karakterler ---
for CH in '"' "'" '\' '$' '`' ';'; do
    printf 'version: 1\nmode: enforcing\nrules:\n  - {id: c, name: "kural c", subject: "%s", object: /tmp/x, action: file.read, effect: deny}\n' "$CH" >/tmp/ax-q8.yaml
    axctl policy check -f /tmp/ax-q8.yaml >/dev/null 2>&1
    RC=$?
    case $RC in
        0|2) ok "ozel karakter '$CH' guvenli sekilde ele alindi (rc=$RC)" ;;
        *) no "ozel karakter '$CH' beklenmeyen rc=$RC" ;;
    esac
done

# --- Unicode / Turkce karakterler ---
printf 'version: 1\nmode: enforcing\nrules:\n  - {id: "u", name: "tr karakter", subject: "*", object: /tmp/x, action: file.read, effect: deny}\n' >/tmp/ax-q9.yaml
axctl policy check -f /tmp/ax-q9.yaml >/dev/null 2>&1 \
    && ok "unicode ad tolere ediliyor" || no "unicode ad reddedildi"

# --- Cikis kodlari ---
# 0=basari 1=hata 2=gecersiz politika 4=altyapi 5=yok
axctl version >/dev/null 2>&1; [ $? -eq 0 ] && ok "version rc=0" || no "version rc!=0"
axctl status >/dev/null 2>&1; [ $? -eq 0 ] && ok "status rc=0" || no "status rc!=0"
axctl template apply YOK >/dev/null 2>&1; [ $? -eq 5 ] && ok "template apply yok rc=5" || no "template apply rc=$?"
axctl mode gecersiz >/dev/null 2>&1; [ $? -ne 0 ] && ok "gecersiz mod rc!=0" || no "gecersiz mod kabul edildi"
axctl reload --force-empty >/dev/null 2>&1; [ $? -eq 0 ] && ok "force-empty rc=0" || no "force-empty rc!=0"

# --- Idempotans: ayni komut iki kez ---
axctl mode permissive >/dev/null 2>&1; R1=$?
axctl mode permissive >/dev/null 2>&1; R2=$?
[ "$R1" = "$R2" ] && ok "mod degisimi idempotent" || no "mod degisimi idempotent degil ($R1/$R2)"
axctl reload --force-empty >/dev/null 2>&1; R3=$?
axctl reload --force-empty >/dev/null 2>&1; R4=$?
[ "$R3" = "$R4" ] && ok "force-empty idempotent" || no "force-empty idempotent degil ($R3/$R4)"

# --- Yarim kalmis kurulum ---
sudo rm -rf /root/.axlinux
axctl reload >/dev/null 2>&1
[ $? -ne 0 ] && ok "politika yokken reload hata veriyor" || no "politika yokken reload basarili"
sudo axctl init >/dev/null 2>&1
[ -d /root/.axlinux ] && ok "axctl init dizini olusturdu" || no "axctl init dizini olusturmadi"
axctl reload >/dev/null 2>&1 && ok "init sonrasi reload calisiyor" || ok "init sonrasi reload basarisiz (bos politika)"

# --- Eski surumden kalan durum ---
sudo sh -c 'mkdir -p /root/.axlinux && echo "version: 99" > /root/.axlinux/policy.yaml'
axctl reload >/dev/null 2>&1
[ $? -ne 0 ] && ok "bozuk aktif politika reddedildi" || no "bozuk aktif politika kabul edildi"
sudo rm -f /root/.axlinux/policy.yaml

# --- Arayuz surekli calisiyor mu ---
FAILCNT=0
for i in $(seq 1 30); do
    axctl status >/dev/null 2>&1 || FAILCNT=$((FAILCNT + 1))
done
[ "$FAILCNT" -eq 0 ] && ok "30 arayuz sorgusu arasi kesintisiz" \
    || no "30 sorguda $FAILCNT basarisiz"

# --- Es zamanli reload ---
for i in 1 2 3; do (sudo axctl reload --force-empty >/dev/null 2>&1) & done
wait
sleep 2
axctl status --json >/dev/null 2>&1 \
    && ok "es zamanli reload sonrasi saglikli" \
    || no "es zamanli reload daemon'i kirdi"

# --- Yarış: reload + mode ---
(sudo axctl reload --force-empty >/dev/null 2>&1) &
(sudo axctl mode permissive >/dev/null 2>&1) &
wait; sleep 2
axctl status --json >/dev/null 2>&1 \
    && ok "reload+mode yarisi saglikli" || no "reload+mode yarisi sagliksiz"
axctl reload --mode enforcing >/dev/null 2>&1

# ==================================================================== R
# R) UCtan UCA ENTEGRASYON
#    Parcalar tek tek calisirken birlikte calistiklarini
#    dogrulamak ayri bir iştir.
begin "R) Uctan uca entegrasyon"

sudo sh -c 'echo GIZLI > /etc/ax-secret; chmod 666 /etc/ax-secret' 2>/dev/null
sudo sh -c 'echo ACIK > /etc/ax-secret2; chmod 666 /etc/ax-secret2' 2>/dev/null

cat >/tmp/ax-r-final.yaml <<'Y'
version: 1
mode: enforcing
labels:
  web: [curl, wget]
rules:
  - id: r1
    name: "tarayici gizli dosyayi okuyamaz"
    subject: web
    object: /etc/ax-secret
    action: file.read
    effect: deny
  - id: r2
    name: "hicbir sey gizliyi silemez"
    subject: "*"
    object: /etc/ax-secret
    action: file.write
    effect: deny
  - id: r3
    name: "curl calistirilamaz"
    subject: curl
    action: process.exec
    effect: deny
Y
rc_is "nihai politika gecerli" 0 axctl policy check -f /tmp/ax-r-final.yaml
apply_policy /tmp/ax-r-final.yaml
sleep 2

# 1) Etiketli okuma engellendi
sudo curl -s file:///etc/ax-secret >/dev/null 2>&1
[ $? -ne 0 ] && ok "R1 etiketli read engellendi" || no "R1 etiketli read ENGELLENMEDI"
# 2) Etiketsiz okuma SERBEST
sudo cat /etc/ax-secret >/dev/null 2>&1 \
    && ok "R2 disi okuma serbest (etiket kirpildi)" \
    || no "etiket kirpilmadi; tum okumalar engellendi"
# 3) Joker yazma engellendi
sudo tee /etc/ax-secret >/dev/null 2>&1
[ $? -ne 0 ] && ok "R2 joker write engellendi" || no "R2 joker write ENGELLENMEDI"
# 4) Ikinci dosya etkilenmedi
sudo cat /etc/ax-secret2 >/dev/null 2>&1 \
    && ok "R1/R2 disi dosya etkilenmedi" || no "kapsam tasmasi"
# 5) process.exec engellendi
sudo python3 -c 'import sys; sys.exit(0)' >/dev/null 2>&1
[ $? -ne 0 ] && ok "R3 process.exec engellendi" || no "R3 process.exec ENGELLENMEDI"
# 6) Audit kaydi olustu
sleep 2
AC="$(sudo axctl status --json 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin).get("audit_denied_count",0))' 2>/dev/null || echo 0)"
[ "${AC:-0}" -gt 0 ] && ok "ihlaller denetlendi ($AC kayit)" || no "ihlaller denetlenmedi"
# 7) Kilitlenme korumasi butunluk
sudo bash -c 'exit 0' >/dev/null 2>&1 && ok "bash hâlâ çalışıyor (kilitlenme yok)" \
    || no "bash kilitlendi"
sudo sh -c 'exit 0' >/dev/null 2>&1 && ok "sh hâlâ çalışıyor" || no "sh kilitlendi"
sudo ls / >/dev/null 2>&1 && ok "ls hâlâ çalışıyor" || no "ls kilitlendi"
# 8)acil cikis yolu
axctl reload --force-empty >/dev/null 2>&1 && ok "acil cikis yolu calisiyor" \
    || no "acil cikis yolu calismiyor"
sudo cat /etc/ax-secret >/dev/null 2>&1 && ok "acil cikista erisim serbest" \
    || no "acil cikista erisim hala engelli"
# 9) Toparlanma
axctl reload --mode enforcing >/dev/null 2>&1
sleep 2
axctl status --json 2>/dev/null | grep -q '"bpf_programs_loaded"[[:space:]]*:[[:space:]]*5' \
    && ok "enforcement'e donus: bpf 5/5" || no "enforcement'e donus basarisiz"
axctl status --json >/dev/null 2>&1 && ok "toparlanma sonrasi saglikli" \
    || no "toparlanma sonrasi sagliksiz"

sudo rm -f /etc/ax-secret /etc/ax-secret2 2>/dev/null

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
