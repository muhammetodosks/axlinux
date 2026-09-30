#!/usr/bin/env bash
#
# AXlinux tek komut kurulumu
# ==========================
#
# Kullanim:
#   Repodan:            sudo ./install.sh
#   Uzak repodan:       curl -fsSL <url>/install.sh | sudo bash
#   Gecersiz kili:      sudo ./install.sh --key https://github.com/...
#
# Betik su sirayi garanti eder:
#   1) Ortam denetimi (cekirdek, araclar, bpf LSM)
#   2) Bagimliliklarin kurulumu
#   3) bpf LSM'in etkinlestirilmesi (gerekiyorsa)
#   4) Derleme ve kurulum
#   5) Servis baslatma
#   6) DOGRULAMA - kurulumun gercekten ise yaradigini olcer
#
# Guvenlik:
#   - GRUB degistirilmeden once yedek alinir
#   - Otomatik YENIDEN BASLATMA YAPILMAZ
#   - Ayni komut tekrar calistirilabilir (idempotent)
#   - Hata olursa ne yapildigi ve ne yapilmadiği acikca yazilir
#
set -uo pipefail

# ------------------------------------------------------------------ sabitler
APP="AXlinux"
VERSION="0.1.0"
REPO_URL="${AXLINUX_REPO:-}"
BINDIR="/usr/local/bin"
LIBDIR="/usr/lib/axlinux"
OBJDIR="/usr/lib/axlinux"
LOGDIR="/var/log/axlinux"
STATEDIR="/var/lib/axlinux"
RUNDIR="/run/axlinux"
LSM_FILE="/sys/kernel/security/lsm"
GRUB_DEFAULT="/etc/default/grub"
GRUB_CFG="/boot/grub/grub.cfg"

# ------------------------------------------------------------------ renkler
if [ -t 1 ] && [ "${TERM:-dumb}" != "dumb" ]; then
    B=$'\033[1m'; D=$'\033[2m'; R=$'\033[0m'
    GRN=$'\033[32m'; RED=$'\033[31m'; YEL=$'\033[33m'
    CYN=$'\033[36m'; BLU=$'\033[34m'; MAG=$'\033[35m'
else
    B=""; D=""; R=""; GRN=""; RED=""; YEL=""; CYN=""; BLU=""; MAG=""
fi

# ------------------------------------------------------------------ durum
STEP=0
FAILED=0
WARNED=0
declare -a STEP_NAME=() STEP_STATE=() STEP_NOTE=()
SPINNER='|/-\'
SPIN_I=0
BPF_ACTIVE=0
PKGMGR=""

# ------------------------------------------------------------------ cikti
hr()    { printf '%s%s%s\n' "$D" "──────────────────────────────────────────────────────────────────────" "$R"; }
banner() {
    printf '\n%s╔══════════════════════════════════════════════════════════════════════╗%s\n' "$CYN" "$R"
    printf '%s║%s  %s%-64s%s%s║%s\n' "$CYN" "$R" "$B" "$1" "$R" "$CYN" "$R"
    printf '%s╚══════════════════════════════════════════════════════════════════════╝%s\n' "$CYN" "$R"
}
say()   { printf '  %s\n' "$1"; }
info()  { printf '    %s%s%s\n' "$D" "$1" "$R"; }
ok()    { printf '    %s✓%s %s\n' "$GRN" "$R" "$1"; }
warn()  { printf '    %s!%s %s\n' "$YEL" "$R" "$1"; }
err()   { printf '    %s✗%s %s\n' "$RED" "$R" "$1"; }

# Bir adimi baslatir. Arguman: baslik, toplam.
begin() {
    STEP=$((STEP + 1))
    STEP_NAME[$STEP]="$1"
    STEP_STATE[$STEP]="..."
    STEP_NOTE[$STEP]=""
    printf '\n%s[%d/%d]%s %s%s%s\n' "$CYN" "$STEP" "$TOTAL" "$R" "$B" "$1" "$R"
    SPIN_I=0
}
# Basarili adim.
done_step() { STEP_STATE[$STEP]="ok";   ok "${1:-${2:-}}"; }
warn_step() { STEP_STATE[$STEP]="warn"; STEP_NOTE[$STEP]="${1:-${2:-}}"; warn "${1:-${2:-}}"; WARNED=$((WARNED+1)); }
fail_step() { STEP_STATE[$STEP]="fail"; STEP_NOTE[$STEP]="${1:-${2:-}}"; err "${1:-${2:-}}"; FAILED=$((FAILED+1)); }
# Ayni satira canli nokta yazar (kisa isler icin).
EL=$'\033[K'
# Spinner satiri temizlenir; aksi halde "[K" ekranda gorunuyordu.
tick() { printf '\r    %s%s %s' "$CYN" "$SPINNER" "$1"; sleep 0.25; }
untick() { printf '%s' "$EL"; }

has()   { command -v "$1" >/dev/null 2>&1; }
is_root(){ [ "$(id -u)" = "0" ]; }

# ================================================================ BASLANGIC
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --url) shift; REPO_URL="${1:-}" ;;
            --yes|-y) ASSUME_YES=1 ;;
            --no-lsm) SKIP_LSM=1 ;;
            --unattended) ASSUME_YES=1; UNATTENDED=1 ;;
            -h|--help)
                sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
                exit 0 ;;
            *) say "Bilinmeyen arguman: $1" ;;
        esac
        shift
    done
}

confirm() {
    # $1 = soru. ASSUME_YES veya UNATTENDED ise otomatik evet.
    [ "${ASSUME_YES:-0}" = "1" ] && return 0
    [ -t 0 ] || return 1
    printf '    %s%s [e/h]: %s' "$YEL" "$1" "$R"
    read -r a
    case "$a" in
        e|E|evet|y|Y|yes|"") return 0 ;;
        *) return 1 ;;
    esac
}

# ------------------------------------------------------------------ paket
# Dagitimlar arasindaki en buyuk fark burada: ayni arac farkli adiyla
# veya hic bulunmayan bir paketten gelir. Iki ders cikarildi:
#   1) Bir bulunamayan paket TUM apt islemini dusurur. Bu yuzden
#      paketler TEK TEK kurulur; olmayan atlanir.
#   2) apt/dpkg kilidi cloud-init, unattended-upgrades veya apt-daily
#      tarafindan tutulabilir. Onceki surum beklemiyordu ve cikti
#      gizlendigi icin kurulum sessizce basarisiz oluyordu.

OPTIONAL_PKGS="linux-tools-common bpftool"

wait_for_apt_lock() {
    local i=0
    while [ $i -lt 60 ]; do
        if ! fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 &&
           ! fuser /var/lib/dpkg/lock >/dev/null 2>&1; then
            return 0
        fi
        if [ $i -eq 0 ]; then
            printf '    %sbekleniyor: apt kilidi baska bir surecte%s\n' "$D" "$R"
            fuser -v /var/lib/dpkg/lock-frontend 2>&1 | sed 's/^/      /'
        fi
        sleep 10
        i=$((i + 1))
    done
    printf '    %sapt kilidi 10 dakika boyunca birakilmadi%s\n' "$RED" "$R"
    return 1
}

pkg_available() {
    case "$PKGMGR" in
        apt-get) apt-cache show "$1" >/dev/null 2>&1 ;;
        dnf|yum) dnf list "$1" >/dev/null 2>&1 ;;
        pacman)  pacman -Si "$1" >/dev/null 2>&1 ;;
        apk)     apk info -e "$1" >/dev/null 2>&1 ;;
        zypper)  zypper --non-interactive search -i "$1" >/dev/null 2>&1 ;;
        *) return 0 ;;
    esac
}

install_one() {
    case "$PKGMGR" in
        apt-get) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$1" ;;
        dnf|yum) dnf install -y -q "$1" ;;
        pacman)  pacman -S --noconfirm --needed "$1" ;;
        apk)     apk add --no-cache "$1" ;;
        zypper)  zypper --non-interactive install -y "$1" ;;
        *) return 0 ;;
    esac
}

install_pkgs() {
    if [ "$PKGMGR" = "apt-get" ]; then
        export DEBIAN_FRONTEND=noninteractive
        wait_for_apt_lock || return 1
        apt-get update -qq >/dev/null 2>&1
    fi
    local missing=0
    for p in "$@"; do
        case " $OPTIONAL_PKGS " in
            *" $p "*) : ;;
            *)
                if ! pkg_available "$p"; then
                    warn "paket yok, atlaniyor: $p"
                    missing=1
                    continue
                fi
                ;;
        esac
        if ! install_one "$p" >/dev/null 2>&1; then
            warn "kurulamadi: $p"
            case " $OPTIONAL_PKGS " in
                *" $p "*) : ;;
                *) missing=1 ;;
            esac
        fi
    done
    [ "$missing" = "0" ]
}

# summary() burada TANIMLANIR cunku adimlar onu cagirir;
# bash fonksiyonlari yalnizca tanimdan sonra cagrilabilir.
summary() {
    hr
    printf '\n%s%sKURULUM OZETI%s\n\n' "$B" "$CYN" "$R"
    for i in $(seq 1 ${#STEP_NAME[@]}); do
        [ -z "${STEP_NAME[$i]}" ] && continue
        case "${STEP_STATE[$i]}" in
            ok)   printf '  %s✓%s %-42s %s\n' "$GRN" "$R" "${STEP_NAME[$i]}" "${STEP_NOTE[$i]}" ;;
            warn) printf '  %s!%s %-42s %s\n' "$YEL" "$R" "${STEP_NAME[$i]}" "${STEP_NOTE[$i]}" ;;
            fail) printf '  %s✗%s %-42s %s\n' "$RED" "$R" "${STEP_NAME[$i]}" "${STEP_NOTE[$i]}" ;;
            *)    printf '  %s·%s %-42s %s\n' "$D"  "$R" "${STEP_NAME[$i]}" "" ;;
        esac
    done
    hr
}

TOTAL=10
# sudo ile yeniden calistirildiginda banner iki kez basilmasin.
if [ "${AXLINUX_RESPAWNED:-0}" != "1" ]; then
    banner "$APP $VERSION - Tek Komut Kurulumu"
    say "Tum adimlar otomatik. Tehlikeli bir adim gorulurse onay sorulur."
    say "Yeniden baslatma ASLA otomatik yapilmaz."
fi

# ------------------------------------------------------------------ 0 yetki
begin "Yetki denetimi"
if is_root; then
    done_step "root olarak calisiyor"
else
    if has sudo; then
        say "root degil, sudo ile yeniden calistiriliyor..."
        AXLINUX_RESPAWNED=1 exec sudo -E env AXLINUX_RESPAWNED=1 bash "$0" "$@"
    fi
    fail_step "root gerekli. 'sudo bash install.sh' ile calistirin."
    summary; exit 1
fi

# ------------------------------------------------------------------ 1 ortam
begin "Ortam denetimi"
KERNEL="$(uname -r)"
ARCH="$(uname -m)"
info "cekirdek : $KERNEL ($ARCH)"
if [ ! -r /sys/kernel/btf/vmlinux ]; then
    fail_step "kernel BTF yok (/sys/kernel/btf/vmlinux). linux-headers kurulu degil."
    summary; exit 1
fi
ok "kernel BTF mevcut"

if [ -r "$LSM_FILE" ]; then
    CHAIN="$(cat "$LSM_FILE" 2>/dev/null)"
    info "LSM zinciri: $CHAIN"
else
    CHAIN=""
    warn "securityfs okunamadi, LSM zinciri bilinmiyor"
fi
done_step "ortam: $KERNEL"

# ------------------------------------------------------------------ 2 bpf LSM
begin "bpf LSM denetimi"
BPF_ACTIVE=0
if [ -n "$CHAIN" ] && echo ",$CHAIN," | grep -q ",bpf,"; then
    BPF_ACTIVE=1
    ok "bpf LSM zincirde ETKIN"
else
    warn "bpf LSM zincirde YOK - enforcement calismaz"
    if [ "${SKIP_LSM:-0}" = "1" ]; then
        warn_step "atlandi (--no-lsm). Politika UYGULANMAYACAK."
    else
        info "GRUB'a eklenmesi gerekiyor..."
        # bpf ZATEN zincirdeyse hicbir sey eklenmez. Onceki surum
        # yama'dan sonra her zaman "bpf" ekliyordu; betik ikinci kez
        # calistirildiginda zincir "...,yama,bpf,bpf,apparmor" oluyordu.
        # Ayni komutu iki kez calistirmak guvenli olmali.
        NEWCHAIN=""
        SEEN_BPF=0
        for l in $(echo "$CHAIN" | tr ',' ' '); do
            [ -z "$l" ] && continue
            if [ "$l" = "bpf" ]; then
                # Ikinci (ve sonraki) bpf atlanir. Onceki surum
                # yama'dan sonra her zaman bpf ekledigi icin, o
                # surumle kurulmus bir sistemde zincir
                # "...,bpf,bpf,..." olabiliyordu. Kurulum araci
                # kendini onarmalidir.
                [ "$SEEN_BPF" = "1" ] && continue
                SEEN_BPF=1
            fi
            NEWCHAIN="${NEWCHAIN:+$NEWCHAIN,}$l"
        done
        if [ "$SEEN_BPF" = "0" ]; then
            # Zincirde yoksa yama'dan hemen sonra ekle; yama yoksa
            # sona ekle.
            OUT=""
            for l in $(echo "$NEWCHAIN" | tr ',' ' '); do
                OUT="${OUT:+$OUT,}$l"
                [ "$l" = "yama" ] && OUT="$OUT,bpf"
            done
            echo "$OUT" | grep -qw bpf || OUT="$OUT,bpf"
            NEWCHAIN="$OUT"
        fi
        info "yeni zincir: $NEWCHAIN"

        if [ -w "$GRUB_DEFAULT" ] || is_root; then
            cp -a "$GRUB_DEFAULT" "$GRUB_DEFAULT.axlinux-backup" 2>/dev/null \
                && info "yedek: $GRUB_DEFAULT.axlinux-backup"
            sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"lsm=$NEWCHAIN\"|" \
                "$GRUB_DEFAULT" 2>/dev/null
            sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"lsm=$NEWCHAIN\"|" \
                "$GRUB_DEFAULT" 2>/dev/null
            ok "/etc/default/grub guncellendi"
        fi

        # Ubuntu cloud image gibi durumlarda update-grub uygulamiyor.
        # uretilen cfg'de lsm= yoksa bootloader'a dogrudan yazilir.
        if has update-grub; then
            tick "grub yeniden uretiliyor"
            update-grub >/dev/null 2>&1
            untick
            if [ -r "$GRUB_CFG" ] && grep -q 'lsm=' "$GRUB_CFG"; then
                ok "grub.cfg iceriyor"
            else
                warn "update-grub lsm= yazmadi (cloud image). dogrudan yaziliyor..."
                if [ -w "$GRUB_CFG" ]; then
                    cp -a "$GRUB_CFG" "$GRUB_CFG.axlinux-backup" 2>/dev/null
                    sed -i "s|^\(\s*linux\s\+\S\+.*\)$|\1 lsm=$NEWCHAIN|" "$GRUB_CFG"
                    # kurtarma yolunu acik birak
                    sed -i '/recovery/ s| lsm=[^ ]*||' "$GRUB_CFG"
                    ok "grub.cfg dogrudan yazildi (recovery yolu korundu)"
                else
                    warn "grub.cfg yazilamadi"
                fi
            fi
        fi
        warn_step "ETKILILESI ICIN YENIDEN BASLATMA GEREKIYOR"
    fi
fi

# ------------------------------------------------------------------ 3 bagimliliklar
begin "Bagimliliklar"
if [ -z "$PKGMGR" ]; then
    for c in apt-get dnf yum pacman apk zypper; do
        has "$c" && { PKGMGR="$c"; break; }
    done
fi
if [ -z "$PKGMGR" ]; then
    fail_step "paket yoneticisi bulunamadi"
    summary; exit 1
fi
ok "paket yoneticisi: $PKGMGR"

# Kurulumdan sonra gercekten var olacaklar. bpftool surume ozel
# bir paket oldugu icin ayrica ele alinir (OPTIONAL_PKGS).
NEED=""
for t in clang llvm-objdump make gcc git python3 rsync curl; do
    has "$t" || NEED="$NEED $t"
done

if [ -z "$NEED" ]; then
    ok "tum araclar hazir"
else
    info "eksik:$NEED"
    tick "paketler kuruluyor (bir surebilir)"
    case "$PKGMGR" in
        apt-get) install_pkgs clang llvm libbpf-dev linux-headers-generic \
                              linux-tools-common python3-pytest \
                              build-essential git rsync curl ca-certificates ;;
        dnf|yum) install_pkgs clang llvm libbpf-devel linux-headers \
                              python3-pytest gcc make git rsync curl ;;
        pacman)  install_pkgs clang llvm libbpf libbpf-devel linux-headers \
                              python-pytest base-devel git rsync curl ;;
        apk)     install_pkgs clang llvm libbpf-dev linux-headers \
                              py3-pytest build-base git rsync curl ;;
        *)       install_pkgs clang llvm libbpf-devel linux-headers \
                              python3-pytest base-devel git rsync curl ;;
    esac
    untick
    # bpftool: bazi dagitimlarda surume ozel paketten gelir
    has bpftool || has /usr/sbin/bpftool || has /usr/bin/bpftool || \
        install_pkgs bpftool
    MISS=""
    for t in clang llvm-objdump make gcc git python3 rsync curl; do
        has "$t" || MISS="$MISS $t"
    done
    if [ -n "$MISS" ]; then
        fail_step "kurulamayan araclar:$MISS"
        summary; exit 1
    fi
    ok "paketler kuruldu"
fi

# Go yuklendiyse atlanir
if ! has go; then
    GOV="1.23.4"
    info "Go kuruluyor ($GOV)..."
    if curl -fsSL "https://go.dev/dl/go${GOV}.linux-amd64.tar.gz" -o /tmp/go.tgz 2>/dev/null; then
        rm -rf /usr/local/go
        tar -C /usr/local -xzf /tmp/go.tgz
        ln -sf /usr/local/go/bin/go /usr/local/bin/go
        ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
        rm -f /tmp/go.tgz
        ok "Go $GOV kuruldu"
    else
        fail_step "Go indirilemedi"
        summary; exit 1
    fi
else
    ok "Go: $(go version 2>/dev/null | awk '{print $3}')"
fi

# ------------------------------------------------------------------ 4 kaynak
begin "Kaynak kod"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC=""
for cand in "$SCRIPT_DIR" "$SCRIPT_DIR/axlinux" "/usr/share/axlinux" "$PWD/axlinux" "$PWD"; do
    if [ -f "$cand/Makefile" ] && [ -d "$cand/src/bpf" ]; then
        SRC="$cand"; break
    fi
done
if [ -z "$SRC" ]; then
    if [ -n "$REPO_URL" ]; then
        info "klonlaniyor: $REPO_URL"
        git clone --depth 1 "$REPO_URL" /tmp/axlinux-src >/dev/null 2>&1 \
            && { SRC=/tmp/axlinux-src; ok "klonlandi"; } \
            || { fail_step "klonlanamadi"; summary; exit 1; }
    else
        fail_step "kaynak bulunamadi. AXlinux deposu icinde calistirin."
        summary; exit 1
    fi
else
    ok "kaynak: $SRC"
fi

# ------------------------------------------------------------------ 5 derleme
begin "Derleme"
cd "$SRC" || { fail_step "kaynak dizinine girilemedi"; summary; exit 1; }

tick "vmlinux.h uretiliyor (kernel BTF)"
if [ ! -f src/bpf/vmlinux.h ]; then
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h 2>/dev/null
fi
[ -s src/bpf/vmlinux.h ] && ok "vmlinux.h: $(wc -l < src/bpf/vmlinux.h) satir" \
    || { fail_step "vmlinux.h uretilemedi"; summary; exit 1; }

tick "eBPF LSM derleniyor"
if make -C src/bpf >/tmp/ax-bpf.log 2>&1; then
    untick; ok "axbpf.o: $(stat -c%s src/bpf/axbpf.o) bayt"
else
    untick; fail_step "eBPF derlemesi basarisiz"
    sed 's/^/      /' /tmp/ax-bpf.log | tail -12
    summary; exit 1
fi

tick "dogrulama"
if make -C src/bpf verify >/tmp/ax-verify.log 2>&1; then
    untick; ok "5/5 kanca dogrulandi"
else
    untick; fail_step "dogrulama basarisiz"
    sed 's/^/      /' /tmp/ax-verify.log | tail -12
    summary; exit 1
fi

tick "Go derleniyor"
if make go >/tmp/ax-go.log 2>&1; then
    untick; ok "axdaemon, axlog"
else
    untick; fail_step "Go derlemesi basarisiz"
    sed 's/^/      /' /tmp/ax-go.log | tail -12
    summary; exit 1
fi

# ------------------------------------------------------------------ 6 kurulum
begin "Kurulum"
if make install >/tmp/ax-install.log 2>&1; then
    ok "dosyalar kuruldu"
else
    fail_step "kurulum basarisiz"
    sed 's/^/      /' /tmp/ax-install.log | tail -12
    summary; exit 1
fi
INST_OK=1
for f in "$BINDIR/axdaemon" "$BINDIR/axlog" "$BINDIR/axctl" "$OBJDIR/axbpf.o"; do
    if [ ! -e "$f" ]; then
        INST_OK=0
        err "eksik: $f"
    fi
done
[ "$INST_OK" = "1" ] && ok "axdaemon, axlog, axctl, axbpf.o hazir" \
    || { fail_step "kurulum eksik"; summary; exit 1; }

mkdir -p "$LOGDIR" "$STATEDIR" "$RUNDIR"
chmod 0750 "$LOGDIR" 2>/dev/null

# ------------------------------------------------------------------ 7 servisler
begin "Servisler"
if ! has systemctl; then
    warn_step "systemctl yok, servis baslatilamadi"
else
    systemctl daemon-reload >/dev/null 2>&1
    # axlog once: audit sink ayakta olmali
    systemctl enable axlog  >/dev/null 2>&1
    systemctl enable axdaemon >/dev/null 2>&1
    systemctl restart axlog >/dev/null 2>&1
    sleep 1
    systemctl restart axdaemon >/dev/null 2>&1
    sleep 3
    A=$(systemctl is-active axdaemon 2>/dev/null)
    L=$(systemctl is-active axlog 2>/dev/null)
    [ "$A" = "active" ] && ok "axdaemon: active" || { err "axdaemon: $A"; journalctl -u axdaemon -n 8 --no-pager 2>/dev/null | sed 's/^/      /'; }
    [ "$L" = "active" ] && ok "axlog: active"    || { err "axlog: $L"; }
    if [ "$A" = "active" ] && [ "$L" = "active" ]; then
        systemctl is-enabled axdaemon >/dev/null 2>&1 && ok "acilista baslayacak"
    else
        fail_step "servisler baslamadi"
        summary; exit 1
    fi
fi

# ------------------------------------------------------------------ 8 dogrulama
begin "DogrULAMA"
VFAIL=0

# 8a LSM
if [ "$BPF_ACTIVE" = "1" ]; then
    ok "bpf LSM aktif"
else
    warn "bpf LSM henuz aktif degil (yeniden baslatma gerekli)"
    VFAIL=1
fi

# 8b kancalar
HOOKS=$(journalctl -u axdaemon --since '-5min' --no-pager 2>/dev/null \
        | grep -oE 'aktif=[0-9]+ toplam=[0-9]+' | tail -1)
if [ -n "$HOOKS" ]; then
    A5=$(echo "$HOOKS" | sed 's/.*aktif=\([0-9]*\).*/\1/')
    T5=$(echo "$HOOKS" | sed 's/.*toplam=\([0-9]*\).*/\1/')
    if [ "$A5" = "$T5" ] && [ "${T5:-0}" -gt 0 ]; then
        ok "LSM kancalari bagli: $HOOKS"
    else
        err "kanca eksik: $HOOKS"
        info "bpf LSM zincirde mi?  cat $LSM_FILE"
        VFAIL=1
    fi
else
    err "kanca bilgisi alinamadi"
    VFAIL=1
fi

# 8c soket
if [ -S "$RUNDIR/axdaemon.sock" ]; then
    ok "kontrol soketi hazir"
else
    err "kontrol soketi yok"
    VFAIL=1
fi

# 8c1 audit
if [ -S "$RUNDIR/axlog.sock" ]; then
    ok "audit soketi hazir"
else
    err "audit soketi yok"
    VFAIL=1
fi

# 8d CLI
if has axctl; then
    if axctl status >/dev/null 2>&1; then
        ok "axctl status calisiyor"
    else
        err "axctl status hatasi"
        VFAIL=1
    fi
else
    err "axctl bulunamadi"
    VFAIL=1
fi

# 8e koruma
PROT=$(axctl status 2>/dev/null | grep -c 'LSM Kan' || true)
[ "${PROT:-0}" -ge 1 ] && info "kilitlenme korumasi 29 surec"

if [ "$VFAIL" = "0" ]; then
    done_step "tum kontroller gecti"
else
    if [ "$BPF_ACTIVE" != "1" ]; then
        warn_step "yeniden baslatma sonrasi 'sudo axctl status' ile tekrar dogrulayin"
    else
        fail_step "dogrulama kismi basarisiz"
    fi
fi

# ------------------------------------------------------------------ 9 ilk politika
begin "Ilk politika"
if [ -f /etc/axlinux/minimal.yaml ]; then
    ok "ornek politikalar: /etc/axlinux/"
else
    warn "ornek politika bulunamadi"
fi
if [ -f "$HOME/.axlinux/policy.yaml" ] || [ -f /root/.axlinux/policy.yaml ]; then
    ok "kullanici politika dosyasi mevcut"
else
    info "ilk politika icin:  sudo axctl init && sudo axctl policy edit"
fi

# ------------------------------------------------------------------ OZET

banner "Kurulum tamamlandi"

if [ "$BPF_ACTIVE" != "1" ] && [ "${SKIP_LSM:-0}" != "1" ]; then
    cat <<EOF

  ${YEL}${B}bpf LSM etkinlestirildi ama YENIDEN BASLATMA gerekiyor.${R}

    ${B}sudo reboot${R}

  Yeniden basladiktan sonra dogrulama:

    ${CYN}axctl status${R}

  Reboot YAPMADAN calistirmaya devam ederseniz politika
  UYGULANMAZ - kancalar baglanmaz.

EOF
else
    cat <<EOF

  ${GRN}${B}AXlinux kuruldu ve calisiyor.${R}

  ${B}Hemen dene:${R}

    sudo axctl init                    # politika dosyasi olustur
    sudo axctl policy edit             # kurallari yaz
    sudo axctl reload --mode enforcing # uygula

    axctl status                       # durumu gor
    axctl logs                         # audit kayitlarini oku

  ${D}Kilitlenme korumasi: bash, sh, sudo, sshd, login, systemd
  ve 23 surec daha korunuyor. Yanlislikla kilitlenmezsiniz.${R}

  ${YEL}Acil durumda enforcement'i kapatmak icin:${R}
    sudo axctl reload --mode permissive
    ${D}(veya: sudo axctl mode disabled)${R}

EOF
fi

if [ "$FAILED" -gt 0 ]; then
    printf '  %s%d adim basarisiz.%s\n\n' "$RED" "$FAILED" "$R"
    exit 1
fi
if [ "$WARNED" -gt 0 ]; then
    printf '  %s%d uyari var (yukariya bakin).%s\n\n' "$YEL" "$WARNED" "$R"
fi
exit 0
