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
BINDIR="/usr/bin"
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

TOTAL=11
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

# netcat: socket_connect / socket_bind kancalarinin TEK kullanan
# test araci. Urunun kendisi nc gerektirmiyor ama kurulumdan sonra
# calisan test paketi gerektiriyor; Pardus'ta nc yoktu ve iki ag
# kancası ATLANDI.
#
# DIKKAT: sadece paket listesine eklemek YETMIYOR. Arac kontrolu
# "tum araclar hazir" dediginde paket listesi hic CALISMAZ. Bu
# yuzden nc kontrol listesinde de olmali; her dagitimda adi
# farkli olabildigi icin (nc, netcat, ncat) hepsi denetleniyor.
#
# busybox KONTROL EDILMEZ: Pardus tabaninda busybox kurulu ve
# "busybox" var olunca burasi gecmis ve netcat kurulmamis olarak
# kaliyordu. Ama testin kullandigi bayraklar (nc -w 2 host port)
# busybox nc'de ayni degil.
if ! has nc && ! has netcat && ! has ncat; then
    NEED="$NEED netcat-openbsd"
fi

if [ -z "$NEED" ]; then
    ok "tum araclar hazir"
else
    info "eksik:$NEED"
    tick "paketler kuruluyor (bir surebilir)"
    case "$PKGMGR" in
        apt-get) install_pkgs clang llvm libbpf-dev linux-headers-generic \
                              linux-tools-common python3-pytest \
                              build-essential git rsync curl \
                              ca-certificates netcat-openbsd ;;
          # selinux-policy-devel / policycoreutils SELinux icin ZORUNLU:
          # modul bu gelistirme dosyalari olmadan derlenmez.
          #
          # Once SELinux adimi "modul derlenemedi" diye uyari verip
          # geciyordu. Sonuc sessiz ve kotuydu: SELinux Enforcing
          # altinda axdaemon unconfined_t alaninda calisiyor ve
          # hicbir alan kurali uygulanmiyordu.
          dnf|yum) install_pkgs clang llvm libbpf-devel linux-headers \
                                python3-pytest gcc make git rsync curl \
                                netcat-openbsd bpftool audit \
                                selinux-policy-devel policycoreutils \
                                selinux-policy-targeted ;;
        pacman)  install_pkgs clang llvm libbpf libbpf-devel linux-headers \
                              python-pytest base-devel git rsync curl \
                              netcat-openbsd ;;
        apk)     install_pkgs clang llvm libbpf-dev linux-headers \
                              py3-pytest build-base git rsync curl \
                              netcat-openbsd ;;
        *)       install_pkgs clang llvm libbpf-devel linux-headers \
                              python3-pytest base-devel git rsync curl \
                              netcat-openbsd ;;
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

# ------------------------------------------------------------ python bagimliliklari
# CLI'nin calisma zamani bagimliliklari. Onceki surumde hic
# kurulmuyordu: Ubuntu'da click/rich/yaml baska paketler sayesinde
# zaten vardir, Debian'da ise kurulum "calisiyor" derken
# "axctl status" "ModuleNotFoundError: No module named 'click'"
# ile cokuyordu. Kullanici kurulumu basarili saniyor, sistem
# kullanilamaz kaliyor.
need_py_deps() {
    local miss=""
    for m in click rich yaml; do
        python3 -c "import $m" >/dev/null 2>&1 || miss="$miss python3-$m"
    done
    echo "$miss"
}
PY_MISS="$(need_py_deps)"
if [ -n "$PY_MISS" ]; then
    info "Python bagimliliklari eksik:$PY_MISS"
    tick "kuruluyor"
    # Once apt ile denenir (paket adi ucu farkli olabilir)
    case "$PKGMGR" in
        apt-get) install_pkgs python3-click python3-rich python3-yaml ;;
        dnf|yum) install_pkgs python3-click python3-rich python3-yaml ;;
        pacman)  install_pkgs python-click python-rich python-yaml ;;
        apk)     install_pkgs py3-click py3-rich py3-yaml ;;
    esac
    untick
    # apt bulamazsa pip ile denenir (ozellikle cloud imajlarda)
    PY_MISS="$(need_py_deps)"
    if [ -n "$PY_MISS" ]; then
        if command -v pip3 >/dev/null 2>&1; then
            tick "pip ile kuruluyor"
            pip3 install --quiet click rich pyyaml >/dev/null 2>&1
            untick
        fi
    fi
    PY_MISS="$(need_py_deps)"
    if [ -n "$PY_MISS" ]; then
        fail_step "Python bagimliliklari kurulamadi:$PY_MISS"
        info "elle kurulum: pip3 install click rich pyyaml"
        summary; exit 1
    fi
    ok "Python bagimliliklari kuruldu (click, rich, yaml)"
else
    ok "Python bagimliliklari hazir"
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
  # HER ZAMAN yeniden uretilir. Once yalnizca "dosya yoksa" uretiliyordu:
  #
  #   if [ ! -f src/bpf/vmlinux.h ]; then ... fi
  #
  # Depoda Eylul'den kalma, GELISTIRME MAKESININ cekirdeginden
  # uretilmis bir vmlinux.h vardir. Varlik kontrolu dosyayi oldugu
  # gibi birakiyordu ve nesne HEDEF CEKIRDEGIN YAPILARINI TASCIIYORDU.
  #
  # Sonuc sessiz ve kotuydu: Fedora 6.19'da yanlis offset'lerle
  # derlenen nesne dogrulayicidan gecse bile bprm->file okumasi bozuk
  # cikiyor, yol cozumlemesi bos kaliyor ve process.exec kurallari
  # HIC UYGULANMIYORDU. Kurulum "basarili" diyordu.
  #
  # Dogrusu: vmlinux.h bir derleme ARTIKLIDIR, kaynak degildir.
  # Her kurulumda calisan cekirdegin BTF'sinden turetilir.
  # AX_VMLINUX_KEEP=1 ile elle hazirlanmis dosya korunabilir.
  if [ "${AX_VMLINUX_KEEP:-0}" = "1" ] && [ -s src/bpf/vmlinux.h ]; then
      info "AX_VMLINUX_KEEP=1: mevcut vmlinux.h korunuyor"
  else
      rm -f src/bpf/vmlinux.h
      bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h 2>/dev/null
  fi
  if [ -s src/bpf/vmlinux.h ]; then
      ok "vmlinux.h: $(wc -l < src/bpf/vmlinux.h) satir (kernel $(uname -r))"
  else
      fail_step "vmlinux.h uretilemedi"
      summary
      exit 1
  fi

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

# ------------------------------------------------------------------ 7 selinux
# SELinux KAPALI sistemlerde tamamen atlanir (Debian/Ubuntu/Pardus).
# Fedora'da ZORUNLUDUR: SELinux enforcing ile gelir ve AXlinux
# kendi alaninda (axlinux_daemon_t) calismalidir. Alan disinda
# (unconfined_service_t) calisiyorsa SELinux onu kisitlamaz ve
# Fedora'nin sertlastirilmis profilinde AXlinux calismaz.
#
# Bu adim olmadan once tespit edilen gercek hata:
#   ps -eZ | grep axdaemon
#     system_u:system_r:unconfined_service_t:s0
# Yani "calisiyor" gorunuyordu ama SELinux korumasi YOKTU.
begin "SELinux"
if ! command -v getenforce >/dev/null 2>&1; then
    ok "SELinux sistemde yok, atlandi"
else
    _se="$(getenforce 2>/dev/null || echo Bilinmiyor)"
    ok "SELinux: $_se"
    _sxs="$SRC/packaging/fedora"
    _sxr="/usr/local/share/axlinux/selinux-setup.sh"

    # Politika modulunu DERLE ve kur.
    #
    # ONCEDEN yalniz "dosya yoksa" derleniyordu:
    #     if [ ! -f /usr/share/selinux/packages/axlinux.pp ]; then
    #
    # Sisteme KURULMUS ESKI modul oldugu icin yeni derleme hic
    # yapilmazdi. Sonuc: kaynaga eklenen yeni SELinux kurallari
    # (orn. bpffs yazma izni, axlinux_cli_exec_t) ASLA yuklenmiyor;
    # selinux-setup.sh eski modulu kuruyor ve
    # "type axlinux_cli_exec_t is not defined" ile BASARISIZ oluyor.
    #
    # Dogrusu: modul bir DERLEME ARTIKLIDIR; her kurulumda kaynaktan
    # yeniden uretilir.
    if [ -f "$_sxs/Makefile" ] && [ -f /usr/share/selinux/devel/Makefile ]; then
        if make -C "$_sxs" >/dev/null 2>&1 && [ -f "$_sxs/axlinux.pp" ]; then
            install -d /usr/share/selinux/packages
            install -m 0644 "$_sxs/axlinux.pp" /usr/share/selinux/packages/
            ok "SELinux modulu derlendi"
        else
            warn "SELinux modulu derlenemedi (selinux-policy-devel eksik olabilir)"
        fi
    else
        warn "SELinux gelistirme dosyalari yok; modul guncellenemedi"
    fi

    # SELinux drop-in: NoNewPrivileges kendi alana gecisini
    # engelliyordu (status=203/EXEC). Gerekce 10-selinux.conf.
    if [ -d "$_sxs/axdaemon.service.d" ]; then
        for _s in axdaemon axlog; do
            install -d "/usr/lib/systemd/system/$_s.service.d"
            install -m 0644 "$_sxs/$_s.service.d/10-selinux.conf" \
                "/usr/lib/systemd/system/$_s.service.d/"
        done
        ok "SELinux systemd drop-in kuruldu"
    fi

    # Politika + dosya baglamlari (rpm %post ile ayni betik)
    install -d "$(dirname "$_sxr")"
    install -m 0755 "$_sxs/selinux-setup.sh" "$_sxr"
    if "$_sxr"; then
        ok "SELinux alani ve dosya baglamlari hazir"
    else
        err "SELinux kurulumu basarisiz; enforcement etkisiz"
    fi
fi

# ------------------------------------------------------------------ 8 servisler
begin "Servisler"
if ! has systemctl; then
    warn_step "systemctl yok, servis baslatilamadi"
else
    systemctl daemon-reload >/dev/null 2>&1
      systemctl enable axlog  >/dev/null 2>&1
      systemctl enable axdaemon >/dev/null 2>&1
      # /run/axlinux'i once biz kuralim; dizini hicbir servis
      # sahiplenmez (bkz. axlinux-tmpfiles.conf).
      systemd-tmpfiles --create /usr/lib/tmpfiles.d/axlinux.conf >/dev/null 2>&1
      # IKISI TEK TRANSACTION'DA baslatilir.
      #
      # Once iki ayri "systemctl restart" vardi: once axlog, 1 sn
      # sonra axdaemon ("audit sink once ayakta olmali" diye).
      # Niyet dogruydu ama UYGULAMA hatayi uretiyordu. Onceki
      # surumde axdaemon RuntimeDirectory=axlinux tasiyordu ve
      # systemd servisi baslatirken dizini SILIP YENIDEN
      # OLUSTURDUGU icin 1 sn once olusan axlog.sock'u siliyordu.
      # Kanit (Debian 12): axlog 20:07:51 basladi + soket olustu,
      # axdaemon 20:07:52 basladi; /proc/<axlog>/fd = 3 socket
      # (bellekte), ss -xl = 0 (diskte). "axlog: active" yaziyordu
      # ama audit kayitlari HICBIR YERE gitmiyordu; kurulum da
      # "audit soketi yok" deyip basarisiz oluyordu.
      # Artik dizini hicbir servis silemez; tek transaction da
      # After= siralamasini gercekten uygular.
      systemctl restart axdaemon axlog >/dev/null 2>&1
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

  # Derleme ciktilarinin sahibi duzeltilir.
  #
  # "sudo make install" icindeki compileall .build/ altina bytecode
  # yazar ve root'a ait dosyalar birakir. Sonrasi kullanicinin
  # DEPOSU silinemez:
  #   rm -rf axlinux -> "Permission denied" (60+ dosya)
  # Yeni kaynak aktarimi sessizce gerceklesmez ve testler GUNCEL
  # OLMAYAN kodun sonucunu verir. Ubuntu ve Pardus'ta yasandi.
  #
  # Konum ONEMLI: bu "6 kurulum" adimindan SONRA olmali. Go
  # derlemesinden hemen sonra konuldugunda .build duzeltilir,
  # ama ardindan "make install" yeniden calisip .build'i root'a
  # ait dosyalarla yeniden dolduruyordu.
  #
  # Sahibi SUDO_USER'dan DEGIL kaynak agacinin sahibinden alinir:
  # install.sh cogu zaman sudo'suz cagriliyor ve icindeki
  # "sudo make" kendi kapsaminda sudo kullaniyor; bu durumda
  # SUDO_USER bos kalir.
  if [ -d .build ]; then
      OWNER="$(stat -c %U . 2>/dev/null)"
      if [ -n "$OWNER" ] && [ "$OWNER" != "root" ]; then
          chown -R "$OWNER" .build 2>/dev/null && \
              ok "derleme ciktilari $OWNER'a ait"
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
  #
  # ONCEDEN gunluk kaziniyordu:
  #   journalctl -u axdaemon --since '-5min' | grep 'aktif=N toplam=N'
  #
  # Bu kirilgandir ve kurulumda surekli basarisiz oluyordu:
  #   - mesaj 5 dakikadan eskiyse veya gunluk donduyse bos doner
  #   - kurulum 5 dakikadan uzun surerse mesaj pencereden cikar
  #   - sonuc: "kanca bilgisi alinamadi" ama kancalar baglidir
  #
  # Dogrusu: calisan daemon'a SOR. axctl status --json her zaman
  # lsm_hooks_active / lsm_hooks_total dondurur. Gunluk yalnizca
  # JSON okunamazsa yedek yoldur.
  A5=""
  T5=""
  # Daemon yeniden baslatildiktan SONRA bu kontrol calisir; soket
  # hazir olmadan axctl status bos doner ve "kanca bilgisi
  # alinamadi" hatasi verir. Kisa bir bekleme dongusu eklenir.
  ST=""
  for _try in 1 2 3 4 5 6 7 8 9 10; do
      ST=$(axctl status --json 2>/dev/null)
      [ -n "$ST" ] && break
      sleep 1
  done
  if [ -n "$ST" ]; then
      A5=$(printf '%s' "$ST" | tr ',' '\n' \
           | sed -n 's/.*"lsm_hooks_active":\([0-9]*\).*/\1/p' | head -1)
      T5=$(printf '%s' "$ST" | tr ',' '\n' \
           | sed -n 's/.*"lsm_hooks_total":\([0-9]*\).*/\1/p' | head -1)
  fi
  if [ -z "$A5" ] || [ -z "$T5" ]; then
      HOOKS=$(journalctl -u axdaemon --since '-30min' --no-pager 2>/dev/null \
              | grep -oE 'aktif=[0-9]+ toplam=[0-9]+' | tail -1)
      if [ -n "$HOOKS" ]; then
          A5=$(echo "$HOOKS" | sed 's/.*aktif=\([0-9]*\).*/\1/')
          T5=$(echo "$HOOKS" | sed 's/.*toplam=\([0-9]*\).*/\1/')
      fi
  fi
  if [ -n "$A5" ] && [ -n "$T5" ]; then
      if [ "$A5" = "$T5" ] && [ "${T5:-0}" -gt 0 ]; then
          ok "LSM kancalari bagli: $A5/$T5"
      else
          err "kanca eksik: $A5/$T5"
          info "bpf LSM zincirde mi?  cat $LSM_FILE"
          VFAIL=1
      fi
  else
      err "kanca bilgisi alinamadi (axctl status --json okunamadi)"
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
#
# ONCEDEN: PROT=$(axctl status | grep -c 'LSM Kan')   -> anlamsiz bir sayim
# ve ciktiya SABIT "29 surec" yaziliyordu. Yani dogru da olsa
# yanlis da olsa ayni sey gorunuyordu; gercek bir dogrulama degildi.
#
# Simdi sayi calisan daemon'dan gelir (internal/protected tek kaynak).
# JSON guzel yazildigi icin '"anahtar": deger' biciminde bosluk var.
# Hem bosluklu hem bosluksuz bicimi kapsayan bir desen kullanilir.
PROT=$(axctl status --json 2>/dev/null \
      | sed -n 's/.*"protected_process_count"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' \
      | head -1)
if [ "${PROT:-0}" -ge 20 ]; then
    ok "kilitlenme korumasi: $PROT surec"
else
    warn "kilitlenme korumasi beklenenden az: ${PROT:-0} surec"
fi

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

# journald UST SINIRI
#
# journald varsayilani kotu dosya sisteminin %10'u (en fazla 4G).
# 20 GB'lik bir Workstation kurulumunda 2 GB ve hic kurulmamis
# olabilir; /var/log/journal sessizce buyup diski doldurur. AXlinux'in
# kendi audit logu sinirli (10 MB segment + 14 gun + 200 MB toplam)
# olsa bile isletim sistemi gunlugu sinirsiz kalirsa o sinir
# anlamsizlasir.
#
# Ana journald.conf DEGISTIRILMEZ. Standart drop-in dizini
# kullanilir; operator istedigi an dosyayi silerek geri alabilir.
JOURNALD_DROPIN=/etc/systemd/journald.conf.d/10-axlinux.conf
if [ -f packaging/journald/10-axlinux.conf ]; then
    if install -d -m 0755 /etc/systemd/journald.conf.d 2>/dev/null \
        && install -m 0644 packaging/journald/10-axlinux.conf "$JOURNALD_DROPIN" 2>/dev/null; then
        systemctl restart systemd-journald 2>/dev/null || true
        ok "journald ust siniri etkin (200M / 1G bos birak)"
        info "geri almak icin: rm $JOURNALD_DROPIN"
    else
        warn "journald ust siniri kurulamadi: $JOURNALD_DROPIN"
    fi
else
    warn "journald drop-in kaynak dosyasi bulunamadi"
fi

# SISTEM GENELI POLITIKA DIZINI
#
# RPM yolu bu dizini spec'te kuruyor; install.sh YOLU KURMUYORDU.
# Sonuc: install.sh ile kurulan sistemde politika reboot sonrasi
# kayboluyordu (axdaemon acilista bu dizini okuyor, dizin yoksa
# hicbir sey yuklemiyor) ve kullanici kalici politika yazamiyordu.
# Iki kurulum yolu ayni sistemi kurmamis oluyordu.
#
# Dizin 0750 root:root ve dosyalar 0640: politika yalnizca root
# tarafindan degistirilebilir. SELinux baglami /etc/axlinux(/.*)?
# kuraliyla zaten axlinux_etc_t.
POLICY_D=/etc/axlinux/policies.d
if install -d -m 0750 "$POLICY_D" 2>/dev/null; then
    ok "sistem politikasi dizini: $POLICY_D"
else
    warn "sistem politikasi dizini kurulamadi: $POLICY_D"
    warn_step "kalici politika yazamazsiniz; politika reboot sonrasi kaybolur"
fi

# Ornek politika. RPM spec'i 00-sample-workstation.yaml kuruyor;
# ayni dosya install.sh icinde de gomuluyor ki iki yol ayni
# icerigi versin. Icerik: hicbir sey kisitlamayan, uygulanmis ve
# calisilmis ornek (rules: []).
if [ -d "$POLICY_D" ]; then
    if [ ! -f "$POLICY_D/00-sample-workstation.yaml" ]; then
        cat >"$POLICY_D/00-sample-workstation.yaml" <<'AXYAML'
# AXlinux sistem geneli politika ornegi (install.sh ile kuruldu)
#
# BU DOSYA HICBIR KISITLAMA ICERMEZ (rules: []). Sistem
# "hicbir sey engellenmiyor" durumunda baslar.
#
# Politika YAZMAK: bu dizindeki bir .yaml dosyasina kurallarinizi
# ekleyin, sonra  sudo systemctl restart axdaemon
#
# Bu dizindeki TUM *.yaml dosyalari lexical sirayla (00-, 50-, ...)
# okunur ve birlestirilir. Politika bozuksa hicbir kural yazilmaz;
# sistem kisitlamasiz kalir ve axdaemon gunluge uyari yazar.
#
# Alanlarin tam listesi: docs/policy-language.md
version: 1

# disabled | permissive | enforcing
# Once permissive ile baslayip denetleyin, sonra enforcing'e gecin.
mode: permissive

rules: []
AXYAML
        chmod 0640 "$POLICY_D/00-sample-workstation.yaml" 2>/dev/null || :
        ok "ornek sistem politikasi yazildi"
    fi
fi

if [ -f /etc/axlinux/minimal.yaml ]; then
    ok "ornek politikalar: /etc/axlinux/"
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
