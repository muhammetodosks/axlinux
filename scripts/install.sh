#!/usr/bin/env bash
# AXlinux kurulum betigi
#
# Bagimliliklari kurar, projeyi derler, systemd servisini kaydeder ve
# LSM zincirinin hazir olup olmadigini raporlar.
#
# Kullanim:
#   sudo ./scripts/install.sh
#   sudo ./scripts/install.sh --prefix /usr/local
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
SKIP_DEPS=0
SKIP_LSM_HINT=0

for arg in "$@"; do
    case "$arg" in
        --skip-deps)    SKIP_DEPS=1 ;;
        --prefix=*)     PREFIX="${arg#*=}" ;;
        --no-lsm-hint)  SKIP_LSM_HINT=1 ;;
        -h|--help)
            sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "bilinmeyen argüman: $arg" >&2; exit 2 ;;
    esac
done

RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; CYN=$'\033[36m'; RST=$'\033[0m'
say()  { printf '%s\n' "${CYN}==>${RST} $*"; }
ok()   { printf '%s\n' "${GRN}  ✓${RST} $*"; }
warn() { printf '%s\n' "${YEL}  !${RST} $*"; }
die()  { printf '%s\n' "${RED}  ✗${RST} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "root olarak calistirin: sudo $0"

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SRC_DIR"

# --- 1. Bagimliliklar ---
if [[ $SKIP_DEPS -eq 0 ]]; then
    say "Bagimliliklar kuruluyor"
    if command -v apt-get >/dev/null; then
        apt-get update -qq
        apt-get install -y --no-install-recommends \
            clang llvm libbpf-dev bpftool make golang-go python3 python3-pip >/dev/null
    elif command -v dnf >/dev/null; then
        dnf install -y clang llvm libbpf-devel bpftool make golang python3 python3-pip >/dev/null
    elif command -v pacman >/dev/null; then
        pacman -S --noconfirm clang llvm libbpf bpf make go python python-pip >/dev/null
    else
        warn "bilinmeyen paket yoneticisi, bagimliliklar atlandi"
    fi
    ok "bagimliliklar hazir"
fi

# --- 2. Kontroller ---
say "Ortam kontrolu"

# go, clang ve python3 farkli yerlerde olabilir (snap, /usr/local,
# kullanici dizini). PATH'i genisletmeden once bira bir ara.
find_tool() {
    local name="$1"
    if command -v "$name" >/dev/null 2>&1; then
        command -v "$name"
        return 0
    fi
    local p
    for p in /usr/local/go/bin/go /usr/lib/go/bin/go \
             /snap/bin/go "$HOME/go/bin/go" /usr/local/bin/go; do
        [[ -x "$p" ]] && { printf '%s\n' "$p"; return 0; }
    done
    return 1
}

for t in go clang python3 make; do
    found="$(find_tool "$t")" || die "$t bulunamadi (paket yoneticisiyle kurun)"
    if [[ "$found" != "$(command -v "$t" 2>/dev/null || true)" ]]; then
        export PATH="$(dirname "$found"):$PATH"
    fi
    ok "$t -> $found"
done

KVER="$(uname -r | cut -d. -f1)"
KMIN="$(uname -r | cut -d. -f2)"
if (( KVER < 5 )) || { (( KVER == 5 )) && (( KMIN < 15 )); }; then
    die "kernel 5.15+ gerekli, simdiki: $(uname -r)"
fi
ok "kernel $(uname -r) yeterli"

# --- 3. Derle ---
say "Derleniyor"
make -s all
ok "derleme tamam"

# --- 4. Kurulum ---
say "Kuruluyor ($PREFIX)"
install -d "$PREFIX/bin" /usr/lib/axlinux /etc/axlinux
install -m 0755 src/go/axdaemon/axdaemon "$PREFIX/bin/axdaemon"
install -m 0755 src/go/axlog/axlog       "$PREFIX/bin/axlog"
install -m 0644 src/bpf/axbpf.o          /usr/lib/axlinux/axbpf.o
install -m 0644 examples/*.yaml          /etc/axlinux/ 2>/dev/null || true
install -m 0644 docs/INSTALL.md          /usr/share/doc/axlinux/ 2>/dev/null || true

# axctl: yorumlayici tabanli, bu yuzden lib'e degil /usr/local/bin'e
install -d "$PREFIX/lib/axlinux-python"
cp -r src/python/axctl "$PREFIX/lib/axlinux-python/"
cat > "$PREFIX/bin/axctl" <<EOF
#!/bin/sh
exec env PYTHONPATH="$PREFIX/lib/axlinux-python" python3 -m axctl "\$@"
EOF
chmod 0755 "$PREFIX/bin/axctl"
ok "axctl, axdaemon, axlog, axbpf.o kuruldu"

# --- 5. Servis ---
if [[ -d /lib/systemd/system ]]; then
    say "systemd servisleri kaydediliyor"
    for svc in axdaemon axlog; do
        if [[ -f "packaging/$svc.service" ]]; then
            sed "s#/usr/local/bin#${PREFIX}/bin#g; s#/usr/lib/axlinux#/usr/lib/axlinux#g" \
                "packaging/$svc.service" > "/lib/systemd/system/$svc.service"
            ok "$svc.service kuruldu"
        else
            warn "packaging/$svc.service bulunamadi, atlandi"
        fi
    done
    systemctl daemon-reload
    # AXLOG AYNI ZAMANDA ETKINLESTIRILIR. axdaemon audit kayitlarini
    # axlog'a yazar; axlog etkin degilse kayitlar bellekte kalir ve
    # /var/log/axlinux bos olur. Denetim izi kalici olmalidir.
    systemctl enable axlog >/dev/null 2>&1 \
        && ok "axlog servisi etkin (kalici audit kaydi)" \
        || warn "axlog etkinlestirilemedi; kayitlar yazilmayacak"
    systemctl enable axdaemon >/dev/null 2>&1 \
        && ok "axdaemon servisi etkin" \
        || warn "axdaemon etkinlestirilemedi"
fi

# --- 6. LSM kontrolu ---
say "LSM zinciri kontrolu"
CHAIN="$(cat /sys/kernel/security/lsm 2>/dev/null || echo 'okunamadi')"
echo "    zincir: $CHAIN"

if [[ ",$CHAIN," == *,bpf,* ]]; then
    ok "bpf LSM aktif - AXlinux calisir"
else
    warn "bpf LSM zincirde YOK - AXlinux politika UYGULAMAZ"
    if [[ $SKIP_LSM_HINT -eq 0 ]]; then
        cat <<EOF

  ${RED}POLITIKA UYGULANMAYACAK${RST}
  Politika yukleyebilirsiniz ama cekirdek hicbir kurali
  uygulamaz. Duzeltmek icin:

    1) ${PREFIX}/bin/axctl mode disabled
       (her sey su an calismiyor, acikca belirtiyoruz)

    2) /etc/default/grub dosyasinda:
         GRUB_CMDLINE_LINUX_DEFAULT="... lsm=apparmor,bpf"

    3) sudo update-grub && sudo reboot

    4) cat /sys/kernel/security/lsm   # 'bpf' gorunmeli

  Ayrintili: docs/INSTALL.md bolum 1
EOF
    fi
fi

cat <<EOF

${GRN}Kurulum tamamlandi.${RST}

  axctl init                      # ~/.axlinux/ olustur
  axctl policy edit               # politikani yaz
  axctl policy check              # dogrula
  axctl policy simulate           # neyi etkileyecegini gor
  sudo axctl reload               # uygula
  axctl status                    # durumu kontrol et

EOF
