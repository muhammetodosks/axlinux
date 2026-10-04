#!/bin/sh
# AXlinux SELinux kurulumu. IDEMPOTENT (tekrar calistirilabilir).
#
# Bu betigi rpm %post ve install.sh paylasir; iki yolun ayni
# sonucu vermesi icin tek dogruluk kaynagi.
#
# SELinux'u bilerek ATLAMAK yanlis olur. AXlinux kendi alaninda
# (axlinux_daemon_t) calismalidir; alan disinda (unconfined_service_t)
# calisiyorsa SELinux onu kisitlamaz ve Fedora'nin sertlastirilmis
# profilinde tamamen calismaz.
set -e

MODULE=axlinux
PREFIX=/usr/local
UNITDIR=/usr/lib/systemd/system
FC="$PREFIX/axlinux-selinux-fcontexts"

if ! command -v getenforce >/dev/null 2>&1; then
    echo "  SELinux sistemde degil; atlaniyor." >&2
    exit 0
fi
if ! command -v semodule >/dev/null 2>&1; then
    echo "  SELinux politika araclari yok (policycoreutils); atlaniyor." >&2
    exit 0
fi

echo "  SELinux: $(getenforce)"

# 1) Politika modulunu derle (kaynak varsa) ve kur
PP=""
for cand in "$PREFIX/share/selinux/packages/$MODULE.pp" \
            "$FC/../selinux/packages/$MODULE.pp" \
            "/usr/share/selinux/packages/$MODULE.pp"; do
    [ -f "$cand" ] && { PP="$cand"; break; }
done
if [ -z "$PP" ]; then
    PP=$(find / -name "$MODULE.pp" -path '*selinux*' 2>/dev/null | head -1)
fi

if [ -n "$PP" ] && [ -f "$PP" ]; then
    if ! semodule -i "$PP" 2>/dev/null; then
        echo "  HATA: SELinux modulu kurulamadi ($PP)" >&2
        exit 1
    fi
    echo "  modul kuruldu: $PP"
else
    echo "  HATA: $MODULE.pp bulunamadi; modul kurulamadi." >&2
    echo "  RPM ile kurulumda bu bir hata; kaynak kurulumda" >&2
    echo "  'make -C packaging/fedora && make install-selinux' calistir." >&2
    exit 1
fi

# 2) Dosya baglamlari.
#
#    semanage fcontext -a -u system_u -r system_r ... DENEMESI
#    Fedora 44'te CALISMIYOR ("usage: semanage"): fcontext alt
#    komutunda -u/-r secenekleri YOK. Betik sessizce devam ediyor
#    ve eski (yanlis) kayit kaliyordu:
#      /var/log/axlinux  ->  unconfined_u:object_r:axlinux_var_log_t:s0
#    Sistem dosyasi icin kullanici system_u olmali.
#
#    Duzeltme: once eski kayit SILINIR, sonra tipi YAZILIR.
#    Kullanici/rol restorecon tarafindan politikadan alinir.
set_fcontext() {
    semanage fcontext -d "$2" >/dev/null 2>&1 || true
    if ! semanage fcontext -a -t "$1" "$2" >/dev/null 2>&1; then
        semanage fcontext -m -t "$1" "$2" >/dev/null 2>&1 || true
    fi
}
set_fcontext axlinux_axbpf_t     "$PREFIX/lib/axlinux/axbpf\.o"
set_fcontext axlinux_etc_t       '/etc/axlinux(/.*)?'
set_fcontext axlinux_var_lib_t   '/var/lib/axlinux(/.*)?'
set_fcontext axlinux_var_log_t   '/var/log/axlinux(/.*)?'
set_fcontext axlinux_var_run_t   '/run/axlinux(/.*)?'
set_fcontext axlinux_daemon_exec_t "$PREFIX/bin/axdaemon"
set_fcontext axlinux_log_exec_t  "$PREFIX/bin/axctl"
echo "  dosya baglamlari tanimlandi"

# 3) Mevcut dosyalara baglamlari UYGULA. Bu olmadan dosyalar
#    rpm/semanage'in biraktigi genel baglamda kalir (var_log_t,
#    lib_t, etc_t) ve AXlinux okuyamaz.
for p in "$PREFIX/lib/axlinux" /etc/axlinux /var/lib/axlinux \
         /var/log/axlinux /run/axlinux \
         "$PREFIX/bin/axdaemon" "$PREFIX/bin/axlog" \
         "$UNITDIR/axdaemon.service" "$UNITDIR/axlog.service"; do
    [ -e "$p" ] && restorecon -R "$p" 2>/dev/null
done
echo "  baglamlar uygulandi"

# 4) bpffs dizinini KUR.
#
# Haritalar /sys/fs/bpf/axlinux altina pinlenir. Dizini daemon
# kendisi olusturmayi deniyor ve basarisiz oluyor:
#
#   msg="pin dizini olusturulamadi" dir=/sys/fs/bpf/axlinux
#     error="mkdir /sys/fs/bpf/axlinux: permission denied"
#
# Bu SELinux degildi: permissive modda da olmuyor. Daemon root
# (Uid: 0) ve gerekli yeteneklere sahip, ama systemd'in
# seccomp filtresi (Seccomp: 2, 3 filtre) mkdir'i engelliyor.
#
# Neden ONEMLI: harita pinlenmezse reload YENI harita uretir;
# takili BPF programlari ESKI haritaya bakmaya devam eder ve
# yeniden yuklenen politika HIZLA UYGULANMAZ. Yani "reload
# basarili" denir ama politika etkisiz kalir.
#
# Cozum: dizini kurulum betigi (kisitlanmis alan DISINDAN)
# olusturur. Bu standart yaklasimdir: bpffs dizinini arac
# kurulumu yaratir, daemon yalnizca pinler.
if [ -d /sys/fs/bpf ]; then
    if ! mkdir -p /sys/fs/bpf/axlinux 2>/dev/null; then
        echo "  HATA: /sys/fs/bpf/axlinux olusturulamadi." >&2
        echo "  Politika reload sonrasi UYGULANMAZ." >&2
        exit 1
    fi
    chmod 0700 /sys/fs/bpf/axlinux
    restorecon /sys/fs/bpf/axlinux 2>/dev/null || true
    chcon -t bpf_t /sys/fs/bpf/axlinux 2>/dev/null || true
    echo "  bpffs dizini hazir: /sys/fs/bpf/axlinux"
fi

# 5) LSM zinciri uyarisi (hata degil; operatora bilgi)
if [ -r /sys/kernel/security/lsm ]; then
    case ",$(cat /sys/kernel/security/lsm)," in
        *,bpf,*) : ;;
        *) echo "  UYARI: BPF LSM etkin degil; enforcement calismaz." ;;
    esac
fi

echo "  SELinux hazir"
exit 0
