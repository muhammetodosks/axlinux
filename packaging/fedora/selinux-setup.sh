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
# On ek artik KANONIK /usr. Ikililer /usr/bin altina kuruluyor
# (bkz. Makefile PREFIX). Burada /usr/local kalirsa:
#
#   - file_context kaydi /usr/local/bin/axdaemon'a yazilir,
#   - gercek ikili /usr/bin/axdaemon bin_t etiketinde kalir,
#   - init_system_domain() gecisi olusmaz,
#   - daemon unconfined_service_t'de calisir.
#
# Yani SELinux alan izni tanimli olur ama DAEMON O ALANDA
# CALISMAZ: koruma sahte, bpf() unconfined'ten gelir.
# RPM ile kurulumda sessizce ortaya cikti; elle kurulumda
# /usr/local/bin gercekten var oldugu icin gorunmuyordu.
PREFIX="${PREFIX:-/usr}"
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
# SCRIPT_DIR: bu betigin bulundugu dizin. Kurulumda
# /usr/local/share/axlinux/ altina, kaynakta packaging/fedora/ altina
# konur. Derlenen .pp de ayni dizinde olur.
SCRIPT_DIR=$(cd "$(dirname "$0")" 2>/dev/null && pwd)

# ONCELIK SIRASI ONEMLI.
#
# Dogru sira: ONCE bu betigin yanindaki (yani az once derlenmis)
# modul, SONRA sisteme kurulmus olan.
#
# Once sistem yolu ("/usr/share/selinux/packages") basta oldugu icin
# ESKI kurulu modul seçiliyordu ve yeni derlenen modul HIC kurulmuyordu.
# Sonuc: kaynaga yeni izin eklemek (orn. bpffs yazma izni) hicbir
# etki gostermiyordu; sesearch kurali bulamiyor, harita pinleme
# yine "permission denied" veriyordu.
# Adaylar arasinda EN YENI dosya secilir (`-nt`).
#
# Sadece oncelik sirasi yetersiz: kurulum yeni kaynagi, sistem
# yolu eskiyi tasiyor olabilir. Eski modul kurulunca yeni tip
# tanimlari (orn. axlinux_cli_exec_t) yok oluyor ve modul
# "type ... is not defined" ile basarisiz kuruluyor.
PP=""
for cand in "$SCRIPT_DIR/$MODULE.pp" \
            "$SCRIPT_DIR/../$MODULE.pp" \
            "$PREFIX/share/axlinux/$MODULE.pp" \
            "$PREFIX/share/selinux/packages/$MODULE.pp" \
            "/usr/share/selinux/packages/$MODULE.pp" \
            "$FC/../selinux/packages/$MODULE.pp"; do
    [ -f "$cand" ] || continue
    if [ -z "$PP" ] || [ "$cand" -nt "$PP" ]; then
        PP="$cand"
    fi
done
if [ -z "$PP" ]; then
    # ONCEDEN: find / -name "$MODULE.pp" -path '*selinux*'
    # Bu kosul derlenen dosyayi BULAMIYORDU: kaynaktan kurulumda
    # dosya packaging/fedora/axlinux.pp altindadir ve yolunda
    # "selinux" kelimesi YOK. Sonuc: modul kurulamadi, SELinux
    # Enforcing altinda axdaemon unconfined_t'de calisti ve alan
    # kurallari hic uygulanmadi.
    #
    # Simdi yol filtresi yok; yalnizca adi eslesen dosya aranir.
    PP=$(find / -name "$MODULE.pp" 2>/dev/null | head -1)
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
# --- Guvenlik on kontrolu: calisan politika okunabiliyor mu? ---
#
# Gercek hata (Fedora 43 cloud imajinda olculdu):
# `semanage fcontext -a -t axlinux_daemon_exec_t ...` BASARILI
# donuyor, ama tip calisan cekirdek politikasinda YOK. Sonuc:
#
#   ikili etiketlenince -> kanca 0/0, bpf 0, "ebpf yuklenemedi"
#   etiketlenmede kalinca -> kanca 5/5, bpf 5, enforcement calisir
#
# Yani konfinasyon etiketi sistemi tamamen bozuyor. Ayirt edici
# olcut `seinfo -t`:
#
#   Fedora 44 -> 5292 tip (politika okunuyor)  etiketlemek GUVENLI
#   Fedora 43 ->    0 tip (politika okunamiyor) etiketlemek TEHLIKELI
#
# Politikayi okuyamiyorsak tipin guvenli oldugunu DOGRULAMAK
# MUMKUN DEGIL; o durumda etiketlemek yerine kurulumu yazilmis
# etmemek, sistemi calisir halde birakmanin cok daha iyi yoludur.
AX_POLICY_READABLE=1
if command -v seinfo >/dev/null 2>&1; then
    _types=$(seinfo -t 2>/dev/null | wc -l)
    if [ "${_types:-0}" -eq 0 ]; then
        AX_POLICY_READABLE=0
    fi
fi

set_fcontext() {
    # $1 = tip, $2 = yol (fcontext)
    #
    # ONCE eski kaydi sil, sonra yaz.
    #
    # TIP TANIMLI DEGILSE HICBIR SEY YAZMA. Gercek hata (Fedora 43
    # cloud imajinda olculdu): modulun tipi politikada yoksa
    # semanage "-a" sessizce basarisiz olur. Kayit yine de
    # yazilirsa ikili, politikada VAR OLMAYAN bir tipe etiketlenir
    # ve SELinux hicbir seye izin vermez:
    #
    #   etiketli  -> kanca 0/0, bpf 0, "ebpf yuklenemedi"
    #   etiketsiz -> kanca 5/5, bpf 5, enforcement calisir
    #
    # Yani etiketlemek sistemi tamamen bozuyordu. Guvenli taraf
    # kurali: tip tanimli degilse etiketleme, bir kez uyari ver,
    # devam et. LSM enforcement calisir; SELinux kisitlamasi
    # olmaz ve deep_verify bunu acikca bildirir.
    if [ "$AX_POLICY_READABLE" -eq 0 ]; then
        if [ -z "${AX_SELINUX_TYPE_WARNED:-}" ]; then
            echo "  UYARI: calisan SELinux politikasi okunamiyor (seinfo: 0 tip)."
            echo "         Konfinasyon etiketleri UYGULANMADI - aksi halde"
            echo "         ikililer var olmayan bir tipe etiketlenir ve"
            echo "         eBPF yuklenemez (kanca 0/0)."
            echo "         LSM enforcement etkin, SELinux kisitlamasi yok."
            AX_SELINUX_TYPE_WARNED=1
        fi
        return 1
    fi
    semanage fcontext -d "$2" >/dev/null 2>&1 || true
    if semanage fcontext -a -t "$1" "$2" >/dev/null 2>&1; then
        return 0
    fi
    if semanage fcontext -m -t "$1" "$2" >/dev/null 2>&1; then
        return 0
    fi
    # Ikisi de basarisiz: tip tanimli degil (veya yol gecersiz).
    semanage fcontext -d "$2" >/dev/null 2>&1 || true
    if [ -z "${AX_SELINUX_TYPE_WARNED:-}" ]; then
        echo "  UYARI: SELinux tipi '$1' politikada tanimli degil;"
        echo "         '$2' ETIKETLENMEDI."
        echo "         LSM enforcement calisir, SELinux kisitlamasi olmaz."
        AX_SELINUX_TYPE_WARNED=1
    fi
    return 1
}
set_fcontext axlinux_axbpf_t     "$PREFIX/lib/axlinux/axbpf\.o"
set_fcontext axlinux_etc_t       '/etc/axlinux(/.*)?'
set_fcontext axlinux_var_lib_t   '/var/lib/axlinux(/.*)?'
set_fcontext axlinux_var_log_t   '/var/log/axlinux(/.*)?'
set_fcontext axlinux_var_run_t   '/run/axlinux(/.*)?'
# Once eski on eke ait kayitlari temizle. semanage fcontext
# kayitlari kalicidir; on ek /usr/local -> /usr degisse bile
# eski kayit durur ve hicbir dosyaya isabet etmez.
for stale in /usr/local/bin/axdaemon /usr/local/bin/axlog \
             /usr/local/bin/axctl \
             "/usr/local/lib/axlinux/axbpf\\.o"; do
    semanage fcontext -d "$stale" >/dev/null 2>&1 || true
done
set_fcontext axlinux_daemon_exec_t "$PREFIX/bin/axdaemon"
set_fcontext axlinux_log_exec_t    "$PREFIX/bin/axlog"
set_fcontext axlinux_cli_exec_t    "$PREFIX/bin/axctl"
echo "  dosya baglamlari tanimlandi"

# 3) Mevcut dosyalara baglamlari UYGULA. Bu olmadan dosyalar
#    rpm/semanage'in biraktigi genel baglamda kalir (var_log_t,
#    lib_t, etc_t) ve AXlinux okuyamaz.
for p in "$PREFIX/lib/axlinux" /etc/axlinux /var/lib/axlinux \
         /var/log/axlinux /run/axlinux \
         "$PREFIX/bin/axdaemon" "$PREFIX/bin/axlog" "$PREFIX/bin/axctl" \
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

# 6) Alan gecisi dogrulaması
#
# axdaemon'in ayri bir alanda calistigini DOGRULAMAK icin.
# Burada "semanage login -a -t ..." KULLANILMAZ: Fedora 44'teki
# semanage bu secenegi saglamiyor ve alan gecisi zaten calisiyor.
#
# Alan gecisi systemd servisleri icin LOGIN eslemesinden degil,
# calistirilabilir dosyanin ETIKETINDEN olusur:
#   /usr/bin/axdaemon -> axlinux_daemon_exec_t
#   init_system_domain() bu etiketi baslatan domain_auto_trans
#   kuralini kurar.
#
# Buraya daha once bir "semanage login" adimi eklenmisti; o adim
# her kurulumda basarisiz oluyor ve calismayan bir sistemi
# varsaydi. Gercek dogrulama asagidakidir: ayakta olan daemon'in
# gercek baglami okunur.
# --- DOGRULAMA: konfinasyon AXlinux'i calisir halde birakti mi? ---
#
# Gercek hata (Fedora 43 cloud imajinda olculdu): etiketler
# uygulandiginda axdaemon axlinux_daemon_t alanina giriyor ve
# SELinux BPF harita islemini REDDEDIYOR:
#
#   avc: denied { map_read map_write } for comm="axdaemon"
#        scontext=system_u:system_r:axlinux_daemon_t:s0
#
# Sonuc: eBPF yuklenmiyor -> kanca 0/0 -> enforcement HIC CALISMIYOR.
# Yani konfinasyon, konfinasyonsuz sistemden daha kotu bir sistem
# birakiyor.
#
# Bu yuzden etiketleme sonrasi FIUNCIONAL dogrulama yapilir: eBPF
# gercekten yukleniyor mu? Yuklenmiyorsa etiketler GERI ALINIR ve
# operator'a acikca bildirilir. Boylece en kotu durumda bile sistem
# calisir kalir (konfinasyonsuz ama enforcement'li).
# Dogrulama icin daemon AYAKTA olmali. Temiz kurulumda servis
# henuz baslamamis olur; o zaman baslatip bekliyoruz. Aksi halde
# dogrulama bos gecer ve bozuk etiketler sistemde kalir
# (Fedora 43'te boyle oldu: kanca 0/0, bpf 0).
if ! pgrep -x axdaemon >/dev/null 2>&1; then
    if command -v systemctl >/dev/null 2>&1; then
        systemctl start axdaemon >/dev/null 2>&1 || :
        _w=0
        while [ "$_w" -lt 20 ]; do
            pgrep -x axdaemon >/dev/null 2>&1 && break
            _w=$((_w + 1)); sleep 1
        done
    fi
    unset _w
fi

_axd=$(pgrep -x axdaemon 2>/dev/null | head -1)
_axctx=""
if [ -n "$_axd" ] && [ -r "/proc/$_axd/attr/current" ]; then
    _axctx=$(tr -d '\000' < "/proc/$_axd/attr/current" 2>/dev/null)
fi

case "$_axctx" in
    *axlinux_daemon_t*)
        # Konfinede mi calisiyor? eBPF gercekten yuklendi mi?
        _bpf=""
        _t=0
        while [ "$_t" -lt 20 ]; do
            _bpf=$(axctl status --json 2>/dev/null \
                   | sed -n 's/.*"bpf_programs_loaded"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' \
                   | head -1)
            [ -n "$_bpf" ] && [ "${_bpf:-0}" -gt 0 ] && break
            _t=$((_t + 1)); sleep 1
        done
        if [ "${_bpf:-0}" -gt 0 ]; then
            echo "  alan dogrulandi: $_axctx (eBPF: $_bpf)"
        else
            echo "  UYARI: konfinasyon eBPF yuklemeyi engelliyor" >&2
            echo "         (axdaemon: $_axctx, bpf_programs_loaded=0)." >&2
            echo "         SELinux, BPF harita islemini reddediyor." >&2
            echo "         Guvenli taraf: etiketler geri aliniyor." >&2
            echo "         Enforcement LSM uzerinden calisacak," >&2
            echo "         SELinux kisitlamasi olmayacak." >&2
            for _f in "$PREFIX/bin/axdaemon" "$PREFIX/bin/axlog" "$PREFIX/bin/axctl"; do
                semanage fcontext -d "$_f" >/dev/null 2>&1 || true
            done
            semanage fcontext -d "$PREFIX/lib/axlinux/axbpf\.o" >/dev/null 2>&1 || true
            restorecon -F "$PREFIX/bin/axdaemon" "$PREFIX/bin/axlog" \
                        "$PREFIX/bin/axctl" >/dev/null 2>&1 || true
            restorecon -F "$PREFIX/lib/axlinux/axbpf.o" >/dev/null 2>&1 || true
            echo "  etiketler geri alindi; enforcement LSM ile aktif" >&2
            # Calisan surec ETIKETLENMIS baglamda oldugu icin
            # yeniden baslatilmali; aksi halde eski (kisitli) baglam
            # ile calismaya devam eder ve eBPF yuklenmez.
            if command -v systemctl >/dev/null 2>&1; then
                systemctl restart axdaemon axlog >/dev/null 2>&1 || :
                _r=0
                while [ "$_r" -lt 30 ]; do
                    _v=$(axctl status --json 2>/dev/null \
                         | sed -n 's/.*"bpf_programs_loaded"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' \
                         | head -1)
                    [ -n "${_v:-}" ] && [ "${_v:-0}" -gt 0 ] && break
                    _r=$((_r + 1)); sleep 1
                done
                echo "  yeniden baslatildi; eBPF: ${_v:-0} program" >&2
                unset _r _v
            fi
        fi
        ;;
    unconfined*)
        echo "  UYARI: axdaemon unconfined alanda calisiyor" >&2
        echo "         ($_axctx). LSM kancalarina disaridan" >&2
        echo "         mudahale edilebilir." >&2 ;;
    "")
        echo "  axdaemon henuz calismiyor; alan dogrulamasi yapilamadi" >&2 ;;
    *)
        echo "  axdaemon alani: $_axctx" ;;
esac
unset _axd _axctx _bpf _t _f

echo "  SELinux hazir"
exit 0
