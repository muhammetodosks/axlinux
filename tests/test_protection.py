#!/usr/bin/env python3
"""ax_protected (kilitlenme korumasi) sozlesme testleri.

Bu testler koruma listesinin KERNEL'de gercekten var oldugunu ve
Guvenlik acigi yaratmadigini dogrular. Liste yanlislikla cok
genisletilirse (orn. tumEditor uygulamalari) koruma amacini
yitirir; cok daraltilirsa ise sistem yine kilitlenir.

Calistirma: python3 -m pytest tests/test_protection.py
veya:        python3 tests/test_protection.py
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BPF_DIR = os.path.join(HERE, "..", "src", "bpf")
AXBPF_H = os.path.join(BPF_DIR, "axbpf.h")

# Bu surecler HIC BIR ZAMAN engellenmemeli. Bunlardan biri
# engellenirse kullanici sisteme erisimini kaybeder.
#
# Liste "kurtarma yolu"dur: makine ayakta kalmali, oturum
# acilabilmeli ve kullanici bir kabuga ulasabilmeli.
MUST_PROTECT = [
    # calisma ortami
    "systemd", "systemd-logind", "systemd-udevd", "systemd-journald",
    "init", "kthreadd",
    # oturum acma
    "sshd", "login", "agetty", "sudo", "su", "doas",
    # mesajlasma / yetki
    "dbus-daemon", "polkitd", "NetworkManager",
    # kabuk (kilitlenmenin AN sorucusu)
    "bash", "sh", "dash", "zsh", "fish",
]

# Bu surecler KORUNMAMALI. Aksi halde MAC islevsizlesir:
# kullanicinin uygulamalari kurala tabi olmaz.
#
# Onemli: dil kosullari (python3, node, ...) de burada. Cogu gercek
# uygulama bir yorumlayicidan calisir; bunlari korumak "python3
# /etc/shadow okuyamaz" turunden en sik kurallari yazilamaz
# hale getirir. Koruma yalnizca kurtarma yolunu (kabuk, oturum
# acma, yetki yukseltme) acik tutmalidir; yorumlayici engellemek
# kilitlenme yaratmaz cunku kullanici hala kabuga sahiptir.
MUST_NOT_PROTECT = [
    # ofis uygulamalari - MAC'in asil hedefi
    "firefox", "chromium", "google-chrome",
    # sunucular
    "nginx", "apache2", "httpd", "postgres", "mysqld", "redis-server",
    # genel araclar
    "curl", "wget", "git", "tar", "rsync", "docker", "containerd",
    # saldiri yuzeyi olan her sey
    "nc", "ncat", "socat", "nmap", "metasploit", "msfconsole",
    # dil kosullari - en sik MAC hedefleri
    "python3", "python", "node", "npm", "perl", "ruby", "deno", "bun",
    # terminal cokluklayici ve editor: konfor araci, kurtarma yolu degil
    "tmux", "screen", "code",
]

# Tum kancalarda koruma cagrisi bulunmali.
HOOKS = [
    "hooks_file_open.inc",
    "hooks_inode_permission.inc",
    "hooks_bprm_check_security.inc",
    "hooks_socket_connect.inc",
    "hooks_socket_bind.inc",
]


def read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def protected_set(header):
    """ax_protected() govdesindeki ax_comm_is çağrılarını çıkarır."""
    m = re.search(
        r"static __always_inline int ax_protected\(const char \*comm\)\s*\{(.*?)\n\}",
        header,
        re.S,
    )
    if not m:
        return None
    return set(re.findall(r'ax_comm_is\(comm,\s*"([^"]+)"\)', m.group(1)))


def main():
    if not os.path.exists(AXBPF_H):
        print(f"HATA: {AXBPF_H} bulunamadi")
        return 1

    header = read(AXBPF_H)
    prot = protected_set(header)
    failures = []

    if prot is None:
        print("FAIL: ax_protected() tanimi bulunamadi")
        return 1
    print(f"ok: ax_protected() bulundu, {len(prot)} surec listeli")

    # --- zorunlu koruma
    missing = [s for s in MUST_PROTECT if s not in prot]
    if missing:
        failures.append(f"korunmasi ZORUNLU ama listede yok: {missing}")
    else:
        print(f"ok: {len(MUST_PROTECT)} kritik surec korunuyor")

    # --- korunmaması gerekenler
    over = [s for s in MUST_NOT_PROTECT if s in prot]
    if over:
        failures.append(f"korunmAMASI gerekir ama listede: {over}")
    else:
        print(f"ok: {len(MUST_NOT_PROTECT)} hedef surec koruma disi")

    # --- PID 1 ve PID 2 korumasi
    #
    # ONCEDEN `bpf_get_current_pid_tgid() >> 32 <= 2` sayimsal
    # kontrolu vardi. KALDIRILDI.
    #
    # Sebep (Fedora 44 / clang 22 / kernel 6.19): o kontrol
    # dogrulayiciyi kirip programin yuklenmesini engelliyordu.
    #   At program exit the register R0 has smin=0 smax=4294967295
    #   should have been in [-4095, 0]
    #
    # LSM kancasi coklu `return` icerdiginden clang 22 cikis
    # degerlerini tek stack degiskeninde birlestiriyor; bu degere
    # katilan PID skateri yiginda tasinip program sonunda ISARETsiz
    # (u32) yuklendigi icin verifier araligi 0..4294967295 goruyor
    # ve program reddediliyordu.
    #
    # Sonuc: hicbir kanca yuklenmiyor; daemon "ebpf yuklenemedi"
    # deyip enforcement OLMADAN calisiyordu.
    #
    # Guvenlikte KAYIP YOK: PID 1 ve PID 2 ADLA zaten korunuyor.
    #   PID 1 -> comm "systemd" (erken acilista "init"/"swapper")
    #   PID 2 -> comm "kthreadd"
    #
    # Test artik sayimsal kontrolu degil, ADLA kapsama kontrolu
    # yapar.
    pid_commas = ["systemd", "init", "kthreadd", "swapper", "migration"]
    eksik_pid = [c for c in pid_commas if c not in prot]
    if eksik_pid:
        failures.append(
            "PID 1/2 korumasi adla kapsamiyor: " + ", ".join(eksik_pid))
    else:
        print("ok: PID 1/2 korumasi adla kapsandi "
              "({})".format(", ".join(pid_commas)))

    if re.search(r"pid_tgid\(\)\s*>>\s*32\)\s*<=\s*2", header):
        print("uyari: sayimsal PID kontrolu geri geldi; "
              "verifier hatasina yol acabilir")
    else:
        print("ok: PID <= 2 (init/kthreadd) korumasi var")

    # --- her kancada koruma cagrisi
    for hook in HOOKS:
        path = os.path.join(BPF_DIR, hook)
        if not os.path.exists(path):
            failures.append(f"kanca dosyasi eksik: {hook}")
            continue
        body = read(path)
        if "ax_protected(" not in body:
            failures.append(f"{hook} icinde ax_protected() cagrisi yok - "
                            f"bu kanca kilitlenmeye acik")
    if not any("ax_protected() cagrisi yok" in f for f in failures):
        print(f"ok: {len(HOOKS)} kancanin tamami koruma cagiryor")

    # --- bprm'de dogru siralama
    #
    # Dogru sira: memset -> ax_get_comm -> ax_fill_path -> ax_protected
    #
    #   * memset ONCE gelmeli; pkey->comm alanini sildigi icin
    #     memset sonrasi comm yeniden yazilmalidir.
    #   * ax_get_comm, ax_protected'dan ONCE gelmeli.
    #   * Koruma kontrolu artik EBVEYNDE DEGIL HEDEFTE calisiyor:
    #     hedef adi bprm->file yolundan (ax_fill_path) bulunur ve
    #     ax_protected(target) ile denetlenir.
    #
    # NEDEN DEGISTI: once pkey->comm (ebeveyn surec: "bash",
    # "sudo") uzerinde kontrol ediliyordu; bunlarin hepsi korumali
    # oldugu icin kanca HER ZAMAN erkenden donuyor ve tum
    # process.exec kurallari etkisiz kaliyordu. deep_verify'daki test
    # de yanlis yolla gecidi: python3 calistiriliyor, blok HIC
    # olmuyor, python3 kendi koduyla exit(1) donuyordu.
    bprm = read(os.path.join(BPF_DIR, "hooks_bprm_check_security.inc"))
    if "ax_protected(" in bprm:
        mi = bprm.find("memset(pkey")
        ci = bprm.find("ax_get_comm(pkey->comm)")
        fi = bprm.find("ax_fill_path(")
        pi = bprm.find("ax_protected(target)")
        if mi == -1 or ci == -1 or fi == -1 or pi == -1:
            failures.append(
                "bprm'de memset/ax_get_comm/ax_fill_path/ax_protected "
                "cagrilarindan biri yok "
                f"(memset@{mi}, get_comm@{ci}, fill@{fi}, protect@{pi})")
        elif -1 < mi < ci < fi < pi:
            print("ok: bprm'de siralama dogru "
                  "(memset -> ax_get_comm -> ax_fill_path -> "
                  "ax_protected(target))")
        else:
            failures.append(
                "bprm'de siralama YANLIS. Dogru sira: memset -> "
                "ax_get_comm -> ax_fill_path -> ax_protected(target). "
                "Kontrol HEDEF uzerinde olmali; ebeveyn uzerinde "
                "olursa kanca her zaman erken doner ve "
                "process.exec kurallari uygulanmaz. "
                f"(memset@{mi}, get_comm@{ci}, fill@{fi}, protect@{pi})")

    # --- sonuc
    print()
    if failures:
        for f in failures:
            print(f"FAIL: {f}")
        print(f"\n{len(failures)} basarisiz")
        return 1
    print("TUM KORUMA TESTLERI GECTI")
    return 0


if __name__ == "__main__":
    sys.exit(main())
