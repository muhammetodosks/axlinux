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

    # --- PID <= 2 kontrolu
    if "pid_tgid() >> 32) <= 2" not in header.replace(" ", " "):
        # parantez/spasi varyasyonlarina toleransli
        if not re.search(r"pid_tgid\(\)\s*>>\s*32\)\s*<=\s*2", header):
            failures.append("PID <= 2 (init/kthreadd) kontrolu yok")
        else:
            print("ok: PID <= 2 (init/kthreadd) korumasi var")
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
    # Dogru sira: memset -> ax_get_comm -> ax_protected
    #
    #   * memset ONCE gelmeli; pkey->comm alanini sildigi icin
    #     memset sonrasi comm yeniden yazilmalidir.
    #   * ax_get_comm, ax_protected'dan ONCE gelmeli; koruma
    #     kontrolu comm uzerinden calistigi icin comm'un once
    #     doldurulmus olmasi zorunludur.
    bprm = read(os.path.join(BPF_DIR, "hooks_bprm_check_security.inc"))
    if "ax_protected(" in bprm:
        mi = bprm.find("memset(pkey")
        ci = bprm.find("ax_get_comm(pkey->comm)")
        pi = bprm.find("ax_protected(pkey->comm)")
        if mi == -1 or ci == -1 or pi == -1:
            failures.append(
                "bprm'de memset/ax_get_comm/ax_protected cagrilarindan "
                f"biri yok (memset@{mi}, get_comm@{ci}, protect@{pi})")
        elif -1 < mi < ci < pi:
            print("ok: bprm'de siralama dogru "
                  "(memset -> ax_get_comm -> ax_protected)")
        else:
            failures.append(
                "bprm'de siralama YANLIS. Dogru sira: "
                "memset -> ax_get_comm -> ax_protected. memset once "
                "gelmeli (comm alanini siler), ax_protected ise "
                "ax_get_comm'den sonra gelmeli (aksi halde comm bos "
                "okunur ve koruma calismaz). "
                f"(memset@{mi}, get_comm@{ci}, protect@{pi})")

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
