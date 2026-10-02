"""Politika derleyici - YAML → iç politika formatı."""

import os

from axctl.exceptions import PolicyError
from axctl.validator import VALID_ACTIONS, validate_policy, _expand_subject

# AXlinux bu sureclere guvenlik geregi hicbir kural UYGULAMAZ
# (kernel tarafinda ax_protected, src/bpf/axbpf.h). Nedeni: bunlardan
# birine kural uygulanirsa sistem kendini kilitler ve kullanici
# sisteme erisemez.
#
# Liste yalnizca KURTARMA YOLUDUR: calisma ortami, oturum acma ve
# kabuk zinciri. Dil kosullari (python3, node, perl, ruby) ve
# terminal/editor araclari (tmux, screen, code) listede DEGILDIR:
# bunlari korumak en sik MAC kurallarini yazilamaz hale getirir
# ve kazanilan tek sey oturumu kapatmaktir, ki zaten kabuk
# korundugu icin gerekli degildir.
#
# Burada o sureclere yazilan kurallari DERLEME zamaninda uyaririz.
# Aksi halde policy "1 kural yuklendi" der, kural map'e yazilir,
# ama hicbir dosya/ surec ile eslesmez ve kullanici neden
# calismadigini anlayamaz. Sessiz basarisizlik.
PROTECTED_PROCESSES = {
    # calisma ortami
    "systemd", "systemd-logind", "systemd-userdbd", "systemd-udevd",
    "systemd-journald", "systemd-oomd", "init", "kthreadd",
    # oturum acma / yetki
    "sshd", "sshd-session", "login", "agetty", "getty",
    "sudo", "su", "doas", "dbus-daemon", "dbus-broker", "polkitd",
    "rtkit-daemon", "NetworkManager", "wpa_supplicant",
    "gdm3", "gdm-session-worke",
    # kabuklar
    "bash", "sh", "dash", "zsh", "fish",
}

# Bir yol bileseninin blok boyutunu asamaz; asilirsa kural
# sessizce bos bir anahtara donusur. 8 blok x 31 karakter.
PATH_DEPTH = 8
PATH_SLOT = 32


def expand_path(path: str) -> str:
    """Kullanici yolunu mutlak yola cevirir.

    "~" ve "~/..." ifadeleri cekirdekte cozulmez; kernel her zaman
    mutlak yol gorur ("~/.ssh" ile "/home/mami/.ssh" esit degildir).
    Burada genisletilmezse kural hicbir zaman eslesmez ve kullanici
    yanlislikla korumayi etkin oldugunu sanir.
    """
    if not path:
        return path
    if path == "~":
        return os.path.expanduser("~")
    if path.startswith("~/"):
        return os.path.expanduser(path)
    return path


# Uygulanmayan aksiyonlar.
#
# Bu liste, LSM kancalarinin HICBIRININ uretmedigi aksiyonlari
# listeler. file.delete ve file.create icin AXlinux'ta uygun bir
# kanca yoktur: LSM zincirinde unlink_at, unlink hooks veya inode
#_delete kancasi baglanmaz. Bu aksiyonlar daha once VALID_ACTIONS
# icinde kabul ediliyordu; kullanici "bu dosya silinemez" yaziyor,
# derleme sorunsuz geciyor, kural map'e yaziliyor, dosya SILINIYOR.
#
# Kurali reddetmek yerine sessizce kabul etmek, urunu guvenilmez
# kilan sey tam olarak budur. Dogru davranis: acik hata ver, kurali
# yazma, hangi aksiyonun calistigini ve neyin calismadigini soyle.
UNIMPLEMENTED_ACTIONS = {
    "file.delete": "AXlinux su an silme kanacasi icermiyor "
                   "(lsm/inode_unlink_at bagli degil). Silme "
                   "kontrolu icin dosya sistemi izinleri "
                   "(chmod, ACL) kullanin.",
    "file.create": "AXlinux su an dosya olusturma kanacasi icermiyor. "
                   "Olusturma kontrolu icin dizin izinlerini "
                   "(chmod) kisitlayin.",
    "net.accept":  "AXlinux su an kabul edilen baglanti kanacasi "
                   "icermiyor (lsm/socket_accept bagli degil). "
                   "Gelen baglantilari dinleyici tarafinda "
                   "denetleyin.",
}


def check_action_implemented(action: str, rule_name: str) -> None:
    """Uygulanmayan bir aksiyonla yazilan kurali reddeder.

    Sessiz basarisizligin en kotu turu: kural "yuklendi" der,
    map'e yazilir, hicbir sey olmaz. Kullanici guvendiigi icin
    (or. "kimse bu dosyayi silemez") yanlis bir guvenlik
    varsayimiyla yasar.
    """
    reason = UNIMPLEMENTED_ACTIONS.get(action)
    if reason is None:
        return
    raise PolicyError(
        f"Kural {rule_name!r} uygulanamaz: '{action}' aksiyonu "
        f"AXlinux tarafindan henuz desteklenmiyor. {reason} "
        f"Desteklenen aksiyonlar: "
        f"{sorted(set(VALID_ACTIONS) - set(UNIMPLEMENTED_ACTIONS))}"
    )


def check_path_representable(path: str, rule_name: str) -> None:
    """Yolun blok duzenine sigip sigmadigini dogrular.

    AXlinux yol alanini PATH_DEPTH x PATH_SLOT baytlik sabit
    bloklara boler. Sigmayan bir yol sessizce bos bir anahtara
    donusur ve kural map'e yazilir ama HICBIR dosyayla eslesmez.
    Burada acik hata verilir.
    """
    if not path or not path.startswith("/"):
        return

    parts = [p for p in path.split("/") if p]
    problems = []
    if len(parts) > PATH_DEPTH:
        problems.append(
            f"{len(parts)} bilesen var, en fazla {PATH_DEPTH} "
            f"desteklenir")
    long = [p for p in parts if len(p) > PATH_SLOT - 1]
    if long:
        problems.append(
            f"asiri uzun bilesen: {long[0]!r} "
            f"({len(long[0])} karakter, en fazla {PATH_SLOT - 1})")

    if problems:
        raise PolicyError(
            f"Kural {rule_name!r} uygulanamaz: {'; '.join(problems)}. "
            f"Yol alani {PATH_DEPTH}x{PATH_SLOT} baytlik bloklara "
            f"bolunur; sigmayan yol sessizce bos bir anahtara donusur "
            f"ve kural hicbir dosyayla eslesmez."
        )


def check_protected_subject(subjects, rule_name: str) -> None:
    """Korumali surecleri hedefleyen kurallari REDDEDER.

    Once bu yalnizca bir uyariydi ve politika yine de yukleniyordu.
    Oysa uyari metninin kendisi diyordu: "Bu kurallar sessizce
    etkisiz kalir." Yani kurallar map'e yaziliyor, derleme "1 kural"
    diyor, kullanici politikayi yuklendigini saniyor - ve hicbir
    sey engellenmiyor. Bu, sessiz basarisizligin en kotu hali:
    operator guvenlik ONDAYKEN saniyor, sistemde ise hicbir sey
    uygulanmiyor.

    Ayni sinif sorun check_path_representable icin zaten ACIK HATA
    sayiliyor ("sessizce bos bir anahtara donusur"). Iki durum da
    "kural hicbir seyle eslesmez"; biri hata, digeri uyari
    olmamalydi. Artik ikisi de hata.

    Bu yuzden operator ya kurali gercek uygulamaya yazar
    (firefox, nginx, curl) ya da kurali kaldirir.
    """
    hits = [s for s in subjects if s in PROTECTED_PROCESSES]
    if not hits:
        return
    raise PolicyError(
        f"Kural {rule_name!r} korumali sistem sureclerini hedefliyor: "
        f"{', '.join(hits)}. Bu surecler kurtarma yoludur (oturum acma "
        f"ve kabuk); AXlinux guvenlik geregi hicbir kural uygulamaz, "
        f"cunku engellenmeleri sistemi kilitler. Kural sessizce etkisiz "
        f"kalirdi. Kurali hedef UYGULAMAYA yazin "
        f"(orn. firefox, nginx, redis-server, curl)."
    )


def compile_policy(policy: dict) -> dict:
    """Politikayı doğrular ve iç formata derler."""
    validate_policy(policy)

    labels = policy.get("labels", {})
    rules = policy.get("rules", [])
    mode = policy.get("mode", "enforcing")

    compiled_rules = []
    for i, rule in enumerate(rules):
        subjects = _expand_subject(rule.get("subject", ""), labels)

        priority = _calculate_priority(rule, i)

        # "~" cekirdekte cozulmez; mutlak yola cevir.
        obj = expand_path(rule.get("object", ""))

        name = rule.get("name", f"rule_{i + 1}")

        # Sessiz basarisizligi onle: uc kontrol yan yana.
        #   1) aksiyon gercekten uygulanabiliyor mu
        #   2) yol blok duzenine sigiyor mu
        #   3) hedef korumali bir surec mi (hicbir zaman etkisiz)
        # Ucunun de kabul etmesi durumunda kural gercekten calisir.
        check_action_implemented(rule.get("action", ""), name)
        check_path_representable(obj, name)
        check_protected_subject(subjects, name)

        compiled_rules.append({
            "id": f"rule_{i + 1:03d}",
            "name": rule.get("name", ""),
            "subject": subjects,
            "object": obj,
            "action": rule.get("action", ""),
            "effect": rule.get("effect", ""),
            "port": rule.get("port"),
            "priority": priority,
        })

    compiled_rules.sort(key=lambda r: (r["effect"] != "deny", r["priority"]))

    return {
        "version": 1,
        "mode": mode,
        "labels": labels,
        "rules": compiled_rules,
    }


def _calculate_priority(rule: dict, index: int) -> int:
    """Kural önceliği hesaplar. Düşük sayı = yüksek öncelik."""
    priority = 100

    if rule.get("effect") == "deny":
        priority -= 50

    obj = rule.get("object", "")
    if obj and obj != "/":
        depth = obj.count("/")
        priority -= depth * 10

    priority += index

    return max(0, priority)
