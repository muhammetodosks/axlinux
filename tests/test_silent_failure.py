#!/usr/bin/env python3
"""Politika derleyicisinin sessiz basarisizligi onleyen kontrolleri.

Buradaki testler su hatayi hedefler: policy "1 kural yuklendi"
der, kural map'e yazilir, ama HICBIR sey engellenmez. Kullanici
sorunun var oldugunu fark edemez.

Uc sessiz basarisizlik yolu vardi:
  1) bpf_d_path yolu bozuyordu          (kernel, bkz. axbpf.h)
  2) cok uzun yol sessizce kirpiliyordu (Go, setKeyPath)
  3) korumali surece yazilan kural      (kernel, ax_protected)
     sessizce etkisiz kaliyordu

Ve bir tanesi daha eklendi:
  4) koruma listesi dil kosullarini da iceriyordu; bu durumda
     MAC'in en sik kurallari (python3 /etc/shadow okuyamaz)
     yazilamaz hale geliyordu. Koruma yalnizca kurtarma yolunu
     (kabuk, oturum acma, yetki yukseltme) kapsamalidir.

Ayrica simulator, korumali surece yazilan kurali ETKISIZ
isaretlemezse kullaniciya calisan bir kural gibi gosteriyordu.

Calistirma: python3 -m pytest tests/test_silent_failure.py
"""
import os
import sys
import tempfile
import unittest
import warnings

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "src", "python")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from axctl.compiler import (  # noqa: E402
    PATH_DEPTH,
    PATH_SLOT,
    PROTECTED_PROCESSES,
    check_path_representable,
    compile_policy,
    check_protected_subject,
)
from axctl.exceptions import PolicyError  # noqa: E402


def rule(name="r", subject="firefox", object_="/etc/hostname",
         action="file.read", effect="deny"):
    return {
        "name": name,
        "subject": subject,
        "object": object_,
        "action": action,
        "effect": effect,
    }


class TestUnimplementedActions(unittest.TestCase):
    """HICBIR kancanin uretmedigi aksiyon reddedilmeli.

    Bu, sessiz basarisizligin EN KOTU turudur. Dosya yazan kural
    "kimse /etc/shadow'u silemez" diye yazilir, derleme sorunsuz
    gecer, daemon "1 kural yuklendi" der, dosya SILINIR. Kullanici
    yazma olmadigini sanir.

    Daha once file.delete, file.create ve net.accept VALID_ACTIONS
    icindeydi. Artık ne validator kabul ediyor ne de compiler
    sessizce yaziyor.
    """

    def test_validator_rejects_unimplemented(self):
        from axctl.validator import VALID_ACTIONS
        for action in ("file.delete", "file.create", "net.accept"):
            self.assertNotIn(
                action, VALID_ACTIONS,
                f"{action} VALID_ACTIONS icinde olmamali: hicbir kanca "
                f"uretmiyor, kural sessizce islevsiz kalir")

    def test_implemented_actions_still_valid(self):
        from axctl.validator import VALID_ACTIONS
        for action in ("file.read", "file.write", "file.execute",
                       "net.connect", "net.bind", "process.exec"):
            self.assertIn(
                action, VALID_ACTIONS,
                f"{action} uygulanabilir bir aksiyon; listede olmali")

    def test_compile_raises_on_unimplemented(self):
        from axctl.compiler import UNIMPLEMENTED_ACTIONS
        for action in UNIMPLEMENTED_ACTIONS:
            policy = {
                "version": 1, "mode": "enforcing",
                "rules": [rule(subject="firefox", object_="/etc/hostname",
                               action=action)],
            }
            with self.assertRaises(PolicyError, msg=action) as cm:
                compile_policy(policy)
            # Hata ne yapilacagini soylemeli, sadece "gecersiz" degil.
            self.assertIn(action, str(cm.exception))

    def test_compile_accepts_file_write(self):
        """file.write yeni olarak file_open'da uygulaniyor."""
        policy = {
            "version": 1, "mode": "enforcing",
            "rules": [rule(subject="dd", object_="/tmp/x",
                           action="file.write")],
        }
        compiled = compile_policy(policy)
        self.assertEqual(compiled["rules"][0]["action"], "file.write")


class TestPathRepresentability(unittest.TestCase):
    """Sessiz kirpma yerine acik hata verilmeli."""

    def test_normal_path_passes(self):
        check_path_representable("/etc/hostname", "r")
        check_path_representable("/usr/bin/cat", "r")
        check_path_representable("/", "r")

    def test_too_many_components_fails_loudly(self):
        deep = "/" + "/".join("x" for _ in range(PATH_DEPTH + 1))
        with self.assertRaises(PolicyError) as cm:
            check_path_representable(deep, "derin")
        self.assertIn("bilesen", str(cm.exception))

    def test_too_long_component_fails_loudly(self):
        long = "/" + ("a" * (PATH_SLOT + 5))
        with self.assertRaises(PolicyError) as cm:
            check_path_representable(long, "uzun")
        self.assertIn("uzun", str(cm.exception))

    def test_exact_limits_accepted(self):
        """Tam sınırdaki yol kabul edilmeli (off-by-one yok)."""
        exact_components = "/" + "/".join(
            "c" for _ in range(PATH_DEPTH))
        check_path_representable(exact_components, "tam")

        exact_component = "/" + ("b" * (PATH_SLOT - 1))
        check_path_representable(exact_component, "tam")

    def test_non_path_values_ignored(self):
        """Port degerleri ('p:8080') yol degildir."""
        check_path_representable("", "r")
        check_path_representable("p:8080", "r")


class TestProtectedSubjectRejected(unittest.TestCase):
    """Korumali surece yazilan kural REDDEDILMELI.

    Once bu yalnizca uyariydi: politika yukleniyor, map'e yaziliyor,
    "N kural" deniyor, ama kural HICBIR zaman tetiklenmiyordu.
    Operator enforcement aktifken saniyordu.
    """

    def test_rejects_protected(self):
        # Yalnizca KURTARMA YOLUNDAKI surecler reddedilir.
        for proc in ("bash", "sh", "sudo", "systemd", "sshd", "login"):
            with self.assertRaises(PolicyError) as cm:
                check_protected_subject([proc], "k")
            self.assertIn(proc, str(cm.exception))

    def test_no_warning_for_runtimes(self):
        """Dil kosullari KORUNMAMALI ve uyari uretmemeli.

        Bu testin var olma sebebi sessiz basarisizligi engellemek:
        koruma listesi birSurec dil kosulunu icerirse, "python3
        /etc/shadow okuyamaz" turunden kurallar sessizce etkisiz
        kalir ve operator kuralin yuklendigini sanar. Liste
        genislettiginde burasi KIRILIR; kirilmasi istenen sey
        budur.
        """
        for proc in ("python3", "python", "node", "npm", "perl",
                     "ruby", "tmux", "screen", "code"):
            try:
                check_protected_subject([proc], "k")
            except PolicyError:
                self.fail(f"{proc} KORUMALI OLMAMALI (koruma listesi "
                          f"cok genis; MAC islevsizlesir)")

    def test_runtimes_accept_real_rules(self):
        """En sik MAC kurallari derlenebilmeli."""
        # Ag kurallari port ZORUNLUDUR: eBPF tarafi "p:PORT" anahtari
        # yazar, portsuz kural bos yol anahtari uretir ve hicbir
        # baglantiyla eslesmez. Bu yuzden ag kuralinda port verilir;
        # dosya kurallarinda object verilir.
        for subject, obj, action, port in (
            ("python3", "/etc/shadow", "file.read", 0),
            ("node", "", "net.connect", 443),
            ("perl", "/etc/passwd", "file.read", 0),
        ):
            rule = {
                "id": "rule_001", "name": "r",
                "subject": [subject], "object": obj,
                "action": action, "effect": "deny",
            }
            if port:
                rule["port"] = port
            policy = {
                "version": 1, "mode": "enforcing",
                "labels": {},
                "rules": [rule],
            }
            try:
                compile_policy(policy)
            except PolicyError as e:
                self.fail(f"{subject} icin kural derlenemedi: {e}")

    def test_net_rule_without_port_is_rejected(self):
        """Portsuz ag kurali derlenmemeli.

        Boyle bir kural haritaya yazilir, "N kural yuklendi" bildirimi
        cikar ve operator kuralin calistigini sanar; ama anahtar
        "p:0" olur ve HICBIR baglantiyla eslesmez.
        """
        policy = {
            "version": 1, "mode": "enforcing", "labels": {},
            "rules": [{
                "id": "rule_001", "name": "r",
                "subject": ["node"], "object": "",
                "action": "net.connect", "effect": "deny",
            }],
        }
        with self.assertRaises(PolicyError) as ctx:
            compile_policy(policy)
        self.assertIn("port", str(ctx.exception))

    def test_subject_list_is_accepted(self):
        """Subject listesi en yaygin bicim ve cokmememeli.

        Dogrulayici once subject'i sozlukte ariyordu; liste
        unhashable oldugu icin Python "unhashable type: 'list'" ile
        cokuyordu. Butun dogrulama bu yuzden hicbir zaman
        tamamlanmiyordu.
        """
        policy = {
            "version": 1, "mode": "enforcing",
            "labels": {"web": ["nginx", "apache2"]},
            "rules": [
                {"id": "r1", "name": "a", "subject": ["firefox", "curl"],
                 "object": "/etc/shadow", "action": "file.read",
                 "effect": "deny"},
                {"id": "r2", "name": "b", "subject": "web",
                 "object": "/etc/passwd", "action": "file.read",
                 "effect": "deny"},
            ],
        }
        compile_policy(policy)  # cokmemeli

    def test_rejects_label_expansion(self):
        """Label ile gelen korumali surecler de reddedilir."""
        with self.assertRaises(PolicyError) as cm:
            check_protected_subject(["firefox", "bash"], "k")
        self.assertIn("bash", str(cm.exception))

    def test_silent_for_normal_subjects(self):
        for proc in ("firefox", "nginx", "curl", "chromium"):
            try:
                check_protected_subject([proc], "k")
            except PolicyError:
                self.fail(f"{proc} icin HATA OLMAMALI "
                          f"(koruma listesi cok genis olabilir)")

    def test_protection_list_covers_shell(self):
        """Kabuk ve yetki araclari MUTLAKA korumali olmali."""
        for must in ("bash", "sh", "dash", "zsh", "fish", "sudo", "su",
                     "systemd", "sshd", "login", "agetty", "dbus-daemon",
                     "polkitd", "NetworkManager"):
            self.assertIn(must, PROTECTED_PROCESSES,
                          f"{must} koruma listesinde olmali")


class TestCompileIntegration(unittest.TestCase):
    """compile_policy uyarilari ve hatalari iletmeli."""

    def test_compile_rejects_unrepresentable_path(self):
        long = "/" + ("a" * (PATH_SLOT + 3))
        policy = {
            "version": 1,
            "mode": "enforcing",
            "rules": [rule(object_=long)],
        }
        with self.assertRaises(PolicyError):
            compile_policy(policy)

    def test_compile_rejects_protected_subject(self):
        """Politika derlenmemeli, sadece uyarilmamali.

        Once uyari uretiyordu ve politika YINE DE yukleniyordu:
        kural map'e yaziliyor, "1 kural" deniyor, hicbir sey
        engellenmiyordu.
        """
        policy = {
            "version": 1,
            "mode": "enforcing",
            "rules": [rule(subject="bash", object_="")],
        }
        with self.assertRaises(PolicyError) as cm:
            compile_policy(policy)
        self.assertIn("bash", str(cm.exception))

    def test_compile_normal_policy_no_warning(self):
        policy = {
            "version": 1,
            "mode": "enforcing",
            "rules": [rule(subject="firefox", object_="/etc/shadow")],
        }
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            compile_policy(policy)
        self.assertEqual(len(w), 0,
                         f"normal politika uyari uretmemeli: "
                         f"{[str(x.message) for x in w]}")


class TestSimulatorFlagsIneffectiveRules(unittest.TestCase):
    """Simulator korumali surece yazilan kurali ETKISIZ isaretlemeli.

    Simulator yalnizca derleme mantigini taklit eder, enforcement'i
    degil. Yine de kullaniciya "bu kural calisir" dersken gercekte
    calismiyorsa (korumali surec) en kotu yaniltmayi uretir:
    kullanici simulasyona guvenir, politika yukler, daemon reddeder,
    neden calismadigini anlamaz.
    """

    def _sim(self, rules):
        from axctl import simulator
        with tempfile.NamedTemporaryFile("w", suffix=".yaml",
                                         delete=False) as f:
            yaml.safe_dump(rules, f, allow_unicode=True)
            path = f.name
        try:
            return simulator.simulate_policy(path)
        finally:
            os.unlink(path)

    def test_simulate_explains_protected_rule(self):
        """Simulator cokmeli, hatayi ACIKLAMALI.

        Politika artik derlenmiyor; simulatorun isi de tam olarak
        bunu anlatmak. Once hata yukseliyordu ve operator yalnizca
        izsiz bir PolicyError goruyordu.
        """
        sim = self._sim({
            "version": 1, "mode": "enforcing",
            "labels": {},
            "rules": [rule(subject="bash", object_="")],
        })
        self.assertIn("error", sim,
                      "simulator derlenemeyen politika icin hata "
                      "aciklamasi dondurmeli")
        self.assertIn("bash", sim["error"])

    def test_normal_rule_marked_effective(self):
        sim = self._sim({
            "version": 1, "mode": "enforcing",
            "labels": {},
            "rules": [rule(subject="firefox", object_="/etc/shadow")],
        })
        self.assertEqual(sim["ineffective_rules"], [])
        self.assertTrue(sim["rules"][0]["effective"])

    def test_runtime_rule_marked_effective(self):
        """Dil kosullari etkisiz isaretlenmemeli; MAC calismali."""
        sim = self._sim({
            "version": 1, "mode": "enforcing",
            "labels": {},
            "rules": [rule(subject="python3", object_="/etc/shadow")],
        })
        self.assertEqual(sim["ineffective_rules"], [],
                         "python3 korumali degil; kural etkili olmali")
        self.assertTrue(sim["rules"][0]["effective"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
