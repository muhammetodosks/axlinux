"""AXlinux Python birim testleri.

Politika derleme, dogrulama ve oncelik mantigini kapsar.
Calistirma:
    python3 -m pytest tests/test_axctl.py -q
    python3 tests/test_axctl.py
"""
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src" / "python"))

import yaml  # noqa: E402

from axctl.compiler import compile_policy, expand_path  # noqa: E402
from axctl.exceptions import PolicyError  # noqa: E402
from axctl.validator import validate_policy  # noqa: E402

MINIMAL = {
    "version": 1,
    "mode": "enforcing",
    "rules": [
        {"name": "r1", "subject": "firefox",
         "object": "/etc/shadow", "action": "file.read", "effect": "deny"},
    ],
}


def P(rules, labels=None, mode="enforcing", version=1):
    return {"version": version, "mode": mode,
            "labels": labels or {}, "rules": rules}


class TestValidator(unittest.TestCase):
    def test_minimal_gecerli(self):
        self.assertEqual(validate_policy(MINIMAL), [])

    def test_bos_kurallar_gecerli(self):
        self.assertEqual(validate_policy(P([])), [])

    def test_bozuk_versiyon(self):
        with self.assertRaises(PolicyError) as e:
            validate_policy(P([], version=2))
        self.assertIn("version", str(e.exception))

    def test_bozuk_mod(self):
        with self.assertRaises(PolicyError):
            validate_policy(P([], mode="kotu"))

    def test_bozuk_aksiyon(self):
        bad = P([{"name": "x", "subject": "a",
                  "object": "/b", "action": "file.yaz", "effect": "deny"}])
        with self.assertRaises(PolicyError):
            validate_policy(bad)

    def test_bozuk_etki(self):
        bad = P([{"name": "x", "subject": "a",
                  "object": "/b", "action": "file.read", "effect": "maybe"}])
        with self.assertRaises(PolicyError):
            validate_policy(bad)

    def test_file_aksiyonu_object_ister(self):
        bad = P([{"name": "x", "subject": "a",
                  "action": "file.read", "effect": "deny"}])
        with self.assertRaises(PolicyError) as e:
            validate_policy(bad)
        self.assertIn("object", str(e.exception))

    def test_net_aksiyonu_object_ister_gerekmez(self):
        ok = P([{"name": "x", "subject": "python",
                 "action": "net.connect", "effect": "deny"}])
        self.assertEqual(validate_policy(ok), [])

    def test_cakisan_kurallar_reddedilir(self):
        bad = P([
            {"name": "a", "subject": "nginx", "object": "/etc/shadow",
             "action": "file.read", "effect": "deny"},
            {"name": "b", "subject": "nginx", "object": "/etc/shadow",
             "action": "file.read", "effect": "allow"},
        ])
        with self.assertRaises(PolicyError) as e:
            validate_policy(bad)
        self.assertIn("Çakışma", str(e.exception))

    def test_yinelenen_kural_reddedilir(self):
        rule = {"name": "x", "subject": "a", "object": "/b",
                "action": "file.read", "effect": "deny"}
        bad = P([dict(rule), dict(rule, name="y")])
        with self.assertRaises(PolicyError) as e:
            validate_policy(bad)
        self.assertIn("Yinelenen", str(e.exception))

    def test_name_required(self):
        bad = P([{"subject": "a", "object": "/b",
                  "action": "file.read", "effect": "deny"}])
        with self.assertRaises(PolicyError):
            validate_policy(bad)


class TestCompiler(unittest.TestCase):
    def test_derleme_temel(self):
        c = compile_policy(MINIMAL)
        self.assertEqual(c["version"], 1)
        self.assertEqual(c["mode"], "enforcing")
        self.assertEqual(len(c["rules"]), 1)
        self.assertEqual(c["rules"][0]["id"], "rule_001")

    def test_etiket_genisletilir(self):
        p = P([{"name": "n", "subject": "web", "object": "/var/www",
                "action": "file.read", "effect": "allow"}],
              labels={"web": ["nginx", "apache2"]})
        c = compile_policy(p)
        self.assertEqual(sorted(c["rules"][0]["subject"]),
                         ["apache2", "nginx"])

    def test_yildiz_etiket_kendisi(self):
        p = P([{"name": "n", "subject": "*", "object": "/etc/shadow",
                "action": "file.read", "effect": "deny"}])
        c = compile_policy(p)
        self.assertEqual(c["rules"][0]["subject"], ["*"])

    def test_deny_once_siralenir(self):
        p = P([
            {"name": "allow", "subject": "a", "object": "/x",
             "action": "file.read", "effect": "allow"},
            {"name": "deny", "subject": "a", "object": "/y",
             "action": "file.read", "effect": "deny"},
        ])
        c = compile_policy(p)
        self.assertEqual(c["rules"][0]["effect"], "deny",
                         "deny kurallari once gelmeli")

    def test_kural_idleri_sirali(self):
        p = P([{"name": f"r{i}", "subject": "a", "object": f"/p{i}",
                "action": "file.read", "effect": "deny"} for i in range(5)])
        c = compile_policy(p)
        self.assertEqual([r["id"] for r in c["rules"]],
                         ["rule_001", "rule_002", "rule_003",
                          "rule_004", "rule_005"])

    def test_etiket_sayisi_korunur(self):
        p = P([], labels={"a": ["x"], "b": ["y", "z"]})
        c = compile_policy(p)
        self.assertEqual(len(c["labels"]), 2)

    def test_denetilebilir_uretim(self):
        """Ayni girdi ayni ciktiyi vermeli (denetlenebilir derleme)."""
        p = P([
            {"name": "a", "subject": "web", "object": "/var/www",
             "action": "file.read", "effect": "allow"},
            {"name": "b", "subject": "web", "object": "/etc/shadow",
             "action": "file.read", "effect": "deny"},
        ], labels={"web": ["nginx"]})
        self.assertEqual(compile_policy(p), compile_policy(p))


class TestPathExpansion(unittest.TestCase):
    """'~' cekirdekte cozulmez; mutlak yola cevrilmezse kural hicbir
    zaman eslesmez ve kullanici korumayi etkin sanir."""

    def test_tilde_alone(self):
        self.assertEqual(expand_path("~"), os.path.expanduser("~"))

    def test_tilde_slash(self):
        self.assertEqual(expand_path("~/.ssh"),
                         os.path.expanduser("~/.ssh"))

    def test_absolute_unchanged(self):
        self.assertEqual(expand_path("/etc/shadow"), "/etc/shadow")

    def test_empty_unchanged(self):
        self.assertEqual(expand_path(""), "")

    def test_relative_unchanged(self):
        self.assertEqual(expand_path("etc/passwd"), "etc/passwd")

    def test_not_a_prefix_match(self):
        """'~foo' bir ev dizini degil, oldugu gibi kalir."""
        self.assertEqual(expand_path("~foo/bar"), "~foo/bar")

    def test_compiled_policy_has_absolute_paths(self):
        p = P([{"name": "n", "subject": "firefox",
               "object": "~/.ssh", "action": "file.read",
               "effect": "deny"}])
        c = compile_policy(p)
        self.assertNotIn("~", c["rules"][0]["object"],
                         "derlenen kurallarda '~' kalmamali")
        self.assertTrue(c["rules"][0]["object"].startswith("/"))


class TestShippedPolicies(unittest.TestCase):
    """Depodaki ornek politikalar dogrulanmali."""

    def test_ornekler_gecerli(self):
        for f in sorted((ROOT / "examples").glob("*.yaml")):
            with self.subTest(politika=f.name):
                policy = yaml.safe_load(f.read_text())
                validate_policy(policy)
                compile_policy(policy)

    def test_orneklerde_yol_mutlak(self):
        """Dagitimdaki ornekler mutlak yol uretmeli; '~' birakmak
        kullaniciyi yanlis yonlendirir."""
        for f in sorted((ROOT / "examples").glob("*.yaml")):
            with self.subTest(politika=f.name):
                policy = yaml.safe_load(f.read_text())
                for r in compile_policy(policy)["rules"]:
                    obj = r["object"]
                    if obj:
                        self.assertFalse(
                            obj.startswith("~"),
                            f"{f.name}: {r['name']} -> {obj}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
