"""Yol yönetimi testleri.

AXLINUX_HOME ve AXLINUX_SOCKET gerçekten her katmanda geçerli mi?
Bu modül tek kaynak olduğu için, bir yerde Path.home() hardcode
edilirse sessizce yanlış dizin kullanılır.
"""
import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src" / "python"))

import axctl.config as config  # noqa: E402
import axctl.daemon_client as dclient  # noqa: E402
import axctl.paths as paths  # noqa: E402
import axctl.policy as policy  # noqa: E402


class TestPathsEnvOverride(unittest.TestCase):
    def setUp(self):
        self._old = {k: os.environ.get(k) for k in
                     (paths.AXLINUX_HOME_ENV, paths.AXLINUX_SOCKET_ENV)}
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        for k, v in self._old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_home_env_honoured(self):
        os.environ[paths.AXLINUX_HOME_ENV] = self.tmp
        self.assertEqual(paths.get_axlinux_home(), Path(self.tmp))

    def test_policy_path_follows_home(self):
        os.environ[paths.AXLINUX_HOME_ENV] = self.tmp
        self.assertEqual(paths.get_policy_path(),
                         Path(self.tmp) / "policy.yaml")
        self.assertEqual(paths.get_config_path(),
                         Path(self.tmp) / "config.yaml")
        self.assertEqual(paths.get_backup_dir(),
                         Path(self.tmp) / "backups")

    def test_default_home_when_unset(self):
        os.environ.pop(paths.AXLINUX_HOME_ENV, None)
        self.assertEqual(paths.get_axlinux_home(),
                         Path.home() / ".axlinux")

    def test_socket_env_honoured(self):
        os.environ[paths.AXLINUX_SOCKET_ENV] = "/tmp/ozel.sock"
        self.assertEqual(paths.get_socket_path(), "/tmp/ozel.sock")

    def test_default_socket_when_unset(self):
        os.environ.pop(paths.AXLINUX_SOCKET_ENV, None)
        self.assertEqual(paths.get_socket_path(), paths.DEFAULT_SOCKET)

    def test_ensure_layout_creates_dirs(self):
        os.environ[paths.AXLINUX_HOME_ENV] = self.tmp
        paths.ensure_layout()
        self.assertTrue(Path(self.tmp, "backups").is_dir())
        self.assertTrue(Path(self.tmp, "audit").is_dir())


class TestNoHardcodedHome(unittest.TestCase):
    """Hiçbir modül Path.home() kullanmamalı; yollar paths'ten gelmeli.

    Hardcode edilmiş bir Path.home() AXLINUX_HOME'yu sessizce yok
    sayar ve testler geçici dizinde çalışmaz.
    """

    ALLOWED = {"paths.py"}  # varsayılanı tanımlayan yer

    def test_no_direct_home_usage(self):
        """Politika/config yolları Path.home() ile kurulmamalı.

        expanduser("~") kullanımı bu testte serbesttir: compiler.py
        kullanıcı yolunu (~/.ssh gibi) mutlaklaştırmak için
        kullanır ve bu zorunludur. Buradaki kural yalnızca AXlinux
        veri dizinini kendi gizleyerek atlamayı engeller.
        """
        pkg = ROOT / "src" / "python" / "axctl"
        offenders = []
        for f in sorted(pkg.glob("*.py")):
            if f.name in self.ALLOWED or f.name == "__init__.py":
                continue
            for i, line in enumerate(
                    f.read_text(encoding="utf-8").splitlines(), 1):
                if "Path.home()" in line:
                    offenders.append(f"{f.name}:{i}: {line.strip()}")
        self.assertEqual(offenders, [],
                         "Path.home() kullanımı paths modülüne taşınmalı")

    def test_policy_path_uses_paths_module(self):
        """policy.py varsayılan yolu kendisi kurmamalı."""
        src = (ROOT / "src" / "python" / "axctl" / "policy.py").read_text()
        self.assertIn("get_policy_path", src)

    def test_no_hardcoded_socket(self):
        pkg = ROOT / "src" / "python" / "axctl"
        offenders = []
        for f in sorted(pkg.glob("*.py")):
            if f.name in self.ALLOWED:
                continue
            for i, line in enumerate(
                    f.read_text(encoding="utf-8").splitlines(), 1):
                if "/run/axlinux" in line:
                    offenders.append(f"{f.name}:{i}: {line.strip()}")
        self.assertEqual(offenders, [],
                         "soket yolu paths.get_socket_path() ile alinmali")


class TestPolicyFileRoundTrip(unittest.TestCase):
    """Politika dosya yonetimi AXLINUX_HOME'a uymali."""

    def setUp(self):
        self._old = os.environ.get(paths.AXLINUX_HOME_ENV)
        self.tmp = tempfile.mkdtemp()
        os.environ[paths.AXLINUX_HOME_ENV] = self.tmp
        paths.ensure_layout()

    def tearDown(self):
        if self._old is None:
            os.environ.pop(paths.AXLINUX_HOME_ENV, None)
        else:
            os.environ[paths.AXLINUX_HOME_ENV] = self._old

    def test_save_load_roundtrip(self):
        p = paths.get_policy_path()
        doc = {"version": 1, "mode": "permissive", "rules": [
            {"name": "n", "subject": "a", "object": "/b",
             "action": "file.read", "effect": "deny"}]}
        policy.save_policy(p, doc)
        self.assertTrue(p.exists())
        self.assertEqual(policy.load_policy(), doc)

    def test_backup_created_in_backup_dir(self):
        p = paths.get_policy_path()
        policy.save_policy(p, {"version": 1, "rules": []})
        b = policy.backup_policy()
        self.assertTrue(b.exists())
        self.assertEqual(b.parent, paths.get_backup_dir())
        self.assertIn("policy_", b.name)

    def test_backup_limit_enforced(self):
        cfg_path = paths.get_config_path()
        cfg_path.write_text("backup_count: 3\n")
        p = paths.get_policy_path()
        for i in range(6):
            policy.save_policy(p, {"version": 1, "rules": [
                {"name": f"r{i}", "subject": "a"}]})
            policy.backup_policy()
        self.assertLessEqual(len(policy.list_backups()), 3)

    def test_list_backups_newest_first(self):
        p = paths.get_policy_path()
        for i in range(3):
            policy.save_policy(p, {"version": 1, "rules": []})
            policy.backup_policy()
        b = policy.list_backups()
        self.assertEqual(len(b), 3)
        self.assertEqual(b, sorted(b, reverse=True))

    def test_stats_counts(self):
        policy.save_policy(paths.get_policy_path(), {
            "version": 1, "mode": "enforcing",
            "labels": {"a": ["x"]},
            "rules": [
                {"name": "n", "subject": "a", "object": "/b",
                 "action": "file.read", "effect": "deny"},
            ]})
        s = policy.get_policy_stats()
        self.assertTrue(s["exists"])
        self.assertEqual(s["rules"], 1)
        self.assertEqual(s["labels"], 1)
        self.assertEqual(s["mode"], "enforcing")

    def test_stats_missing_file(self):
        s = policy.get_policy_stats(Path(self.tmp) / "yok.yaml")
        self.assertFalse(s["exists"])
        self.assertEqual(s["rules"], 0)


class TestConfigValidation(unittest.TestCase):
    def setUp(self):
        self._old = os.environ.get(paths.AXLINUX_HOME_ENV)
        self.tmp = tempfile.mkdtemp()
        os.environ[paths.AXLINUX_HOME_ENV] = self.tmp

    def tearDown(self):
        if self._old is None:
            os.environ.pop(paths.AXLINUX_HOME_ENV, None)
        else:
            os.environ[paths.AXLINUX_HOME_ENV] = self._old

    def test_defaults_written_when_absent(self):
        cfg = config.load_config()
        self.assertEqual(cfg["mode"], "enforcing")
        self.assertTrue(config.get_config_path().exists())

    def test_invalid_mode_falls_back(self):
        config.get_config_path().write_text("mode: kotu\n")
        self.assertEqual(config.load_config()["mode"], "enforcing")

    def test_user_values_preserved(self):
        config.get_config_path().write_text(
            "mode: permissive\nbackup_count: 42\n")
        cfg = config.load_config()
        self.assertEqual(cfg["mode"], "permissive")
        self.assertEqual(cfg["backup_count"], 42)

    def test_broken_yaml_raises(self):
        config.get_config_path().write_text("a: [unclosed\n")
        with self.assertRaises(config.ConfigError):
            config.load_config()


class TestDaemonClientErrors(unittest.TestCase):
    def setUp(self):
        self._old = os.environ.get(paths.AXLINUX_SOCKET_ENV)
        self.tmp = tempfile.mkdtemp()
        os.environ[paths.AXLINUX_SOCKET_ENV] = \
            os.path.join(self.tmp, "yok.sock")

    def tearDown(self):
        if self._old is None:
            os.environ.pop(paths.AXLINUX_SOCKET_ENV, None)
        else:
            os.environ[paths.AXLINUX_SOCKET_ENV] = self._old

    def test_missing_socket_raises_daemon_error(self):
        from axctl.exceptions import DaemonError
        with self.assertRaises(DaemonError) as e:
            dclient.get_status()
        self.assertIn("axdaemon", str(e.exception))

    def test_permission_error_is_not_reported_as_missing(self):
        """0600 socket: root olmayan kullanici icin "yok" denmemeli.

        Eski kod once Path.exists() ile kontrol ediyordu. Izni
        olmayan bir kullanici icin bu False doner ve kullaniciya
        "axdaemon calismiyor" denirdi; oysa daemon calisiyor,
        yalnizca yetki yok. Yaniltici tani kullaniciyi servis
        yeniden baslatmaya yonlendirir.
        """
        import socket as _socket
        from axctl.exceptions import DaemonError

        real_connect = _socket.socket.connect

        def fake_connect(self, address):
            raise PermissionError(13, "Permission denied")

        _socket.socket.connect = fake_connect
        try:
            with self.assertRaises(DaemonError) as e:
                dclient.get_status()
        finally:
            _socket.socket.connect = real_connect

        msg = str(e.exception)
        # Izni oldugunu SOYLEMELI, "calismiyor" DEMEMELI.
        #
        # Onceki kontrol tam kelime "izin" ariyordu. Dogru Turkce
        # mesaj "Socket izni yok" diyor; Turkce eklemeyle birlikte
        # "izin" -> "izni" yazimi degisiyor ve "izin" kelimesi
        # metinde bulunmuyor. Yani test dogru davranisi reddediyor,
        # yalnizca mesajin kurgusuyla oynuyor.
        #
        # Niyet "izin bilgisi gecsin" oldugu icin kabul edilen
        # yazimlar listelenir. Not: Turkce eklemeyle birlikte yazim
        # degisiyor ("izin" -> "izni") ve "izin" kelimesi "izni"
        # icinde gecmiyor; onceden tek kelime aramak bu yuzden dogru
        # mesaji reddediyordu.
        low = msg.lower()
        self.assertTrue(
            any(w in low for w in ("izin", "izni", "yetki", "permission")),
            f"mesaj izin/yetki bilgisi icermiyor: {msg}")
        self.assertNotIn("çalışmıyor", low)
        # Kullaniciya ne yapacagini soylemeli.
        self.assertIn("sudo", msg)

    def test_is_available_false(self):
        self.assertFalse(dclient.is_available())


if __name__ == "__main__":
    unittest.main(verbosity=2)
