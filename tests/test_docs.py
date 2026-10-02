"""Belgelerdeki HER komut gercekten var mi, ve gercek komutlar
belgelenmis mi?

Once docs/cli-reference.md beş komutu ("axctl trust add",
"axctl policy install/verify/use" ve "axctl version") normal komutlar
gibi listeliyordu; hicbiri calismiyordu. Kullanici komutu yazip
"No such command" aliyordu. Buna ek olarak "label rm" calistigi
halde belgelenmemisti.

Bu test iki yonlu denetler:
  - belgede yazan her komut CLI'de VAR olmali
  - CLI'de olan her komut belgelenmis olmali

Bir tarafta degisiklik yapilip digeri unutulursa test kirilir.
"""
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV = {**os.environ, "PYTHONPATH": str(ROOT / "src" / "python")}


def axctl(*args):
    r = subprocess.run(
        [sys.executable, "-m", "axctl", *args],
        cwd=ROOT, capture_output=True, text=True, env=ENV)
    return r.returncode, r.stdout + r.stderr


# Bunlar komut degil grup/yardimci; belgelenmemeleri normaldir.
GROUPS = {"policy", "label", "learn", "template",
          "options", "help", "commands"}


def real_commands():
    """CLI'de gercekten var olan tum komut yollari.

    Iki bicim var ve IKISI de okunmali:

    1. click grubu olmayan komutlar: --help ciktisinda
         status   Sistem durumunu gosterir.
       gibi "ad  aciklama" satirinda listelenir.

    2. click GRUPLARI (policy, label, learn, template): --help
       ciktisinda alt komutlar AYRI bir blok halinde degil,
       kullanim satirinda tek parca listelenir:
         Usage: axctl policy [OPTIONS] {edit|check|simulate}
       Once yalnizca 1. bicim okunuyordu ve policy'nin uc alt
       komutu "belgelenmemis" sayiliyordu.
    """
    found = set()
    rc, out = axctl("--help")
    assert rc == 0, out
    for name in re.findall(r"^\s{2,4}([a-z][\w-]*)\s{2,}\S", out, re.M):
        if name not in GROUPS:
            found.add(name)

    for group in ("policy", "label", "learn", "template"):
        rc, out = axctl(group, "--help")
        assert rc == 0, out
        # (a) ayri blok halinde listelenen alt komutlar
        for sub in re.findall(r"^\s{2,4}([a-z][\w-]*)\s{2,}\S", out, re.M):
            if sub not in GROUPS:
                found.add(f"{group} {sub}")
        # (b) kullanim satirindaki {edit|check|simulate}
        # Ayirici DUNDAYDIR: virgul degil, dikey cizgi.
        for brace in re.findall(r"\{([a-z|,-]+)\}", out):
            for sub in brace.split("|"):
                sub = sub.strip()
                if sub:
                    found.add(f"{group} {sub}")
    return found


def documented_commands():
    """cli-reference.md'de '### baslik' olarak anlatilan komutlar."""
    text = (ROOT / "docs" / "cli-reference.md").read_text(encoding="utf-8")
    out = set()
    for head in re.findall(r"^### (.+)$", text, re.M):
        head = head.strip()
        # Alt gruplar "### policy edit" gibi gelir
        if head.startswith("Yok"):
            continue
        out.add(head)
    return out


class TestDocsMatchCLI(unittest.TestCase):
    def test_cli_is_usable(self):
        """Kurulum sirasinda dayanma olmasin."""
        rc, out = axctl("--help")
        self.assertEqual(rc, 0, out)
        self.assertIn("init", out)

    def test_every_documented_command_exists(self):
        real = real_commands()
        missing = sorted(documented_commands() - real)
        self.assertEqual(
            missing, [],
            "cli-reference.md var olmayan komutlari anlatiyor: "
            f"{missing}. Ya komut ekle ya da 'Henuz uygulanmamis "
            "komutlar' bolumune tasi.")

    def test_every_command_is_documented(self):
        real = real_commands()
        doc = documented_commands()
        # --version bayragi version komutuyla ayni isi gorur
        undocumented = sorted(real - doc)
        self.assertEqual(
            undocumented, [],
            f"CLI'de olan ama belgelenmemis komutlar: {undocumented}")

    def test_version_command_works(self):
        rc, out = axctl("version")
        self.assertEqual(rc, 0, out)
        self.assertRegex(out.strip(), r"^axctl \d+\.\d+\.\d+$")

    def test_unimplemented_section_is_honest(self):
        """Yok denilen komutlar reference'da olmamali."""
        text = (ROOT / "docs" / "cli-reference.md").read_text(
            encoding="utf-8")
        head = text.split("## Henüz uygulanmamış komutlar")
        self.assertEqual(
            len(head), 2,
            "'Henuz uygulanmamis komutlar' bolumu olmali; aksi halde "
            "okuyucu hangi komutlarin olmadigini anlayamaz")
        real = real_commands()
        body = head[1]
        for line in re.findall(r"^\| `(axctl [^`]+)`", body, re.M):
            name = line.replace("axctl ", "").strip()
            self.assertNotIn(
                name, real,
                f"{name} 'uygulanmamis' bolumunda ama CLI'de VAR")


class TestDocCodeSamplesRun(unittest.TestCase):
    """Belgelerdeki ornek komutlar gercekten calisiyor mu?"""

    def test_documented_flags_exist(self):
        """cli-reference.md'de gecen her --bayrak CLI'da olmali."""
        text = (ROOT / "docs" / "cli-reference.md").read_text(encoding="utf-8")
        rc, help_all = axctl("--help")
        rc, help_logs = axctl("logs", "--help")
        rc, help_policy = axctl("policy", "--help")
        rc, help_init = axctl("init", "--help")
        rc, help_learn = axctl("learn", "start", "--help")
        rc, help_report = axctl("learn", "report", "--help")
        rc, help_sim = axctl("policy", "simulate", "--help")
        all_help = "\n".join([help_all, help_logs, help_policy,
                              help_init, help_learn, help_report,
                              help_sim])
        flags = set(re.findall(r"axctl [a-z]+(?: [a-z]+)? (--[\w-]+)",
                               text))
        for f in sorted(flags):
            self.assertIn(
                f, all_help,
                f"cli-reference.md'de anlatilan {f} bayragi CLI'da yok")


if __name__ == "__main__":
    unittest.main()
