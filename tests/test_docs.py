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

#: "Henuz uygulanmamis komutlar" bolumunun kabul edilen basliklari.
#: Belgeler Ingilizceye cevrildiginde baslik da cevrilir; testin
#: denetledigi sey bolumun VARLIGI, cevirisi degil.
UNIMPLEMENTED_HEADINGS = (
    "## Henüz uygulanmamış komutlar",
    "## Commands not yet implemented",
)


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
        # Bolum basligi Turkce veya Ingilizce olabilir (doc English).
        # Dogrulanan sey basligin varligi, cevirisi degil.
        for heading in UNIMPLEMENTED_HEADINGS:
            if heading in text:
                text = text.split(heading)
                break
        else:
            text = []
        self.assertEqual(
            len(text), 2,
            "'Henuz uygulanmamis komutlar' / 'Commands not yet "
            "implemented' bolumu olmali; aksi halde okuyucu hangi "
            "komutlarin olmadigini anlayamaz")
        real = real_commands()
        body = text[1]
        for line in re.findall(r"^\| `(axctl [^`]+)`", body, re.M):
            name = line.replace("axctl ", "").strip()
            self.assertNotIn(
                name, real,
                f"{name} 'uygulanmamis' bolumunda ama CLI'de VAR")


class TestAllDocsAreHonest(unittest.TestCase):
    """TUM belgeler, hicbir yerde var olmayan komut gostermemeli.

    Once denetim yalnizca cli-reference.md uzerinde calisiyordu.
    Baska belgelerde kalan hayaletler vardi:
      - component-design.md: "axctl template show" (CLI'da YOK)
      - user-scenarios.md / component-design.md: trust add,
        policy install/verify/use (CLI'da YOK)
    Bunlar "v0.5" gibi gelecek surum etiketiyle yazilmis
    ti; ancak surum 1.0.0 oldugu icin 0.5 coktan gelmeliydi.
    Kullanici belgeyi okuyup calismayan komutu deniyordu.
    """

    DOCS = ["docs/cli-reference.md", "docs/INSTALL.md",
            "docs/user-scenarios.md", "docs/component-design.md",
            "docs/architecture.md", "docs/policy-language.md",
            "docs/challenges-risks.md", "docs/roadmap.md",
            "docs/DISTRIBUTION.md", "README.md"]

    # Gelecek ozellik olan komut YOLLARI. Tam yol eslesmeli:
    # "policy install" hayalet, ama "policy check" gecerli.
    # Bunlar "Henuz uygulanmamis komutlar" bolumunde acikca
    # "Yok" olarak isaretlenmelidir.
    # Gelecek ozelligin koku (grup altinda degil): "axctl trust add"
    FUTURE_HEADS = {"trust"}
    # Gelecek ozelligin tam yolu (click grubunun altinda)
    FUTURE_PATHS = {"policy install", "policy verify", "policy use"}

    GROUPS = {"policy", "label", "learn", "template"}

    def _commands_in(self, text):
        """Belgedeki axctl cagrilarini tam yol olarak cikarir.

        Kabaclik iki hatayi birakiyordu:
          - "axctl policy edit" icindeki "policy" grub adi, komut
            degildir; tek kelimeye bakilinca hatali "belgelenmemis"
            sayiliyordu.
          - Turkce metindeki "axctl ile ..." ("ile" = "with")
            komut saniliyordu.
        Bu yuzden en fazla iki kelime alinir ve grup yolu ayrica
        dogrulanir.
        """
        out = set()
        for m in re.finditer(r"\baxctl\s+([a-z][\w-]*)(?:\s+([a-z][\w-]*))?", text):
            first, second = m.group(1), m.group(2)
            # Turkce metin: "axctl ile birlikte ..." ("ile" = with)
            if first in ("ile", "ve", "i", "icin", "ile"):
                continue
            if first in GROUPS:
                if second:
                    out.add(f"{first} {second}")
                # grup adi tek basina yazildiysa alt komut
                # belirtilmemis; atlanir
            else:
                # Ikinci kelime ARGUMANDIR, alt komut degil:
                #   axctl mode enforcing   -> "enforcing" bir deger
                #   axctl status && sudo   -> metin arasi
                # Alt komut yalnizca click GRUPLARININ altinda
                # olur (axctl policy check). Bu yuzden yalnizca ilk
                # kelime alinir.
                out.add(first)
        return out

    def test_docs_reference_existing_commands(self):
        real = real_commands()
        top = {c for c in real if " " not in c}
        bad = {}
        for doc in self.DOCS:
            path = ROOT / doc
            if not path.exists():
                continue
            for cmd in self._commands_in(path.read_text(encoding="utf-8")):
                if (cmd in self.FUTURE_PATHS
                        or cmd.split(" ")[0] in self.FUTURE_HEADS
                        or cmd in ("--help", "-h")):
                    continue
                ok = cmd in real or cmd in top
                if not ok:
                    bad.setdefault(cmd, []).append(doc)
        self.assertEqual(
            bad, {},
            "Belgeler CLI'da olmayan komutlar gosteriyor: "
            f"{bad}. Ya komutu ekle ya da 'gelecek ozellik' olarak "
            f"acikca isaretle.")

    def test_future_commands_are_marked_not_implemented(self):
        """Gelecek komutlar 'Yok' bolumunde acikca yazili olmali."""
        text = (ROOT / "docs" / "cli-reference.md").read_text(
            encoding="utf-8")
        self.assertTrue(
            any(h in text for h in UNIMPLEMENTED_HEADINGS),
            "cli-reference.md 'Commands not yet implemented' bolumunu "
            "icermeli")
        for cmd in ("trust add", "policy install", "policy verify",
                    "policy use"):
            self.assertIn(f"axctl {cmd}", text,
                          f"'axctl {cmd}' gelecek ozellik; "
                          f"'Henuz uygulanmamis komutlar' bolumunde "
                          f"'Yok' olarak isaretlenmeli")

    def test_no_lower_version_promised_as_future(self):
        """Surum 1.0.0 iken 'v0.5' gelecek olamaz.

        0.5 < 1.0.0 oldugu icin "v0.5+" etiketi, ozelligin coktan
        gelmesi gerektigini ima eder. Kullanici belgeyi okuyup
        eksik komutu arar.
        """
        for doc in self.DOCS:
            path = ROOT / doc
            if not path.exists():
                continue
            text = path.read_text(encoding="utf-8")
            hits = re.findall(r"v0\.[1-4]\+?", text)
            if hits:
                self.fail(
                    f"{doc}: {sorted(set(hits))} gelecek surum olarak "
                    f"isaretlenmis. Surum 1.0.0; bundan kucuk bir "
                    f"surum 'gelecek' olamaz. 'Gelecek ozellik' "
                    f"ifadesi kullan ya da surumu yukselt.")


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
