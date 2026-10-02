"""Surumun TEK kaynaktan gelmesini zorunlu kilar.

Surum uc yerde tutuluyor: axctl/__init__.py, pyproject.toml ve
Go main.go. Tek biri guncellenip digerleri unutulursa:
  - CLI 1.0.0 derken daemon 0.1.0 oldugunu bildirir
  - paket metaverisi koda uymaz
  - hata raporlarinda surum yanlis cozulur

Bunu sessizce kabul etmek yerine test kirilir.
"""
import re, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
import unittest


def read(p): return (R / p).read_text(encoding="utf-8")


class TestVersionConsistency(unittest.TestCase):
    """Surum her yerde ayni olmali."""

    def _versions(self):
        import re
        return {
            "src/python/axctl/__init__.py":
                re.search(r'__version__ = "([^"]+)"',
                          read("src/python/axctl/__init__.py")).group(1),
            "src/python/pyproject.toml":
                re.search(r'^version = "([^"]+)"',
                          read("src/python/pyproject.toml"), re.M).group(1),
            "src/go/axdaemon/main.go":
                re.search(r'const Version = "([^"]+)"',
                          read("src/go/axdaemon/main.go")).group(1),
        }

    def test_version_identical_everywhere(self):
        v = self._versions()
        self.assertEqual(len(set(v.values())), 1,
                         f"surumler ayrilmis: {v}")

    def test_version_is_semantic(self):
        import re
        ver = next(iter(self._versions().values()))
        self.assertRegex(ver, r"^\d+\.\d+\.\d+$",
                         f"semantik surum olmali (MAJOR.MINOR.PATCH): {ver}")

    def test_cli_reports_the_declared_version(self):
        import subprocess, sys
        declared = next(iter(self._versions().values()))
        out = subprocess.run(
            [sys.executable, "-c",
             "import sys; sys.path.insert(0,'src/python'); "
             "import axctl; print(axctl.__version__)"],
            cwd=R, capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), declared)

    def test_distribution_doc_matches(self):
        import re
        declared = next(iter(self._versions().values()))
        doc = read("DAGITIM.md")
        # Markdown kalin isaretleri ("**1.0.0**") sart degil
        m = re.search(r"\|\s*Sürüm\s*\|\s*\**([\d.]+)", doc)
        self.assertIsNotNone(m, "DAGITIM.md surum satiri bulunamadi")
        self.assertEqual(m.group(1), declared,
                         "DAGITIM.md eski surumu gosteriyor")

    def test_no_experimental_framing(self):
        """'Deneysel' etiketi kurulmus bir surum icin yanilticidir."""
        doc = read("DAGITIM.md").lower()
        for word in ("deneysel", "experimental"):
            self.assertNotIn(word, doc,
                             f"DAGITIM.md '{word}' diyor; 1.0.0 kurulmus "
                             f"bir surum icin yaniltici")


if __name__ == "__main__":
    unittest.main()
