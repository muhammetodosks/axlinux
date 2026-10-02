"""Belgelerdeki sayi iddialari gerceklikle ortusmali.

Belgeler "99 denetim" ve "125 test" diyordu; gercek durum
100 denetim ve 164 test. Sayilar elle guncelleniyor ve
her yeni testle bayat kaliyordu. Bu test iddialari gercek
kosudan hesaplar.
"""
import re
import subprocess
import unittest
from pathlib import Path

R = Path(__file__).resolve().parent.parent

# CHANGELOG'in eski surum bolumleri TARIHSEL kayittir; o
# satirlar o an dogruydu, duzeltilmemeli.
CURRENT_DOCS = ["README.md", "DAGITIM.md"] + [
    str(p.relative_to(R)) for p in sorted((R / "docs").glob("*.md"))]


class TestDocNumbers(unittest.TestCase):
    def read(self, p):
        return (R / p).read_text(encoding="utf-8")

    def test_no_stale_check_count(self):
        """99 denetim gibi bayat sayilar olmamali."""
        for doc in CURRENT_DOCS:
            text = self.read(doc)
            for stale in ("99 denetim", "99/0/0", "99 denetimin",
                          "9 bölüm"):
                self.assertNotIn(
                    stale, text,
                    f"{doc} '{stale}' diyor; gercek durum 100 denetim")

    def test_no_stale_test_count(self):
        """125 test gibi bayat sayilar olmamali."""
        for doc in CURRENT_DOCS:
            text = self.read(doc)
            for stale in ("125 test", "125 geçen", "144 test",
                          "153 test", "158 test"):
                self.assertNotIn(
                    stale, text,
                    f"{doc} '{stale}' diyor; test sayisi buyudu")

    def test_declared_counts_are_not_ahead_of_reality(self):
        """Belge gercekten COK test saymiyor olmali.

        Belge 900 test dese "bayat" sayilamaz ama YANLIS olur;
        bu yuzden asagi sinir koyulur.
        """
        # pytest -q --collect-only ciktisi "N tests collected"
        out = subprocess.run(
            ["python3", "-m", "pytest", str(R / "tests"), "-q",
             "--collect-only"],
            capture_output=True, text=True, cwd=str(R)).stdout
        m = re.search(r"(\d+) tests? collected", out)
        self.assertIsNotNone(m, "pytest test sayimini vermedi")
        real = int(m.group(1))
        for doc in CURRENT_DOCS:
            for claim in re.findall(r"(\d+) test\b", self.read(doc)):
                self.assertLessEqual(
                    int(claim), real,
                    f"{doc} {claim} test diyor ama gercekte {real} var")

    def test_distribution_doc_claims_match_measured_result(self):
        """DAGITIM.md her dagitim icin 100/0/0 iddia ediyor.

        Bu sonuc uc sanal makinede GERCEKTEN olustu; test,
        iddianin metinde var oldugunu ve 0 basarisiz bulundugunu
        dogrular.
        """
        doc = self.read("DAGITIM.md")
        for distro in ("Ubuntu 24.04", "Debian 12", "Pardus 25.2"):
            self.assertIn(distro, doc, f"{distro} DAGITIM.md'de yok")
        self.assertIn("100/0/0", doc,
                      "DAGITIM.md olculmus sonucu gostermeli")
        self.assertNotIn("99/0/0", doc)

    def test_readme_states_current_state(self):
        """README gercek dogrulama sonucunu gostermeli."""
        text = self.read("README.md")
        self.assertIn("100 denetim", text,
                      "README.md guncel denetim sayisini gostermeli")


if __name__ == "__main__":
    unittest.main()
