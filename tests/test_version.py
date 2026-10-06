"""Surumun TEK kaynaktan gelmesini zorunlu kilar.

Tek dogruluk kaynagi artik packaging/fedora/axlinux.spec. Once uc
dosyada birden (axctl/__init__.py, pyproject.toml, Go main.go)
ayri ayri tutuluyordu ve biri unutuldugu anda sessizce ayriisyordu:
axlog sabit "1.0.0" yaziyordu ve RPM 1.1.0 derlenirken log servisi
kendini 1.0.0 olarak bildiriyordu.

Simdi:
  - surum spec'te yazar (TEK kaynak)
  - Go ikililerine -ldflags ile enjekte edilir
  - Python tarafi spec ile ayni olmak ZORUNDADIR (bu test)

Bunu sessizce kabul etmek yerine test kirilir.
"""
import re, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
import unittest


def read(p): return (R / p).read_text(encoding="utf-8")


class TestVersionConsistency(unittest.TestCase):
    """Surum her yerde ayni olmali."""

    def _declared(self):
        """TEK dogruluk kaynagi: RPM spec dosyasi."""
        m = re.search(r"(?m)^Version:\s*(\S+)\s*$",
                      read("packaging/fedora/axlinux.spec"))
        self.assertIsNotNone(m, "spec dosyasinda Version: satiri yok")
        return m.group(1)

    def _versions(self):
        return {
            "packaging/fedora/axlinux.spec (kaynak)": self._declared(),
            "src/python/axctl/__init__.py":
                re.search(r'__version__ = "([^"]+)"',
                          read("src/python/axctl/__init__.py")).group(1),
            "src/python/pyproject.toml":
                re.search(r'^version = "([^"]+)"',
                          read("src/python/pyproject.toml"), re.M).group(1),
        }

    def test_version_identical_everywhere(self):
        v = self._versions()
        self.assertEqual(len(set(v.values())), 1,
                         f"surumler ayrilmis: {v}")

    def test_go_binaries_take_version_from_build(self):
        """Go ikilileri surumu YAZMAMALI, derleme zamaninda almalı.

        main.go icinde sabit surum tutulursa ayrilma tekrar olur:
        RPM 1.1.0 derlerken ikili 1.0.0 bildirir. Bu yuzden Go
        tarafinda yalnizca "dev" varsayilani olmali ve sifiri
        bir -ldflags enjeksiyonu icin var olmali.
        """
        for path in ("src/go/axdaemon/main.go", "src/go/axlog/main.go"):
            src = read(path)
            self.assertIn('var Version = "dev"', src,
                          f"{path} derleme zamaninda enjekte edilebilir "
                          f"surum degiskeni tasimali")
            # Kayan surum: main.go icinde gercek surum olmamali.
            m = re.search(r'var Version = "(\d+\.\d+\.\d+)"', src)
            self.assertIsNone(
                m,
                f"{path} icine surum sabiti yazildi ({m.group(1) if m else ''}); "
                f"surum spec'ten gelmeli")

    def test_makefile_injects_version(self):
        """Makefile her iki Go ikilisine de -ldflags vermeli.

        Yalnizca birine verilirse o ikili "dev" olarak derlenir ve
        operatora yanlis surum bildirilir.
        """
        mk = read("Makefile")
        self.assertIn("-ldflags", mk, "Makefile -ldflags kullanmiyor")
        self.assertEqual(
            mk.count('-ldflags "-X main.Version=$(VERSION)"'), 2,
            "Makefile -ldflags'i her iki Go hedefine de vermeli "
            "(axdaemon + axlog)")
        # Tek kaynak: spec'ten okunmali.
        self.assertRegex(
            mk, r"VERSION\s*:=\s*\$\(shell sed -n 's/\^Version:",
            "Makefile surumu axdaemon/main.go'dan kazimamali, "
            "spec'ten okumali")

    def test_version_is_semantic(self):
        ver = self._declared()
        self.assertRegex(ver, r"^\d+\.\d+\.\d+$",
                         f"semantik surum olmali (MAJOR.MINOR.PATCH): {ver}")

    def test_cli_reports_the_declared_version(self):
        import subprocess, sys
        declared = self._declared()
        out = subprocess.run(
            [sys.executable, "-c",
             "import sys; sys.path.insert(0,'src/python'); "
             "import axctl; print(axctl.__version__)"],
            cwd=R, capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), declared)

    def test_distribution_doc_matches(self):
        declared = self._declared()
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

    def test_changelog_has_current_version(self):
        """CHANGELOG guncel surumu icermeli.

        Surum 1.0.0 oldu ama CHANGELOG.md en ustte 0.1.0 ile
        basliyordu; kullanici ne degistigini okuyamiyordu.
        Degisiklik gunlugu teslimin parcasidir.
        """
        declared = self._declared()
        log = read("CHANGELOG.md")
        # En ust surum basligi guncel olmali (yeni surum en ustte)
        m = re.search(r"(?m)^##\s+v?([\d.]+)", log)
        self.assertIsNotNone(m, "CHANGELOG.md surum basligi yok")
        self.assertEqual(
            m.group(1), declared,
            "CHANGELOG.md'nin en ust surumu guncel degil; degisiklik "
            "gunlugu guncel surumu icermeli")

    def test_changelog_newest_version_is_not_below_declared(self):
        """Eski surumun altinda kalmis "acik kalan isler" iddialari
        yanilticidir."""
        declared = self._declared()
        log = read("CHANGELOG.md")
        for m in re.finditer(r"(?m)^##\s+v?([\d.]+)", log):
            self.assertLessEqual(
                parse_version(m.group(1)), parse_version(declared),
                f"CHANGELOG.md'de {declared} surumunden YUKSEK "
                f"surumlu bolum var: {m.group(1)}")

    def test_no_experimental_framing(self):
        """'Deneysel' etiketi kurulmus bir surum icin yanilticidir."""
        doc = read("DAGITIM.md").lower()
        for word in ("deneysel", "experimental"):
            self.assertNotIn(word, doc,
                             f"DAGITIM.md '{word}' diyor; 1.0.0 kurulmus "
                             f"bir surum icin yaniltici")

    def test_changelog_has_current_version(self):
        """CHANGELOG guncel surumu icermeli.

        Surum 1.0.0 oldu ama CHANGELOG.md en ustte 0.1.0 ile
        basliyordu; kullanici ne degistigini okuyamiyordu.
        Degisiklik gunlugu teslimin parcasidir.
        """
        declared = self._declared()
        log = read("CHANGELOG.md")
        # En ust surum basligi guncel olmali (yeni surum en ustte)
        m = re.search(r"(?m)^##\s+v?([\d.]+)", log)
        self.assertIsNotNone(m, "CHANGELOG.md surum basligi yok")
        self.assertEqual(
            m.group(1), declared,
            "CHANGELOG.md'nin en ust surumu guncel degil; degisiklik "
            "gunlugu guncel surumu icermeli")

    def test_changelog_newest_version_is_not_below_declared(self):
        """Eski surumun altinda kalmis "acik kalan isler" iddialari
        yanilticidir."""
        declared = self._declared()
        log = read("CHANGELOG.md")
        for m in re.finditer(r"(?m)^##\s+v?([\d.]+)", log):
            self.assertLessEqual(
                parse_version(m.group(1)), parse_version(declared),
                f"CHANGELOG.md'de {declared} surumunden YUKSEK "
                f"surumlu bolum var: {m.group(1)}")

    def test_changelog_documents_package(self):
        """1.0.0'in ana teslimi paketleme; gunlugde olmali."""
        log = read("CHANGELOG.md")
        self.assertIn("make package", log,
                      "CHANGELOG.md paketleme komutunu icermeli")
        self.assertIn("dpkg -i", log,
                      "CHANGELOG.md kurulum komutunu icermeli")
        self.assertIn("100/0/0", log,
                      "CHANGELOG.md dogrulama sonucunu icermeli")

    def test_no_stale_claims(self):
        """Cozulmus isler "acik kalan" olarak durmamali.

        CHANGELOG "Pardus 25.2 UZERINDE tam dogrulama YAPILAMADI"
        diyordu; gercek Pardus'ta 100/0/0 alindi.
        """
        log = read("CHANGELOG.md").upper()
        # Bu cumleler cozuldu; guncel bolum haric gorunmemeli
        for stale in ("YAPILAMADI",):
            for line in log.splitlines():
                if stale in line and "1.0.0" not in line:
                    # 0.1.x tarihsel bolumlerinde olabilir, ama
                    # "COZULDU" isareti olmali
                    idx = log.find(line)
                    ctx = log[max(0, idx - 400):idx + 400]
                    self.assertTrue(
                        "COZULDU" in ctx or "COZULDU" in line,
                        f"CHANGELOG.md bayat iddia iceriyor: {line.strip()[:60]}")



def parse_version(v):
    """'1.2.3' -> (1, 2, 3) karsilastirma icin."""
    return tuple(int(x) for x in v.split("."))


if __name__ == "__main__":
    unittest.main()
