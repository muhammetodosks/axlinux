#!/usr/bin/env python3
"""Kurulum araclarinin guvenlik korumalari icin regresyon testleri.

Buradaki testler daha once YANLISLIKLA GECTI. Hepsi ayni siniftan:
koruma kod vardi, calisiyor gibi gorunuyordu, ama bir bilesen
beklenmedik davraninca sessizce devre disi kaliyordu.

Sessiz gecen bir guvenlik korumasi, hic koruma olmamasindan
kotudur: kullanici korundugunu sanar.
"""
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERIFY = ROOT / "tests" / "verify_all.sh"
INSTALL = ROOT / "install.sh"


def read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


class TestVirtualGuard(unittest.TestCase):
    """verify_all.sh fiziksel makinede calismayi reddetmeli."""

    def test_guard_present(self):
        src = read(VERIFY)
        self.assertIn("AXLINUX_ALLOW_PHYSICAL", src,
                      "fiziksel makine korumasi yok")
        self.assertIn("systemd-detect-virt", src)

    def test_no_exit_code_fallback_on_detect_virt(self):
        """Bu regresyonu kilitliyor.

        systemd-detect-virt fiziksel makinede "none" YAZAR ve
        CIKIS KODU 1 doner. Onceki surum
        "$(systemd-detect-virt || echo bilinmiyor)" yaziyordu; bu
        yuzden _VIRT iki satirlik "none\\nbilinmiyor" oluyor ve
        case "none" ile ESLESMIYORDU. Koruma hic tetiklenmedi.

        Kural: cikis kodu hicbir yerde fallback zincirine girmez.
        """
        src = read(VERIFY)
        for m in re.finditer(r'\$\(systemd-detect-virt[^)]*\)', src):
            self.assertNotIn("||", m.group(0),
                             f"systemd-detect-virt ciktisinda "
                             f"'||' var; rc=1 oldugunda ikinci satir "
                             f"ekler ve koruma calismaz: {m.group(0)}")

    def test_detect_virt_output_taken_with_head(self):
        src = read(VERIFY)
        self.assertRegex(
            src, r'systemd-detect-virt\s+2>/dev/null\s*\|\s*head -1',
            "systemd-detect-virt ciktisi tek satira indirilmelidir")

    @staticmethod
    def _is_physical() -> bool:
        """Guvenli tespit: cikis koduna DUGANME.

        systemd-detect-virt fiziksel makinede "none" yazar ve cikis
        kodu 1 doner. Onceki surum "|| echo" ile zincir kuruyordu ve
        iki satirlik deger uretiliyordu.
        """
        try:
            r = subprocess.run(["systemd-detect-virt"],
                               capture_output=True, text=True, timeout=10)
            first = (r.stdout or "").strip().splitlines()
            return (first[0] if first else "none") == "none"
        except (OSError, subprocess.SubprocessError):
            return False

    def test_refuses_on_physical_machine(self):
        """Fiziksel makinede betik reddetmeli.

        Yalnizca fiziksel makinede calistirilir. SANAL MAKİNEDE
        bu test atlanir: aksi halde verify_all.sh gercekten enforcement
        uygular, adim sonunda modu "disabled"a ceker ve testin
        YAN ETKISI olarak sistemin enforcement'i kapatir.

        Boyle bir test kabul edilemez: test, denetledigi seyi bozuyor.
        """
        if not self._is_physical():
            self.skipTest("sanal makine; verify_all.sh calistirilamaz")
        r = subprocess.run(["bash", str(VERIFY)],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 1,
                         "fiziksel makinede reddetmeliydi")
        self.assertIn("fiziksel", (r.stdout + r.stderr).lower())
        # Reddedildiginde hicbir sey baslatilmamis olmali.
        self.assertNotIn("socket acildi", r.stdout)
        self.assertNotIn("setsid", r.stdout)

    def test_verify_script_syntax_valid(self):
        """verify_all.sh sozdizimi bozuk olmamali.

        Yalnizca SOZDIZIMI denetlenir; betik calistirilmaz. Calistirmak
        gercek enforcement uygular.
        """
        r = subprocess.run(["bash", "-n", str(VERIFY)],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0,
                         f"sozdizimi hatasi: {r.stderr}")


class TestInstallScript(unittest.TestCase):
    """install.sh daha once kurulumu durduran hatalar icerdi."""

    def test_btf_checked_as_file_not_directory(self):
        """Regresyon: /sys/kernel/btf/vmlinux bir DOSYADIR.

        -d (dizin) ile kontrol edildigi icin "kernel BTF yok"
        denip kurulum durduruluyordu.
        """
        src = read(INSTALL)
        self.assertIn("/sys/kernel/btf/vmlinux", src)
        # -d (dizin) YANLIS: vmlinux bir dosya. -e veya -r dogru.
        # [dr] icinde 'r' de oldugu icin onceki negatif desen
        # dogru kodu da reddediyordu; sadece -d'ye bakilir.
        self.assertNotRegex(
            src, r'!\s*-d\s+/sys/kernel/btf/vmlinux',
            "vmlinux bir dosyadir; -d (dizin) kullanilmamali")
        self.assertRegex(src, r'!\s*-[er]\s+/sys/kernel/btf/vmlinux',
                         "vmlinux -e/-r ile kontrol edilmeli")

    def test_summary_defined_before_use(self):
        """Regresyon: summary() adimlardan SONRA tanimliydi.

        Bash fonksiyonlari yalnizca tanimdan sonra cagrilabilir;
        once cagrilinca "command not found" verip kurulumu
        yarida kesiyordu.
        """
        lines = read(INSTALL).split("\n")
        fn = next(i for i, l in enumerate(lines) if l.startswith("summary()"))
        use = next(i for i, l in enumerate(lines) if l.strip().startswith("begin "))
        self.assertLess(fn, use,
                        "summary() tanimi ilk adimdan once olmali")

    def test_steps_no_unbound_argument(self):
        """Regresyon: done_step bos argumanla cagrilinca $2
        unbound oluyordu ve set -u altinda script cokuyordu."""
        src = read(INSTALL)
        # Govde regex'i "${2:-}" icindeki '}'de kesilmesin diye
        # fonksiyonun TAM SATIRINI aliyoruz.
        for fn in ("done_step", "warn_step", "fail_step"):
            line = next((l for l in src.split("\n")
                         if l.strip().startswith(fn + "()")), None)
            self.assertIsNotNone(line, f"{fn} tanimi bulunamadi")
            self.assertNotRegex(line, r'\$\{1:-\$2\}',
                                f"{fn} $2'ye guvenli erisim kullanmali")
            self.assertIn("${2:-}", line,
                          f"{fn} $2 icin varsayilan kullanmali")

    def test_step_count_matches_actual_steps(self):
        src = read(INSTALL)
        total = int(re.search(r'^\s*TOTAL=(\d+)', src, re.M).group(1))
        actual = len(re.findall(r'^\s*begin\s+"', src, re.M))
        self.assertEqual(total, actual,
                         f"TOTAL={total} ama {actual} adim var")

    def test_lsm_chain_is_idempotent(self):
        """Regresyon: zincirde bpf varken yine ekleniyordu.

        Ayni komut ikinci calistirildiginda lsm=...,bpf,bpf,...
        olusuyordu.
        """
        src = read(INSTALL)
        # Tekrar eden bpf elemesi olmali.
        self.assertRegex(src, r'\[ "\$SEEN_BPF" = "1" \] && continue',
                         "tekrar eden bpf girdileri temizlenmeli")
        # ve sayac resetlenmeli
        self.assertIn("SEEN_BPF=0", src)

    def test_no_automatic_reboot(self):
        src = read(INSTALL)
        dangerous = re.findall(r'^\s*(sudo\s+)?reboot\s*$', src, re.M)
        for d in dangerous:
            self.fail("kurulum araci otomatik reboot yapmamali")
        self.assertIn("sudo reboot", src,
                      "reboot yalnizca kullaniciya onerilmeli")

    def test_grub_backed_up_before_change(self):
        src = read(INSTALL)
        cp = src.index("axlinux-backup")
        sed = src.index("GRUB_CMDLINE_LINUX_DEFAULT=\\\"lsm=")
        self.assertLess(cp, sed,
                        "GRUB degistirilmeden once yedek alinmali")

    def test_recovery_entry_left_usable(self):
        """Guvenlik agina cikis: bpf LSM boot'u kirarsa sistem
        rescue modu ile kurtarilabilmeli."""
        src = read(INSTALL)
        self.assertRegex(src, r"/recovery/\s*s\|\s*lsm=\[\^\s*\]\*\|\|",
                         "recovery girdisinden lsm= kaldirilmalidir")


if __name__ == "__main__":
    unittest.main(verbosity=2)
