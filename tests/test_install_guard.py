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


    def test_required_tools_are_also_installed(self):
        """Kontrol edilen her arac kurulum listesinde de gecmeli.

        "git" kontrol ediliyordu ama install_pkgs cagrisinda
        yoktu; Ubuntu'da onceden kurulu oldugu icin sorun
        gorunmedi, Debian'da kurulum durdu.
        """
        src = read(INSTALL)
        m = re.search(r"for t in ([^;]+);", src)
        self.assertIsNotNone(m, "arac kontrol listesi bulunamadi")
        checked = set(re.findall(r"[\w+]+", m.group(1)))
        self.assertIn("git", checked, "git kontrol ediliyor olmali")
        flat = re.sub(r"\\\s*\n\s*", " ", src)
        calls = " ".join(re.findall(r"install_pkgs\s+([^;]*?);", flat))
        for tool in ("git", "clang", "llvm", "rsync", "curl"):
            if tool in checked:
                self.assertIn(
                    tool, calls,
                    f"{tool} kontrol ediliyor ama install_pkgs "
                    f"cagrisinda gecmiyor")

    def test_packages_installed_individually(self):
        """Regresyon: tek bulunamayan paket tum kurulumu dusuruyordu.

        apt/dnf, "bulunamayan paket" hatasinda islemin tamamini
        birakir. Listede dagitima gore olmayan bir paket varsa
        (linux-tools-common Debian 12'de "no installation candidate")
        HICBIR paket kurulmuyor, kurulum "kurulamayan araclar: git"
        ile duruyor ve axctl hic kurulmuyordu - 69 test basarisiz.

        Cozum: paketler tek tek kurulur, bulunamayanlar atlanir.
        """
        src = read(INSTALL)
        self.assertIn("install_one", src)
        self.assertIn("pkg_available", src)
        # toplu kurulum KALMAMALI
        self.assertNotRegex(
            src, r'apt-get install -y -qq "\$@"',
            "toplu kurulum kaldirilmali; paketler tek tek kurulmali")

    def test_waits_for_apt_lock(self):
        """Regresyon: apt kilidi tutuldugunda kurulum SESSIZCE
        basarisiz oluyordu.

        cloud-init, unattended-upgrades veya apt-daily kilidi
        tutuyorsa apt-get "Could not get lock" verir. Onceki surum
        bunu /dev/null'a atiyor ve kullaniciya "araclar kurulamadi"
        diyordu; gercek sebep gizliydi.
        """
        src = read(INSTALL)
        self.assertIn("wait_for_apt_lock", src)
        self.assertRegex(src, r'dpkg/lock-frontend',
                         "kilit kontrolu /var/lib/dpkg/lock-frontend "
                         "olmalidir")
        # paket kurulum ciktisi gizlenmemeli
        self.assertNotRegex(
            src, r'apt-get install -y -qq[^\n]*>/dev/null',
            "apt-get install ciktisi gizlenmemeli; hata gorunmelidir")

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


class TestPythonDependencies(unittest.TestCase):
    """axctl'in calisma zamani bagimliliklari sozlesmeli.

    Once hicbir bagimlilik tanimli degildi. Ubuntu'da click/rich/yaml
    baska paketler sayesinde zaten kurulu oldugu icin sorun
    gorunmedi; Debian'da kurulum "calisiyor" derken
    "axctl status" "ModuleNotFoundError: No module named 'click'"
    ile coktu. Kullanici kurulumu basarili saniyordu.
    """

    ROOT = Path(__file__).resolve().parent.parent
    REQ = ROOT / "src" / "python" / "requirements.txt"
    PKGDIR = ROOT / "src" / "python" / "axctl"
    STDLIB = {
        "axctl", "os", "sys", "json", "re", "pathlib", "shutil",
        "subprocess", "socket", "time", "datetime", "typing", "enum",
        "dataclasses", "collections", "itertools", "functools",
        "textwrap", "hashlib", "stat", "tempfile", "errno",
        "signal", "platform", "glob", "copy", "argparse", "abc",
        "io", "contextlib", "logging", "pprint", "secrets", "string",
        "uuid", "warnings", "ast", "unittest", "pytest",
    }
    # PyPI adi -> import adi
    MAP = {"PyYAML": "yaml"}

    def test_requirements_file_exists(self):
        self.assertTrue(self.REQ.exists(),
                        "src/python/requirements.txt yok; calisma zamani "
                        "bagimliliklar tanimsiz")

    def test_every_third_party_import_is_declared(self):
        """Yeni import eklenip requirements.txt guncellenmezse yakalar."""
        declared = set()
        for line in read(self.REQ).splitlines():
            line = line.split("#")[0].strip()
            if line:
                declared.add(re.split(r"[><=!\[]", line)[0].strip().lower())
        imported = set()
        for f in self.PKGDIR.glob("*.py"):
            for m in re.finditer(r"^\s*(?:import|from)\s+([a-zA-Z_][\w]*)",
                                 read(f), re.M):
                mod = m.group(1)
                if mod not in self.STDLIB:
                    imported.add(mod.lower())
        missing = imported - {d.lower() for d in declared} - \
            {v.lower() for v in self.MAP.values()}
        self.assertEqual(
            missing, set(),
            f"requirements.txt'te olmayan import'lar: {missing}. "
            f"Yeni bir 3. taraf modul eklediyseniz requirements.txt "
            f"ve pyproject.toml'a da ekleyin.")

    def test_makefile_verifies_dependencies(self):
        """make python bagimliliklari DOGRULAMALI.

        Kurulumdan sonra degil, ONCEDEN bilmelidir: kurulum
        basarili gorunup CLI cokmemelidir.
        """
        mk = read(self.ROOT / "Makefile")
        # Makefile dongusu "import $m" yazar; tek tek ad aramak
        # yanlis olurdu, dongunun varligi ve ad listesi denetlenir.
        self.assertRegex(mk, r"for m in click rich yaml",
                         "Makefile bagimlilik dongusu eksik")
        self.assertIn('import $$m', mk,
                      "Makefile her modulü import ile denemeli")
        self.assertRegex(mk, r"eksik Python bagimliliklari",
                         "eksik bagimlilik hatasi acikca bildirilmeli")

    def test_installer_installs_dependencies(self):
        s = read(self.ROOT / "install.sh")
        self.assertIn("python3-click", s)
        self.assertRegex(s, r"pip3 install.*click",
                         "apt bulamazsa pip yolu da olmali")

    def test_pyproject_declares_dependencies(self):
        pp = self.ROOT / "src" / "python" / "pyproject.toml"
        self.assertTrue(pp.exists(), "pyproject.toml yok")
        txt = read(pp)
        for d in ("click", "rich", "PyYAML"):
            self.assertIn(d, txt, f"{d} pyproject.toml'da tanimli degil")

    def test_install_copies_metadata(self):
        mk = read(self.ROOT / "Makefile")
        self.assertIn("requirements.txt", mk,
                      "requirements.txt kurulumla birlikte kopyalanmali")


class TestSharedRuntimeDirectory(unittest.TestCase):
    """/run/axlinux birden fazla servis tarafindan paylasilir.

    RuntimeDirectory, sahibi olan servis HER BASLADIGINDA dizini
    silip yeniden olusturur. Dizin iki servis arasinda paylasildigi
    icin bu, diger servisin soketini ortadan kaldirir. 2026-09-30
    Debian 12'de boyle oldu: axlog 20:07:51'de basladi ve
    axlog.sock olusturdu, axdaemon 20:07:52'de basladi ve dizini
    sildi. axlog calismaya devam etti (3 socket fd bellekte)
    ama diskte soket yoktu (ss -xl -> 0). Yani "aktif" gorunen
    audit servisi KAYIT BIRAKMIYORDU ve kurulum yanlis olarak
    basarisiz oldu.

    Dizin artik systemd-tmpfiles ile kurulur; hicbir servis
    sahiplenmez.
    """

    ROOT = Path(__file__).resolve().parent.parent
    PKG = ROOT / "packaging"
    TMPFILES = Path("/usr/lib/tmpfiles.d/axlinux.conf")

    def units(self):
        return {p.name: read(p) for p in self.PKG.glob("*.service")}

    def test_no_unit_owns_shared_runtime_directory(self):
        for name, txt in self.units().items():
            for line in txt.splitlines():
                line = line.strip()
                if line.startswith("RuntimeDirectory="):
                    self.fail(
                        f"{name} RuntimeDirectory tanimliyor: {line!r}. "
                        f"/run/axlinux paylasildigi icin hicbir servis "
                        f"sahiplenmemeli; systemd sahibi baslarken dizini "
                        f"silip diger servisin soketini yok ediyor. "
                        f"Dizin axlinux-tmpfiles.conf'a tasindi.")

    def test_tmpfiles_config_creates_runtime_dir(self):
        f = self.PKG / "axlinux-tmpfiles.conf"
        self.assertTrue(f.exists(),
                        "axlinux-tmpfiles.conf yok; /run/axlinux'i "
                        "kuran tek mekanizma bu olmali")
        txt = read(f)
        self.assertRegex(txt, r"(?m)^d /run/axlinux ",
                         "tmpfiles /run/axlinux dizinini kurmali")
        # onceki oturumdan kalmis soketler temizlenmeli
        self.assertRegex(txt, r"(?m)^r /run/axlinux/axlog\.sock",
                         "eski axlog.sock temizlenmeli")

    def test_services_wait_for_tmpfiles(self):
        for name, txt in self.units().items():
            self.assertIn("systemd-tmpfiles-setup.service", txt,
                          f"{name} tmpfiles kurulumunu beklemeli")

    def test_installer_creates_dir_and_single_transaction(self):
        s = read(self.ROOT / "install.sh")
        self.assertIn("systemd-tmpfiles --create", s,
                      "installer tmpfiles ile dizini kurmali")
        # Iki ayri restart After= siralamasini UYGULAMAZ; tek
        # transaction gerekir.
        self.assertNotRegex(
            s, r"systemctl restart axlog[^\n]*\n[^\n]*systemctl restart axdaemon",
            "servisler ayri transaction'da baslatiliyor; After= "
            "tek transaction icinde gecerlidir")
        self.assertIn("systemctl restart axdaemon axlog", s,
                      "servisler tek transaction'da baslatilmali")

    def test_makefile_installs_tmpfiles(self):
        mk = read(self.ROOT / "Makefile")
        self.assertIn("axlinux-tmpfiles.conf", mk)
        self.assertIn("tmpfiles.d/axlinux.conf", mk)


class TestSourceTreeNotPolluted(unittest.TestCase):
    """Kurulum kullanicinin deposunu kirletmemeli.

    "sudo make install" derleme adimini da root olarak calistirir.
    Onceki surumde "compileall src/python/axctl" dogrudan kaynak
    agacina yaziyordu, sonuc root'a ait __pycache__ kaliyordu.
    Sonrasi: kullanici artik "rm -rf axlinux" bile yapamiyor
    ("Permission denied") ve yeni kaynak aktarimi sessizce
    ESKI kaynakla surer. Debian 12'de duzeltmeyi test
    etmek mumkun olmadi bu yuzden.

    Bytecode .build/pycache altina yonlendirilir.
    """

    ROOT = Path(__file__).resolve().parent.parent

    def test_compileall_does_not_write_to_source_tree(self):
        mk = read(self.ROOT / "Makefile")
        m = re.search(r"compileall[^\n]*", mk)
        self.assertIsNotNone(m, "compileall cagrisi bulunamadi")
        self.assertRegex(
            mk, r"PYTHONPYCACHEPREFIX=\$\(CURDIR\)/\.build/pycache",
            "compileall pycache-prefix olmadan calisiyor; kaynak "
            "agacini root'a ait dosyalarla kirletir")
        # Prefix tanimli olsa bile pycache_prefix'i unutmamali
        self.assertNotRegex(
            mk, r"^\s*@?\s*\$\(PYTHON\) -m compileall -q \$\(PY_DIR\)",
            "prefix'siz dogrudan compileall cagrisi var")

    def test_build_dir_ignored(self):
        gi = self.ROOT / ".gitignore"
        self.assertTrue(gi.exists())
        self.assertRegex(read(gi), r"(?m)^/?\.build/",
                         ".build/ gitignore'da olmali; bytecode "
                         "kaynak agacini degil buraya yazilir")


class TestPolicyCheckAcceptsFile(unittest.TestCase):
    """policy check/simulate bir dosyayi denetleyebilmeli.

    Once "check" ve "simulate" dosya ARGUMANI kabul etmiyordu;
    yalnizca aktif politikayi (/…/.axlinux/policy.yaml) denetliyordu.
    Sonuc: bir aday politikayi UYGULAMADAN ONCE dogrulamanin
    hicbir yolu yoktu. Politika ancak aktif edilip hata
    verildikten sonra denetlenebiliyordu, yani "check" komutu
    uygulama sonrasi hatayi gormekten baska ise yaramiyordu.
    """

    ROOT = Path(__file__).resolve().parent.parent
    CLI = ROOT / "src" / "python" / "axctl" / "cli.py"

    def test_policy_group_has_file_option(self):
        txt = read(self.CLI)
        self.assertRegex(
            txt, r'"--file",\s*"-f",\s*"file_path"',
            "policy komut grubunda --file/-f secenegi olmali")

    def test_check_receives_file_path(self):
        txt = read(self.CLI)
        self.assertRegex(txt, r"def _policy_check\(file_path",
                         "_policy_check dosya almal")
        self.assertIn("load_policy(file_path)", txt,
                      "check verilen dosyayi yuklemeli")
        self.assertIn("get_policy_stats(file_path)", txt,
                      "istatistikler denetlenen dosyadan alinmali; "
                      "aktif politikanin sayilari gosterilmemeli")

    def test_simulate_receives_file_path(self):
        txt = read(self.CLI)
        self.assertRegex(txt, r"def _policy_simulate\(output_format[^)]*file_path")
        self.assertIn("simulate_policy(file_path)", txt)

    def test_underlying_functions_accept_path(self):
        """Alt fonksiyonlar zaten destekliyordu; eksik olan yalnizca CLI."""
        pol = read(self.ROOT / "src" / "python" / "axctl" / "policy.py")
        self.assertRegex(pol, r"def load_policy\(path")
        self.assertRegex(pol, r"def get_policy_stats\(path")
        sim = read(self.ROOT / "src" / "python" / "axctl" / "simulator.py")
        self.assertRegex(sim, r"def simulate_policy\(path")


class TestDaemonErrorHandling(unittest.TestCase):
    """Daemon hatalari kullaniciya anlasilir sekilde donmeli.

    JSON-RPC hata nesnesi bir SOZLUKTUR:
        {"code": -32000, "message": "ogrenme modu zaten aktif"}
    Once f-string ile basilirdi ve kullanicya ham Python sozlugu
    gorunuyordu:
        x Daemon hatasi: {'code': -32000, 'message': '...'}
    Ayrica "zaten aktif" bir ALTYAPI hatasi degil, uygulama
    seviyesinde bir ret; ama exit code 4 ile cikiyordu.
    """

    ROOT = Path(__file__).resolve().parent.parent
    DC = ROOT / "src" / "python" / "axctl" / "daemon_client.py"
    EX = ROOT / "src" / "python" / "axctl" / "exceptions.py"
    CLI = ROOT / "src" / "python" / "axctl" / "cli.py"

    def test_app_error_class_exists_and_inherits(self):
        txt = read(self.EX)
        self.assertIn("class DaemonAppError(DaemonError)", txt)
        # Miras iliskisi calisma aninda dogrulanir: sinif
        # tanimlanma SIRASI hataliysa modul hic import olmaz.
        import subprocess
        r = subprocess.run(
            [sys.executable, "-c",
             "import sys;sys.path.insert(0,'src/python');"
             "from axctl.exceptions import DaemonAppError,DaemonError;"
             "assert issubclass(DaemonAppError,DaemonError);"
             "print(DaemonAppError.exit_code)"],
            cwd=self.ROOT, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0,
                         f"exceptions.py import edilemiyor: {r.stderr}")
        self.assertEqual(r.stdout.strip(), "1",
                         "uygulama seviyesi hata exit_code=1 olmali")

    def test_error_dict_is_unpacked(self):
        txt = read(self.DC)
        self.assertNotIn("f\"Daemon hatası: {response['error']}\"", txt,
                         "ham sozluk f-string ile basilmaya devam ediyor")
        self.assertIn("DaemonAppError(msg)", txt,
                      "hata mesaji temizlenip uygulama hatası olarak "
                      "yükseltilmeli")
        self.assertIn('err.get("message")', txt)

    def test_cli_uses_exception_exit_code(self):
        txt = read(self.CLI)
        self.assertNotRegex(txt, r"except DaemonError as e:\n\s+"
                                r"print_error\(str\(e\)\)\n\s+sys\.exit\(4\)",
                           "sabit exit 4 kullaniliyor; sinifin exit_code'u "
                           "kullanilmali")
        self.assertGreaterEqual(txt.count("sys.exit(e.exit_code)"), 5)

    def test_logs_has_structured_options(self):
        """logs yalnizca --filter metni kabul ediyordu.

        "axctl logs --effect denied" click tarafindan "bilinmeyen
        secenek" hatasina dusuyordu (rc=2). Ayrica status --json
        varken logs'ta --json yoktu; audit kayitlarini arac olarak
        islemek isteyen kullanici elle metin ayiklamak zorundaydi.
        """
        txt = read(self.CLI)
        for opt in ('"--json"', '"--subject"', '"--action"', '"--effect"'):
            self.assertIn(opt, txt, f"logs'ta {opt} secenegi olmali")
        # Alan secenekleri filtre sozlesmesine cevrilmeli
        self.assertIn('filters["subject"] = subject', txt)
        self.assertIn('filters["action"] = action', txt)
        # effect DAIMONUN bekledigi deger olarak normalize edilir
        # ("deny"/"allow"); kullanicinin "denied" yazmasi calismali.
        self.assertRegex(txt, r'filters\["effect"\] = \(\s*\n?\s*'
                             r'"deny" if effect\.lower\(\)',
                         "effect filtresi normalize edilmiyor")

    def test_label_rm_exists(self):
        """Etiket ekleniyordu ama SILINEMIYORDU."""
        txt = read(self.CLI)
        self.assertIn('@label.command("rm")', txt,
                      "label rm yok; etiket kaldirilamiyor")
        self.assertIn("del labels[name]", txt)
        # Var olmayan etiket sessizce "silindi" dememeli
        self.assertIn("Etiket bulunamadı", txt)


class TestEmergencyEscapeHatch(unittest.TestCase):
    """ACIL KURTARMA YOLU calismali.

    "axctl reload --force-empty", kotu bir politika yuzunden
    kilitlenen operatorun enforcement'i durdurma yoludur. Bos
    politika reddedildigi icin komut KENDISI basarisiz oluyordu:

        x policy yukleme hatasi: policy en az bir kural icermeli

    Yani kurtarma araci sistemi kilitli birakirdi. Ayni
    dogrulama "axctl init" + "axctl reload" ilk kurulum akisini
    da kirip gecersiz kiliyordu: init bos politika yazar.
    """

    ROOT = Path(__file__).resolve().parent.parent
    POL = ROOT / "src" / "go" / "axdaemon" / "internal" / "policy" / "policy.go"
    CLI = ROOT / "src" / "python" / "axctl" / "cli.py"

    def test_daemon_accepts_empty_rule_set(self):
        import re
        txt = read(self.POL)
        # Eski hata metni aciklama yorumunda ANILIR; onemli olan
        # canli bir hatada cikmasidir.
        live = [ln for ln in txt.splitlines()
                if "en az bir kural" in ln
                and not ln.lstrip().startswith("//")]
        self.assertEqual(live, [],
                         "bos kural listesi yine reddediliyor; acil "
                         "kurtarma yolu calismaz")
        # Kural sayisi yerine anahtarin VARLIGI denetlenmeli
        self.assertIn('probe["rules"]', txt,
                      "'rules' anahtarinin varligi denetlenmeli; yazim "
                      "hatasi sessizce kisitlamasiz sistem uretmemeli")

    def test_go_test_covers_escape_hatch(self):
        t = read(self.ROOT / "src" / "go" / "axdaemon" / "internal"
                 / "policy" / "policy_test.go")
        self.assertIn("TestLoadAcceptsEmptyRuleSet", t)
        self.assertIn("TestLoadRejectsMissingRulesKey", t)

    def test_init_completes_partial_install(self):
        """init, dizin var ama politika dosyasi yoksa cikis yapmamali."""
        txt = read(self.CLI)
        self.assertRegex(txt, r"if policy_path\.exists\(\):\s*\n\s*"
                              r"print_warning",
                         "init, politika dosyasi eksikken de cikiyor")
        self.assertIn("oluşturuluyor", txt,
                      "eksik politika dosyasi olusturulmali")


class TestInexpressibleRulesRejected(unittest.TestCase):
    """HICBIR ZAMAN ESLESEMEYECEK kural reddedilmeli.

    Iki durum da ayni sinif sorun: kural map'e yaziliyor, "N kural
    yuklendi" ciktiyor, kullanici politikayi yuklendigini saniyor -
    ama kural HICBIR zaman tetiklenmiyor. Operator enforcement
    aktifken sanirken sistem bos durur.

    Once ikisi de yalnizca UYARI idi ve politika yine de
    yukleniyordu.
    """

    ROOT = Path(__file__).resolve().parent.parent
    COMP = ROOT / "src" / "python" / "axctl" / "compiler.py"

    def test_protected_subject_is_error_not_warning(self):
        txt = read(self.COMP)
        self.assertIn("def check_protected_subject(", txt)
        self.assertNotIn("def warn_protected_subject(", txt,
                         "uyari olarak kalmaliydi; sessiz etkisizlik")
        # Fonksiyonun govdesinde PolicyError firlatmali
        m = re.search(r"def check_protected_subject\(.*?\n\ndef ", txt, re.S)
        self.assertIsNotNone(m)
        self.assertIn("raise PolicyError", m.group(1))

    def test_simulator_explains_instead_of_crashing(self):
        """Simulatorun isi hatayi ACIKLAMAKTIR."""
        sim = read(self.ROOT / "src" / "python" / "axctl" / "simulator.py")
        self.assertRegex(sim, r"except PolicyError as e:\s*\n\s*return \{",
                         "simulator derlenemeyen politika icin hata "
                         "dondurmeli")
        cli = read(self.ROOT / "src" / "python" / "axctl" / "cli.py")
        self.assertIn('simulation.get("error")', cli,
                      "CLI simulator hatasini gostermeli")

    def test_deep_path_test_generates_real_depth(self):
        """Derin yol testi gercekten derin yol uretmeli.

        Once "printf 'd%.0s' {1..12}" ile TEK bir 12 karakterlik
        bilesen uretiliyordu (/dddddddddddd): derinlik 1. Test
        "derin yol kabul edildi" diye basarisiz oluyordu ama
        politika hicbir zaman derin degildi.
        """
        s = read(self.ROOT / "tests" / "deep_verify.sh")
        self.assertNotIn("printf 'd%.0s' {1..12}", s)
        self.assertRegex(s, r"for i in \$\(seq 1 12\)",
                         "bilesen sayisi kadar yol uretilmeli")


if __name__ == "__main__":
    unittest.main(verbosity=2)
