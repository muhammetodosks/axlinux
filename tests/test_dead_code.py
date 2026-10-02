"""Olu kod ve yarim kalmis kod denetimi.

AXlinux'te olu kod bir kez su sekilde zarar verdi: `get_editor`
hicbir yerden cagrilmadan tanimliydi; CLI'daki olu import
pyflakes'in bildirdigi haliyle duruyordu. Derleyici uyari
vermedigi icin kimse fark etmiyordu.

Asagidaki kontroller kodu temiz tutar:
- pyflakes (kullanilmayan import/degisken)
- TODO/FIXME/HACK yalnizca UYGULAMA kodunda (vmlinux.h ve test
  dosyalari haric)
- CLI'nin cevabi gozlemedigi durumlar
"""
import ast
import re
import unittest
from pathlib import Path

R = Path(__file__).resolve().parent.parent
SRC = R / "src"


class TestNoDeadCode(unittest.TestCase):
    def _py_sources(self):
        return sorted((SRC / "python" / "axctl").glob("*.py"))

    def _imported_names(self, tree):
        """Dosyada import edilen tum adlar."""
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    names.add((a.asname or a.name.split(".")[0]))
            elif isinstance(node, ast.ImportFrom):
                for a in node.names:
                    if a.name == "*":
                        continue
                    names.add(a.asname or a.name)
        return names

    def _used_names(self, tree):
        """Kodda GERCEKTEN referans verilen adlar.

        Import satirlarinin kendisi referans sayilmaz; boylece
        "import X" yazip hic kullanmamak yakalanir.
        """
        used = set()
        import_nodes = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                import_nodes.add(id(node))
        for node in ast.walk(tree):
            if id(node) in import_nodes:
                continue
            if isinstance(node, ast.Name):
                used.add(node.id)
            elif isinstance(node, ast.Attribute):
                n = node
                while isinstance(n, ast.Attribute):
                    n = n.value
                if isinstance(n, ast.Name):
                    used.add(n.id)
        return used

    def test_no_unused_imports(self):
        """Import edilip hic kullanilmayan ad olmamali.

        Harici araca (pyflakes) baglanmaz; PEP 668 yuzden sistem
        Python'unda kurulamayan bir arac testi sessizce atlanma
        riski tasirdi. AST ile ayni denetim her yerde calisir.

        Gercek bulgu: cli.py `get_editor`, `list_backups`;
        compiler.py `warnings`; formatter.py `Text`;
        policy.py `get_audit_dir`; daemon_client.py `code`.
        """
        problems = []
        for f in self._py_sources():
            tree = ast.parse(f.read_text(encoding="utf-8"),
                             filename=str(f))
            imported = self._imported_names(tree)
            used = self._used_names(tree)
            # disa aktarilan __all__ gibi sey olabilir
            text = f.read_text(encoding="utf-8")
            for name in sorted(imported - used):
                # dunder ve tip stub haric
                if name.startswith("__"):
                    continue
                if f'"{name}"' in text or f"'{name}'" in text:
                    continue
                problems.append(f"{f.name}: '{name}'")
        self.assertEqual(problems, [],
                         "kullanilmayan import:\n" + "\n".join(problems))

    def test_no_unused_locals(self):
        """Atanan ama hic okunmayan yerel degisken olmamali.

        Gercek bulgu: cli.py `errors` (validate_policy cevabi
        tamamen atiliyordu) ve `result` (set_mode cevabi
        gozlemedigi icin CLI istenen modu yaziyordu).
        """
        problems = []
        for f in self._py_sources():
            tree = ast.parse(f.read_text(encoding="utf-8"),
                             filename=str(f))
            for func in ast.walk(tree):
                if not isinstance(func, (ast.FunctionDef,
                                         ast.AsyncFunctionDef)):
                    continue
                assigned = {}
                loaded = set()
                for node in ast.walk(func):
                    if isinstance(node, ast.Name):
                        if isinstance(node.ctx, ast.Store):
                            assigned.setdefault(node.id, node.lineno)
                        else:
                            loaded.add(node.id)
                for name, line in assigned.items():
                    if name in loaded or name.startswith("_"):
                        continue
                    problems.append(f"{f.name}:{line}: '{name}'")
        self.assertEqual(problems, [],
                         "okunmayan yerel degisken:\n"
                         + "\n".join(problems))

    def test_no_unreferenced_top_level_functions(self):
        """Ust duzey fonksiyon tanimli ama hicbir yerden cagrilmiyorsa
        olu kod adayidir.

        Diger modulden import edilenler ve CLI tarafindan kullanilanlar
        haric tutulur.
        """
        defs = {}
        for f in self._py_sources():
            tree = ast.parse(f.read_text(encoding="utf-8"))
            for node in tree.body:
                if isinstance(node, ast.FunctionDef):
                    if not node.name.startswith("_"):
                        defs[node.name] = f.name
        # click komutlari @cli.command() DEKORATORUYLE kayit olur; adi
        # hicbir yerde gecmez. Bunlar olu kod degildir.
        # Dekorator cok satirli olabildigi icin (@click.option(
        # ... ) 5 satira yayiliyor) AST ile aliniyor, metin
        # eslesmesiyle degil -- metin eslesmesi bu komutlari
        # olu saniyordu.
        cli_tree = ast.parse(
            (SRC / "python" / "axctl" / "cli.py").read_text(encoding="utf-8"))
        registered = set()
        for node in cli_tree.body:
            if not isinstance(node, ast.FunctionDef):
                continue
            for dec in node.decorator_list:
                target = dec.func if isinstance(dec, ast.Call) else dec
                if isinstance(target, ast.Attribute) and target.attr == "command":
                    registered.add(node.name)

        corpus = "\n".join(
            p.read_text(encoding="utf-8", errors="replace")
            for p in list(SRC.rglob("*.py")) + list((R / "tests").glob("*.py"))
            if "vmlinux" not in p.name
        )
        dead = []
        for name, where in defs.items():
            if name in registered:
                continue
            uses = len(re.findall(rf"\b{re.escape(name)}\b", corpus))
            # 1 = yalnizca tanim
            if uses <= 1:
                dead.append(f"{where}:{name} ({uses} gecis)")
        self.assertEqual(dead, [],
                         "hicbir yerden cagrilmayan fonksiyon: "
                         + ", ".join(dead))

    def test_no_todo_markers_in_application_code(self):
        """TODO/FIXME/HACK yalnizca UYGULAMA kodunda olmamali.

        vmlinux.h uretilmis cekirdek basligidir; test dosyalari
        bilerek "TODO" icerebilir.
        """
        bad = []
        for pat in ("*.py", "*.go", "*.h"):
            for f in SRC.rglob(pat):
                if f.name == "vmlinux.h":
                    continue
                for i, line in enumerate(
                        f.read_text(encoding="utf-8",
                                    errors="replace").splitlines(), 1):
                    if re.search(r"\b(TODO|FIXME|XXX|HACK)\b", line):
                        rel = f.relative_to(R)
                        bad.append(f"{rel}:{i}: {line.strip()[:50]}")
        self.assertEqual(bad, [], "TODO/FIXME/HACK isaretleri:\n"
                         + "\n".join(bad))

    def test_cli_mode_reports_daemon_answer(self):
        """`axctl mode` daemon'in dondurdugu modu yazmali.

        Once `result = set_mode(mode)` sonucu atiliyordu ve ISTEMEDIGI
        mod yaziliyordu; cevap ile istenen ayrilirsa kullanici
        yanlis bilgi aliyordu.
        """
        s = (SRC / "python" / "axctl" / "cli.py").read_text(encoding="utf-8")
        m = re.search(r"def mode\(mode\):(.*?)\n@(cli|click)", s, re.S)
        self.assertIsNotNone(m)
        body = m.group(1)
        self.assertIn("set_mode(mode)", body)
        self.assertRegex(body, r'effective\s*=\s*result\.get\("mode"',
                         "mode komutu daemon cevabini okumali")
        self.assertIn('f"Mod değiştirildi: {effective}"', body,
                      "cikti ETKILI modu gostermeli, isteneni degil")

    def test_policy_errors_printed_once(self):
        """Dogrulama hatalari iki kez basilmamali.

        PolicyError mesaji hata listesini iceriyor; CLI de
        `e.errors`'i ayrica basiyordu, ayni hata iki kez cikiyordu.
        """
        exc = (SRC / "python" / "axctl" / "exceptions.py").read_text(
            encoding="utf-8")
        self.assertIn("self.summary = message", exc,
                      "PolicyError.summary listeyi icermeyen ozet olmali")
        cli = (SRC / "python" / "axctl" / "cli.py").read_text(encoding="utf-8")
        # Her PolicyError yakalayicisinin GOVDESI ayri incelenir.
        # Govde, bir sonraki "except" veya bos satira kadar.
        handlers = re.findall(
            r"except PolicyError as e:\n((?:[ \t]+[^\n]*\n)+?)(?=[ \t]*\n|[ \t]*except)",
            cli)
        self.assertGreaterEqual(len(handlers), 4,
                                "PolicyError yakalayicilari bulunamadi")
        for i, body in enumerate(handlers, 1):
            prints_list_twice = ("str(e)" in body and "e.errors" in body)
            self.assertFalse(
                prints_list_twice,
                f"{i}. PolicyError yakalayicisi hem str(e) hem "
                f"e.errors yaziyor; hata listesi iki kez basilir:\n{body}")
            self.assertTrue(
                "e.summary" in body or "e.errors" not in body,
                f"{i}. yakalayici e.errors yaziyor ama e.summary "
                f"kullanmiyor; ozet gerekir:\n{body}")


if __name__ == "__main__":
    unittest.main()
