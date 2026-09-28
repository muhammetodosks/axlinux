#!/usr/bin/env python3
"""AXlinux uctan uca entegrasyon testi.

Daemon'i gecer, gercek YAML politikasini derler, socket uzerinden
reload eder ve status ciktisinin sozlesmeyi sagladigini dogrular.

Kullanim:
    python3 tests/integration.py --daemon /tmp/axdaemon
"""
import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src" / "python"))

from axctl.compiler import compile_policy  # noqa: E402
from axctl.validator import validate_policy  # noqa: E402

SOCKET_PATH = "/run/axlinux/ax_it.sock"

POLICY = """
version: 1
mode: enforcing
labels:
  web:
    - nginx
    - apache2
  browsers:
    - firefox
    - chromium
rules:
  - name: "web sunuculari web icerigini okur"
    subject: web
    object: /var/www
    action: file.read
    effect: allow
  - name: "web sunuculari shadow okuyamaz"
    subject: web
    object: /etc/shadow
    action: file.read
    effect: deny
  - name: "tarayicilar ssh anahtarlarini goremez"
    subject: browsers
    object: /root/.ssh
    action: file.read
    effect: deny
  - name: "python disari cikamaz"
    subject: python
    action: net.connect
    effect: deny
"""

# status ciktisinda olmasi gereken anahtarlar (Go sozlesmesi)
EXPECTED_KEYS = {
    "status", "mode", "uptime", "started_at",
    "rules_loaded", "labels_loaded", "last_reload",
    "lsm_hooks_active", "lsm_hooks_total",
    "bpf_programs_loaded", "bpf_programs_total",
    "enforcement_active",
}

passed = 0
failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ok   {name}")
    else:
        failed += 1
        print(f"  FAIL {name} {detail}")


def rpc(method, params=None, path=SOCKET_PATH, timeout=8):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(path)
    s.sendall((json.dumps({"method": method, "params": params or {},
                           "id": 1}) + "\n").encode())
    buf = b""
    while b"\n" not in buf:
        chunk = s.recv(65535)
        if not chunk:
            break
        buf += chunk
    s.close()
    return json.loads(buf.decode().strip())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--daemon", default="/tmp/axd2")
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()

    # --- 1. Politika derleme ---
    print("[1] YAML derleme ve dogrulama")
    import yaml
    policy = yaml.safe_load(POLICY)
    validate_policy(policy)
    compiled = compile_policy(policy)
    check("derlendi", compiled["version"] == 1)
    check("4 kural", len(compiled["rules"]) == 4, f"-> {len(compiled['rules'])}")
    check("2 etiket", len(compiled["labels"]) == 2, f"-> {len(compiled['labels'])}")
    check("deny oncelikli", compiled["rules"][0]["effect"] == "deny",
          f"-> ilk kural {compiled['rules'][0]['effect']}")
    check("etiket genisletildi",
          any("nginx" in r["subject"] for r in compiled["rules"]))

    # --- 2. Daemon baslat ---
    print("[2] Daemon")
    Path(SOCKET_PATH).unlink(missing_ok=True)
    proc = subprocess.Popen(
        [args.daemon, "--socket", SOCKET_PATH],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        preexec_fn=os.setsid if hasattr(os, "setsid") else None,
    )
    for _ in range(40):
        if Path(SOCKET_PATH).exists():
            break
        time.sleep(0.25)
    check("socket acildi", Path(SOCKET_PATH).exists())
    if not Path(SOCKET_PATH).exists():
        print(proc.stdout.read() if proc.stdout else "")
        return 1

    try:
        # --- 3. Bos durum ---
        print("[3] Bos durum")
        st = rpc("get_status")["result"]
        check("mode permissiv baslar", st["mode"] == "permissive", f"-> {st['mode']}")
        check("kural yok", st["rules_loaded"] == 0, f"-> {st['rules_loaded']}")
        check("son yukleme bos", st["last_reload"] == "", f"-> {st['last_reload']!r}")
        check("uptime bicimli", "sn" in st["uptime"] or "dk" in st["uptime"],
              f"-> {st['uptime']!r}")
        check("sozlesme anahtarlari", EXPECTED_KEYS <= set(st.keys()),
              f"-> eksik: {sorted(EXPECTED_KEYS - set(st.keys()))}")

        # --- 4. Politika reload ---
        print("[4] Politika reload")
        r = rpc("reload_policy", {"policy": compiled})
        check("reload ok", r.get("error") is None, f"-> {r.get('error')}")
        res = r.get("result", {})
        check("4 kural yuklendi", res.get("rules_loaded") == 4,
              f"-> {res.get('rules_loaded')}")

        # --- 5. Duzeltilmis durum ---
        print("[5] Duzeltilmis durum")
        st = rpc("get_status")["result"]
        check("mode enforcing oldu", st["mode"] == "enforcing", f"-> {st['mode']}")
        # enforcement_active must be an honest boolean. When the host
        # lacks 'bpf' in its LSM chain it must be False, and a notice
        # must be present so the CLI can warn.
        if st.get("enforcement_active"):
            check("enforcement acik, uyari olmamali",
                  not st.get("enforcement_notice"))
        else:
            check("enforcement kapali, uyari var",
                  bool(st.get("enforcement_notice")),
                  "-> kancalar bagli olsa bile uyari verilmeli")
        check("4 kural", st["rules_loaded"] == 4, f"-> {st['rules_loaded']}")
        check("2 etiket", st["labels_loaded"] == 2, f"-> {st['labels_loaded']}")
        check("son yukleme dolu", st["last_reload"] != "", f"-> {st['last_reload']!r}")
        check("uptime bicimli", "sn" in st["uptime"] or "dk" in st["uptime"],
              f"-> {st['uptime']!r}")

        # --- 6. Mod degisimi ---
        print("[6] Mod degisimi")
        r = rpc("set_mode", {"mode": "permissive"})
        check("permissive", r["result"]["mode"] == "permissive", f"-> {r['result']}")
        st = rpc("get_status")["result"]
        check("status yansitti", st["mode"] == "permissive", f"-> {st['mode']}")

        r = rpc("set_mode", {"mode": "disabled"})
        check("disabled", r["result"]["mode"] == "disabled", f"-> {r['result']}")

        # --- 7. Hatali mod reddedilmeli ---
        print("[7] Girdi dogrulama")
        r = rpc("set_mode", {"mode": "kotu_mod"})
        check("gecersiz mod reddedildi", r.get("error") is not None)

        bad = dict(compiled)
        bad["version"] = 99
        r = rpc("reload_policy", {"policy": bad})
        check("gecersiz versiyon reddedildi", r.get("error") is not None)

        # --- 8. Ogrenme modu ---
        print("[8] Ogrenme modu")
        r = rpc("learn_start", {"days": 1})
        check("learn_start ok", r.get("error") is None, f"-> {r.get('error')}")
        r = rpc("learn_report")
        check("learn_report ok", r.get("error") is None, f"-> {r.get('error')}")

    finally:
        try:
            os.killpg(os.getpgid(proc.pid), 15)
        except Exception:
            proc.terminate()
        time.sleep(0.3)
        if not args.keep:
            Path(SOCKET_PATH).unlink(missing_ok=True)

    print()
    print(f"SONUC: {passed} gecti, {failed} kaldi")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
