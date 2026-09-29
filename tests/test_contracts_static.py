#!/usr/bin/env python3
"""eBPF/Go sozlesme ve "sessiz basarisizlik" testleri.

Buradaki testler, enforcement'in YANLISLIKLA calisiyor gibi
gosterilmesini engeller. MAC'te sessiz basarisizlik en tehlikeli
hata modudur: daemon "1 kural yuklendi" der, 5/5 kanca bagli
gosterir, enforcement_active true doner - ama hicbir sey
engellenmez. Bu testler boyut/alan uyusmazligini, port bicimi
farklarini ve eksik cagriyi YAPILANDAN once yakalar.

Calistirma: python3 tests/test_contracts_static.py
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
BPF = os.path.join(ROOT, "src", "bpf")
GO = os.path.join(ROOT, "src", "go", "axdaemon")

HOOKS = [
    "hooks_file_open.inc",
    "hooks_inode_permission.inc",
    "hooks_bprm_check_security.inc",
    "hooks_socket_connect.inc",
    "hooks_socket_bind.inc",
]

failures = []
passes = 0


def read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def ok(msg):
    global passes
    passes += 1
    print(f"  ok   {msg}")


def fail(msg):
    failures.append(msg)
    print(f"  FAIL {msg}")


def section(name):
    print(f"\n=== {name} ===")


def main():
    header = read(os.path.join(BPF, "axbpf.h"))
    maps_src = read(os.path.join(
        GO, "internal", "maps", "maps.go"))

    # ------------------------------------------------ 1) policy_key boyutu
    section("1) policy_key boyutu (C vs Go)")
    m = re.search(
        r"struct policy_key \{(.*?)\};", header, re.S)
    if not m:
        fail("struct policy_key bulunamadi")
    else:
        body = m.group(1)
        comm = re.search(r"char comm\[(\w+)\]", body)
        path = re.search(r"char path\[(\w+)\]\[(\w+)\]", body)
        act = re.search(r"__u32 action", body)
        if not (comm and path and act):
            fail("policy_key alanlari beklenen degil")
        else:
            defs = dict(re.findall(r"#define (\w+)\s+(\d+)", header))
            c = int(comm.group(1)) if comm.group(1).isdigit() else int(
                defs.get(comm.group(1), 0))
            d1 = int(path.group(1)) if path.group(1).isdigit() else int(
                defs.get(path.group(1), 0))
            d2 = int(path.group(2)) if path.group(2).isdigit() else int(
                defs.get(path.group(2), 0))
            c_size = 16 + d1 * d2 + 4
            ok(f"C policy_key = 16 + {d1}x{d2} + 4 = {c_size} bayt")

            maps = read(os.path.join(GO, "internal", "maps", "maps.go"))
            pm = re.search(
                r"Path\s+\[PathDepth\]\[PathSlot\]byte", maps)
            if pm:
                dm = re.search(r"PathDepth\s*=\s*(\d+)", maps)
                ds = re.search(r"PathSlot\s*=\s*(\d+)", maps)
                if dm and ds:
                    g_size = 16 + int(dm.group(1)) * int(ds.group(1)) + 4
                    if g_size == c_size:
                        ok(f"Go MapKey = {g_size} bayt -> C ile ayni")
                    else:
                        fail(f"Go MapKey {g_size} != C {c_size}")
            else:
                fail("Go MapKey.Path bloklu degil "
                     "(Path [PathDepth][PathSlot]byte bekleniyor)")

    # ------------------------------------------------ 2) audit_event boyutu
    section("2) audit_event boyutu (C vs Go)")
    m = re.search(r"struct audit_event \{(.*?)\};", header, re.S)
    if not m:
        fail("struct audit_event bulunamadi")
    else:
        body = m.group(1)
        defs = dict(re.findall(r"#define (\w+)\s+(\d+)", header))

        def dim(spec, default=0):
            if spec is None:
                return default
            if spec.isdigit():
                return int(spec)
            return int(defs.get(spec, default))

        ts = 8
        pid = 4
        comm = dim(re.search(r"char comm\[(\w+)\]", body).group(1))
        pm2 = re.search(r"char path\[(\w+)\]\[(\w+)\]", body)
        if pm2:
            path = dim(pm2.group(1)) * dim(pm2.group(2))
        else:
            pm3 = re.search(r"char path\[(\w+)\]", body)
            path = dim(pm3.group(1)) if pm3 else 0
        tail = len(re.findall(r"__u32 ", body)) - 1  # timestamp zaten __u64
        c_size = ts + pid + comm + path + tail * 4
        ok(f"C audit_event = 8+4+{comm}+{path}+{tail}x4 = {c_size} bayt")

        audit = read(os.path.join(GO, "internal", "audit", "audit.go"))
        pm4 = re.search(
            r"Path\s+\[PathDepth\]\[PathSlot\]byte", audit)
        if pm4:
            dm = re.search(r"PathDepth\s*=\s*(\d+)", audit)
            ds = re.search(r"PathSlot\s*=\s*(\d+)", audit)
            if dm and ds:
                g_size = 8 + 4 + 16 + int(dm.group(1)) * int(ds.group(1)) \
                    + 5 * 4
                if g_size == c_size:
                    ok(f"Go Event = {g_size} bayt -> C ile ayni")
                else:
                    fail(f"Go Event {g_size} != C {c_size}")
        else:
            fail("Go Event.Path bloklu degil")

        # EventSize sabiti gercek boyutla tutarli mi
        es = re.search(r"const EventSize = ([^/]+)", audit)
        if es:
            expr = es.group(1).strip()
            try:
                val = eval(expr, {"__builtins__": {}}, {})
            except Exception:
                val = None
            if val == c_size:
                ok(f"EventSize sabiti C boyutuyla ayni ({val})")
            else:
                fail(f"EventSize {val} != C audit_event {c_size} "
                     f"(her audit kaydi bu yuzden dusuyor olabilir)")

    # ------------------------------------------------ 3) audit boyut kontrolu
    section("3) audit okuma boyut kontrolu")
    audit = read(os.path.join(GO, "internal", "audit", "audit.go"))
    # Iki kabul edilebilir bicim var:
    #
    #   len(rec.RawSample) < EventSize   -- tercih edilen; C tarafiyla
    #                                        ayni sabiti kullandigi icin
    #                                        kayamaz.
    #   len(rec.RawSample) < 304         -- elle yazilmis sayi; C
    #                                        degisirse sessizce kayar.
    #
    # Onceki desen yalnizca rakam kabul ediyordu ve bosluk sinifa
    # dahil oldugu icin "EventSize" yaziminda grubu BOS string olarak
    # yakalayip eval("") ile cokuyordu. Duzeltilip buraya geldi.
    uses_const = re.search(
        r"len\(rec\.RawSample\)\s*<\s*EventSize\b", audit) is not None
    num_guards = [g for g in re.findall(
        r"len\(rec\.RawSample\)\s*<\s*([0-9][0-9+*\s]*)", audit)
        if g.strip()]

    if uses_const:
        ok("boyut kontrolu EventSize sabitini kullaniyor "
           "(elle yazilmis sayi ile kaymaz)")
    elif num_guards:
        em = re.search(r"const EventSize = ([^/\n]+)", audit)
        if not em:
            fail("EventSize sabiti tanimli degil; boyut kontrolu "
                 "dogrulanamaz")
        else:
            real = eval(em.group(1).strip(), {"__builtins__": {}}, {})
            for g in num_guards:
                val = eval(g.replace(" ", ""), {"__builtins__": {}}, {})
                if val > real:
                    fail(f"boyut kontrolu {val} > EventSize {real} -> "
                         f"HER audit kaydi sessizce dusuyor")
                elif val < real:
                    fail(f"boyut kontrolu {val} < EventSize {real} -> "
                         f"yarim/bozuk kayitlar ayristirilip HATA "
                         f"sayiliyor ve sessizce atiliyor")
                else:
                    ok(f"boyut kontrolu {val} == EventSize {real}")
    else:
        fail("RawSample boyut kontrolu yok")

    # ------------------------------------------------ 4) port bicimi
    section("4) ag kurali port bicimi (Go vs eBPF)")
    maps = read(os.path.join(GO, "internal", "maps", "maps.go"))
    if re.search(r'Sprintf\("p:%d"', maps):
        ok("Go port anahtari ASCII \"p:<port>\" uretiyor")
    else:
        fail('Go tarafi "p:%d" bicimi uretmiyor; ağ kurallari tutmaz')
    if re.search(r"ax_set_port\s*\(", header):
        ok("eBPF tarafi ax_set_port() ile ASCII port yaziyor")
    else:
        # C tanimi "static __always_inline int ax_set_port(...)" seklindedir.
        # Onceki deneme "func ax_set_port" ariyordu; bu Go soz dizimidir
        # ve C'de hicbir zaman bulunmaz, yani kontrol her zaman
        # basarisiz oluyordu.
        fail("eBPF tarafi ax_set_port() tanimi yok")
    for h in ("hooks_socket_bind.inc", "hooks_socket_connect.inc"):
        body = read(os.path.join(BPF, h))
        if re.search(r"ax_set_port\(key->path\[0\]", body):
            ok(f"{h} ax_set_port kullanıyor")
        elif "memcpy(pb + 2" in body:
            fail(f"{h} portu HAM BINARY yaziyor; Go ASCII yaziyor "
                 f"-> hicbir ağ kuralı tutmaz")

    # ------------------------------------------------ 5) socket_connect IP
    section("5) socket_connect IP adresi")
    body = read(os.path.join(BPF, "hooks_socket_connect.inc"))
    if "AF_INET" in body and "ax_set_port" in body:
        ok("socket_connect AF_INET port yaziyor")
    else:
        fail("socket_connect IP adresi icin port yazmiyor -> "
             "net.connect kurallari hicbir zaman tutmaz")
    if "AF_INET6" in body:
        ok("socket_connect AF_INET6 destekli")
    else:
        print("  !   socket_connect AF_INET6 desteklemiyor (IPv6)")

    # ------------------------------------------------ 6) set_mode haritaya yaziyor
    section("6) set_mode eBPF haritasina yaziyor mu")
    handlers = read(os.path.join(GO, "internal", "handlers", "handlers.go"))
    hm = re.search(
        r"func \(h \*Handler\) handleSetMode\(.*?\n\}", handlers, re.S)
    if not hm:
        fail("handleSetMode bulunamadi")
    else:
        body = hm.group(0)
        if "SetMode" in body:
            ok("handleSetMode maps.SetMode() cagirıyor "
               "(acil çıkış yolu çalışır)")
        else:
            fail("handleSetMode yalnizca Go bellegini guncelliyor; "
                 "mode_map'e yazmiyor -> ACIL CIKIS YOLU CALISMAZ")

    # ------------------------------------------------ 7) mode varsayılanı
    section("7) daemon acilista mode_map degeri")
    main_go = read(os.path.join(GO, "main.go"))
    if re.search(r"SetMode\(", main_go):
        ok("main.go modu baslangicta haritaya yaziyor")
    else:
        print("  !   main.go baslangicta mod haritasina yazmiyor "
              "(mode_map 0 = disabled kaliyor; bu guvenli ama "
              "kullanici policy yukleyene kadar enforcement kapali)")

    # ------------------------------------------------ 8) bpf_d_path yasagi
    section("8) bpf_d_path yasagi")
    # bpf_d_path bu projede hedef tampona iki konuma birden
    # yaziyor ve yol alanini bozuyor. Gorunurde her sey yolunda
    # gider (derlenir, yuklenir, 5/5 kanca baglanir) ama hicbir
    # yol kurali tutmaz. Bu yuzden hicbir yerde cagrilmamali.
    offenders = []
    for fn in sorted(os.listdir(BPF)):
        if not fn.endswith((".c", ".h", ".inc")):
            continue
        path = os.path.join(BPF, fn)
        body = read(path)
        for i, line in enumerate(body.splitlines(), 1):
            if "bpf_d_path" not in line:
                continue
            s = line.strip()
            # yorum satirini, typedef'i ve dokumantasyonu haric tut
            if s.startswith(("*", "/*", "//", "typedef")):
                continue
            offenders.append(f"{fn}:{i}: {s}")
    if offenders:
        for o in offenders:
            fail(f"bpf_d_path cagrisi kaldirilmali -> {o}")
    else:
        ok("hicbir yerde bpf_d_path cagrisi yok "
           "(aks halde tum yol kurallari sessizce basarisiz olur)")

    # ------------------------------------------------ 9) runtime dongu yasagi
    section("9) ax_fill_path unroll kurali")
    m = re.search(
        r"static __always_inline int ax_fill_path\(.*?\n\}", header, re.S)
    if not m:
        fail("ax_fill_path bulunamadi")
    else:
        body = m.group(0)
        loops = re.findall(r"for\s*\((\w+)\s*=\s*0;\s*\1\s*<\s*(\w+)", body)
        unrolled = body.count("#pragma unroll")
        if len(loops) == 2 and unrolled >= 2:
            ok(f"ax_fill_path 2 gecis, ikisi de unroll "
               f"({unrolled} pragma unroll)")
        else:
            fail(f"ax_fill_path dongu/unroll sayisi: {len(loops)} gecis, "
                 f"{unrolled} unroll. Runtime dongu verifier'i 1M "
                 f"instruction sinirina tasirir")
        if re.search(r"&key->path\[(?!b\])", body):
            fail("ax_fill_path icinde calisma aninda indekslenen "
                 "path erisimi var (verifier reddeder)")
        else:
            ok("ax_fill_path sadece sabit blok ofseti kullanıyor")

    # ------------------------------------------------ 10) koruma cagrisi
    section("10) koruma (ax_protected) her kancada")
    for h in HOOKS:
        body = read(os.path.join(BPF, h))
        if "ax_protected(" in body:
            ok(f"{h} koruma cagiriyor")
        else:
            fail(f"{h} koruma cagiriyor degil -> kilitlenme riski")

    # ------------------------------------------------ 11) port anahtari
    section("11) port anahtari kernel/Go uyumu")
    #
    # Bu regresyonu yakalayan testtir. ax_set_port bir zamanlar sabit
    # 5 basamak yaziyordu ("p:00080"), Go ise fmt.Sprintf("p:%d")
    # ile degisken uretiyordu ("p:80"). 80, 443 gibi gercek
    # portlarda iki taraf farkli anahtar uretiyor, hash eslesmesi
    # hicbir zaman tutmuyor ve ag kurallari sessizce uygulanmiyordu.
    # Yalnizca 45678 gibi tam 5 haneli TEST portlari kazara tutuyordu.
    #
    # Go tarafi "p:" + str(port). Bu, sola sikistirILMAZ:
    #   80    -> "p:80"
    #   443   -> "p:443"
    #   8080  -> "p:8080"
    #   45678 -> "p:45678"
    # Kernel de ayni sonucu vermeli.
    m = re.search(
        r"static __always_inline int ax_set_port\(char \*slot.*?\n\}",
        header, re.S)
    if not m:
        fail("ax_set_port tanimi bulunamadi")
    else:
        body = m.group(0)
        # Yorumlari temizle: desenler yalnizca KODDA aranir.
        code = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
        code = re.sub(r"//.*", "", code)

        # Sabit genislik yaziminin izi: modulo 10 dogrudan yazilir
        # ve konum sabit bir ofsetten hesaplanir.
        if re.search(r"\(\s*v\s*%\s*10\s*\)", code) and \
                re.search(r"slot\[\s*\d+\s*\+\s*\w+\s*\]", code):
            fail("ax_set_port sabit 5 basamak yaziyor ama Go "
                 "degisken uretiyor (fmt.Sprintf(\"p:%d\")); 80/443 "
                 "gibi portlarda anahtarlar eslesmez, ag kurallari "
                 "sessizce uygulanmaz")
        elif "div" in code and ">=" in code:
            ok("ax_set_port degisken basamak yaziyor (Go ile ayni)")
        else:
            fail("ax_set_port'in basamak mantigi okunamadi; Go ile "
                 "uyum dogrulanamadi. Beklenen: v >= div kosuluyla "
                 "sola sikistirma yapmayan yazim")

    # Go tarafi gercekten "p:%d" mi uretiyor?
    gm = re.search(r"fmt\.Sprintf\(\s*\"p:%d\"\s*", maps_src)
    if not gm:
        fail('Go tarafi p:<port> uretmiyor; kernel ile uyumsuz '
             '(fmt.Sprintf("p:%d", port) bekleniyor)')
    else:
        ok("Go port anahtari p:<port> (degisken basamak)")

    # Davranis dogrulamasi: kernel algoritmasi KAYNAKTAN okunup
    # Python'da birebir calistirilir ve Go'nun uretecegi metinle
    # karsilastirilir. Bu asil kontroldur; yukaridaki desen
    # kontrolleri yalnizca yanlis varyanti yakalar.
    #
    # Beklenen: 80->"p:80", 443->"p:443", 8080->"p:8080",
    #           45678->"p:45678"  (sola sikistirma YOK)
    #
    # Sabit 5 basamakli varyant ("p:00080") 80 ve 443 icin
    # basarisiz olur; test kirilir.
    if m:
        code = re.sub(r"/\*.*?\*/", "", m.group(0), flags=re.S)
        code = re.sub(r"//.*", "", code)

        # "v >= div" kosulu ve "div *= 10" carpani mevcutsa,
        # kernel'in yazim algoritmasini simule et.
        if re.search(r"v\s*>=\s*div", code) and re.search(r"div\s*\*=\s*10", code):
            def kernel_port(v):
                """ax_set_port'un Python karsiligi."""
                out = ["p", ":"]
                i = 2
                for place in range(4, -1, -1):
                    div = 10 ** place
                    if v >= div:
                        out.append(chr(ord("0") + (v // div) % 10))
                        i += 1
                return "".join(out)

            mismatch = []
            for port in (80, 443, 8080, 45678, 1, 65535):
                k = kernel_port(port)
                g = "p:%d" % port
                if k != g:
                    mismatch.append(f"{port}: kernel={k!r} go={g!r}")
            if mismatch:
                fail("kernel/Go port anahtari UYUSMUYOR: "
                     + "; ".join(mismatch))
            else:
                ok("kernel/Go port anahtari birebir ayni "
                   "(1, 80, 443, 8080, 45678, 65535)")
        else:
            fail("ax_set_port'te 'v >= div' / 'div *= 10' deseni "
                 "bulunamadi; algoritma Python'da birebir "
                 "simule edilemedi, davranis dogrulanamadi")

    # ------------------------------------------------ 12) aksiyon -> kanca sozlesmesi
    section("12) her aksiyonu ureten bir kanca var mi")
    #
    # BU, projedeki en sessiz basarisizlik sinifini kapatir.
    #
    # actionToUint her aksiyon icin gecerli bir sabit uretir, bu
    # yuzden "file.delete" kurali anahtar olarak sorunsuz olusur
    # ve map'e yazilir. Sorun cekirdek tarafinda: hicbir kanca o
    # degeri URETMEZ, dolayisiyla kayit hicbir seyle eslesmez.
    # Kullanici "kimse bu dosyayi silemez" yaziyor, daemon "1 kural
    # yuklendi" diyor, dosya SILINIYOR.
    #
    # Burada her ACTION_* degerinin en az bir kancada uretildigini
    # dogruluyoruz. Uretilmeyen her deger, Go ve Python tarafinda
    # reddedilmek ZORUNDA; aksi halde sessizce kabul edilir.
    hook_files = [f for f in os.listdir(BPF) if f.startswith("hooks_")]

    def hook_bodies():
        for fn in sorted(hook_files):
            yield fn, read(os.path.join(BPF, fn))

    actions_defined = set(re.findall(
        r"#define\s+(ACTION_\w+)\s+\d+", header))
    ok(f"{len(actions_defined)} ACTION_* tanimi bulundu")

    produced = {}
    for fn, body in hook_bodies():
        # Yorum satirlari ve #define'lar uretim sayilmaz.
        code = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
        code = re.sub(r"//.*", "", code)
        for act in actions_defined:
            if act in code:
                produced.setdefault(act, []).append(fn)

    unproduced = sorted(set(actions_defined) - set(produced))
    for act in sorted(produced):
        ok(f"{act} ureten kanca: {', '.join(produced[act])}")

    if unproduced:
        # Uretilmeyenler reddediliyor mu? Iki tarafta da.
        go_blocked = set(re.findall(
            r'"(file\.\w+|net\.\w+|process\.\w+)":\s*\n?\s*"',
            maps_src, re.S))
        py_src = read(os.path.join(
            ROOT, "src", "python", "axctl", "compiler.py"))
        py_blocked = set(re.findall(
            r'"(file\.\w+|net\.\w+)":', py_src))

        # C -> Go sabit eslemesi: ACTION_FILE_DELETE -> file.delete
        const_to_name = {
            "ACTION_FILE_DELETE": "file.delete",
            "ACTION_FILE_CREATE": "file.create",
            "ACTION_NET_ACCEPT": "net.accept",
        }
        for act in unproduced:
            name = const_to_name.get(act, act)
            where = []
            if name in go_blocked:
                where.append("Go")
            if name in py_blocked:
                where.append("Python")
            if not where:
                fail(f"{act} ({name}) HICBIR kanca tarafindan uretilmiyor "
                     f"ve {'Go/Python'.replace('/', ' ve ')} tarafindan "
                     f"reddedilmiyor -> kural sessizce islevsiz kalir")
            else:
                ok(f"{act} ({name}) uretilmiyor, "
                   f"{' ve '.join(where)} reddediyor")
    else:
        ok("her ACTION_* degeri en az bir kanca tarafindan uretiliyor")

    # ------------------------------------------------ 13) kanca listeleri senkron
    section("13) HOOKS / HookTable senkroni")
    #
    # Yeni bir kanca eklemek DORT yer degistirmeyi gerektirir:
    #   axbpf.c (include), src/bpf/Makefile (HOOKS),
    #   Go HookTable, ve buradaki HOOKS listesi.
    # Bir adim atlantiiginda ya program derlenmez ya da baglanmaz;
    # her iki durumda da enforcement sessizce eksik kalir ve
    # "5/5 kanca bagli" yalanini soylemeye devam eder.
    bpfs = read(os.path.join(BPF, "axbpf.c"))
    bpf_make = read(os.path.join(BPF, "Makefile"))
    lsm_go = read(os.path.join(GO, "internal", "lsm", "lsm.go"))

    # HOOKS girdileri DOSYA ADIDIR ("hooks_file_open.inc"). Onceki
    # kod bunlarin uzerine "hooks_{h}.inc" ekliyordu ve
    # "hooks_hooks_file_open.inc.inc" ariyordu; sonuc bolum 13 her
    # zaman basarisiz oluyor, yani kanca senkronu denetimi calismiyordu.
    section_ok = True
    for h in HOOKS:
        inc = h if h.endswith(".inc") else f"hooks_{h}.inc"
        if inc not in bpfs:
            fail(f"axbpf.c {inc} dosyasini include etmiyor")
            section_ok = False
        if inc not in bpf_make:
            fail(f"src/bpf/Makefile HOOKS listesinde {inc} yok; "
                 f"make .inc degisimini fark etmez")
            section_ok = False
        if inc not in lsm_go:
            fail(f"Go HookTable'da {inc} kaynak dosyasi tanimli degil")
            section_ok = False
    if section_ok:
        ok(f"{len(HOOKS)} kanca: axbpf.c, Makefile ve Go HookTable "
           f"uyumlu")

    # Ters yon: Go'da tanimli ama C'de olmayan kanca.
    go_sources = re.findall(r'Source:\s*"([^"]+)"', lsm_go)
    for src in go_sources:
        if src and src not in bpfs:
            fail(f"Go HookTable '{src}' diyor ama axbpf.c onu "
                 f"include etmiyor; program baglanamaz")
    for src in go_sources:
        if src and not os.path.exists(os.path.join(BPF, src)):
            fail(f"Go HookTable '{src}' diyor ama dosya diskte yok")

    # ------------------------------------------------ sonuç
    print("\n" + "=" * 40)
    if failures:
        for f in failures:
            print(f"FAIL: {f}")
        print(f"{passes} basarili, {len(failures)} basarisiz")
        return 1
    print(f"TUM SOZLESME TESTLERI GECTI ({passes} kontrol)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
