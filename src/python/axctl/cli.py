"""AXlinux CLI - Sen YAML yaz, AXlinux uygulsın."""

import subprocess
import sys
import time

import click

from axctl import __version__
from axctl.compiler import compile_policy
from axctl.config import get_editor, load_config
from axctl.daemon_client import (
    get_logs,
    get_status,
    learn_report,
    learn_start,
    learn_stop,
    reload_policy,
    set_mode,
)
from axctl.exceptions import AxctlError, DaemonError, PolicyError, TemplateError
from axctl.formatter import (
    console,
    print_error,
    print_info,
    print_logs,
    print_simulation,
    print_status,
    print_success,
    print_warning,
)
from axctl.paths import ensure_layout, get_axlinux_home, get_policy_path
from axctl.policy import (
    backup_policy,
    get_policy_stats,
    list_backups,
    load_policy,
    save_policy,
)
from axctl.simulator import simulate_policy
from axctl.templates import apply_template, list_templates
from axctl.validator import validate_policy


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__, prog_name="axctl")
def cli():
    """AXlinux CLI - Sen YAML yaz, AXlinux uygulsın."""


@cli.command()
@click.option("--force", is_flag=True, help="Mevcut dizini sıfırlar")
def init(force):
    """AXlinux'u başlatır ve ~/.axlinux/ dizinini oluşturur."""
    import shutil

    axlinux_home = get_axlinux_home()
    policy_path = get_policy_path()

    if axlinux_home.exists() and not force:
        # init idempotent olmali: dizin varsa AMA politika dosyasi
        # yoksa (silinmis, yarim kurulum, elle temizlik) sessizce
        # cikis yapmak sistemi politika dosyasi olmadan birakirdi.
        # Sonrasi kullanici "axctl reload" calistirir, "Politika
        # dosyasi yok" hatasi alir ve nedenini bulamaz.
        # Dizin var, dosya yok -> dosyayi olusturup devam et.
        if policy_path.exists():
            print_warning(f"{axlinux_home} zaten mevcut. "
                          "--force ile sıfırlayabilirsiniz.")
            return
        print_warning(f"{axlinux_home} var ama {policy_path.name} "
                      "eksik; oluşturuluyor.")
        ensure_layout()
        save_policy(policy_path, {
            "version": 1,
            "mode": "enforcing",
            "rules": [],
        })
        print_success(f"{policy_path} oluşturuldu (boş politika, sistem serbest)")
        print_info("Hazır. 'axctl policy edit' ile politikanı yaz.")
        return

    if force and axlinux_home.exists():
        shutil.rmtree(axlinux_home)

    ensure_layout()
    save_policy(policy_path, {
        "version": 1,
        "mode": "enforcing",
        "rules": [],
    })

    config = load_config()

    print_success(f"{axlinux_home} oluşturuldu")
    print_success(f"{policy_path} oluşturuldu (boş politika, sistem serbest)")
    print_success(f"Mod: {config['mode']} (boş politika = kısıtlama yok)")
    print_info("Hazır. 'axctl policy edit' ile politikanı yaz.")


@cli.command("policy")
@click.argument("subcommand", type=click.Choice(["edit", "check", "simulate"]))
@click.option("--editor", help="Editör seçimi")
@click.option("--format", "output_format", type=click.Choice(["text", "json"]), default="text")
@click.option(
    "--file", "-f", "file_path", type=click.Path(exists=True, dir_okay=False),
    help="Aktif politika yerine bu dosyayı kullan (check/simulate)",
)
def policy_cmd(subcommand, editor, output_format, file_path):
    """Politika yönetimi: edit, check, simulate."""
    if subcommand == "edit":
        _policy_edit(editor)
    elif subcommand == "check":
        _policy_check(file_path)
    elif subcommand == "simulate":
        _policy_simulate(output_format, file_path)


def _policy_edit(editor: str | None):
    """Politika dosyasını editörde açar."""
    config = load_config()
    editor = editor or config.get("editor", "nano")
    policy_path = get_policy_path()

    if not policy_path.exists():
        print_error("Politika dosyası yok. Önce 'axctl init' çalıştırın.")
        sys.exit(1)

    subprocess.call([editor, str(policy_path)])


def _policy_check(file_path: str | None = None):
    """Politika doğrulaması yapar.

    file_path verilirse o dosya denetlenir. Bu secenek onceden
    YOKTU: "check" yalnizca aktif politikayi (/…/.axlinux/policy.yaml)
    denetleyebiliyordu, yani bir aday politikayi uygulamadan once
    dogrulamanin hicbir yolu yoktu. Politika ancak aktif edilip
    hata verildikten sonra denetlenebiliyordu; yani "check"
    komutu uygulama sonrasi hatayi gormekten baska bir ise
    yaramiyordu.
    """
    try:
        policy = load_policy(file_path)
        errors = validate_policy(policy)

        print_success("YAML syntax geçerli")
        print_success("Schema doğrulaması başarılı")

        # Istatistikler DENETLENEN politika icin olmali. Once
        # get_policy_stats() parametresiz cagriliyordu ve her
        # zaman AKTIF politikanin sayilarini gosteriyordu; yani
        # "policy check -f aday.yaml" adayin "3 kural" dedigi
        # halde aktif politikanin sayisini yazardi.
        stats = get_policy_stats(file_path) if file_path else get_policy_stats()
        print_success(f"{stats['rules']} kural, {stats['labels']} etiket bulundu")

        # compile_policy, sessiz basarisizligi onleyen denetimleri de
        # icerir: uygulanamaz yollar acik hata verir, korumali
        # surecleri hedefleyen kurallar uyarilir. Bu olmadan politika
        # "gecerli" gorunur ama hicbir seyi engellemez.
        import warnings as _warnings

        from axctl.compiler import compile_policy

        with _warnings.catch_warnings(record=True) as caught:
            _warnings.simplefilter("always")
            compiled = compile_policy(policy)

        print_success(
            f"Uygulanabilirlik denetimi: {len(compiled['rules'])} kural")

        for w in caught:
            print_warning(str(w.message))

        print_success("Çakışma yok")
        print_success("Öncelik sıralaması tamam")

        print_info("Politika geçerli. 'axctl reload' ile uygula.")

    except PolicyError as e:
        print_error(str(e))
        if e.errors:
            for err in e.errors:
                print_error(f"  - {err}")
        sys.exit(2)


def _policy_simulate(output_format: str, file_path: str | None = None):
    """Politika simülasyonu yapar."""
    try:
        simulation = simulate_policy(file_path)

        # Politika derlenemiyorsa simulator hatanin aciklamasini
        # dondurur. Simule etmek isteyen operator icin bu, komutun
        # hicbir sey yazdirmamaktan iyidir.
        if simulation.get("error"):
            print_error(simulation["error"])
            print_info("Simulasyon yapilamadi; politika duzeltilip "
                       "'axctl policy check -f <dosya>' ile dogrulanabilir.")
            sys.exit(2)

        if output_format == "json":
            console.print_json(data=simulation)
        else:
            print_simulation(simulation)

    except PolicyError as e:
        print_error(str(e))
        sys.exit(2)


@cli.command()
@click.option("--mode", type=click.Choice(["enforcing", "permissive", "disabled"]), help="Mod")
@click.option("--force-empty", is_flag=True, help="Boş politika yükle (acil durum)")
def reload(mode, force_empty):
    """Politikayi derler ve uygular."""
    try:
        if force_empty:
            empty_policy = {
                "version": 1, "mode": mode or "enforcing", "rules": [],
            }
            compiled = compile_policy(empty_policy)
            print_warning("Acil durum: Bos politika yukleniyor")
        else:
            policy_path = get_policy_path()
            if not policy_path.exists():
                # PolicyError -> exit_code 2. Once dogrudan
                # sys.exit(1) vardi; politika sorunlarinin kodu
                # 2, ama bu yol 1 donuyordu. Kullanici betik
                # yazarken "reload 1 donerse politika yok" ile
                # "reload 2 donerse politika bozuk" ayrimini
                # yapamiyordu.
                raise PolicyError(
                    f"Politika dosyasi yok: {policy_path}. "
                    f"Once 'axctl init' calistirin.")

            backup_policy(policy_path)
            policy = load_policy(policy_path)

            # compile_policy, sessiz basarisizligi onleyen
            # denetimleri de icerir. Yakalayip gosteriyoruz: derleyici
            # uyarisi, kuralin UYGULANMAYACAGI anlamina gelir ve
            # kullaniciya soylemelidir.
            import warnings as _warnings

            with _warnings.catch_warnings(record=True) as caught:
                _warnings.simplefilter("always")
                compiled = compile_policy(policy)

            for w in caught:
                print_warning(str(w.message))

        print_info("Politika derleniyor...")
        print_success(f"{len(compiled['rules'])} kural, "
                      f"{len(compiled['labels'])} etiket")

        reload_policy(compiled)
        print_success("eBPF map'lerine yazildi")
        print_success("LSM kancalari guncellendi")

        # --mode DOGRULANMASI ZORUNLU.
        #
        # Onceki surumde mode parametresi YALNIZCA --force-empty
        # dalinda kullaniliyordu; normal yolda hic kullanilmazdi.
        # Sonuc: "axctl reload --mode permissive" komutu "Yukleme
        # tamam" yaziyor, policy dosyasindaki "mode: enforcing"
        # gecerli kaliyor ve sistem ENGELLEMEYE DEVAM ediyordu.
        #
        # Bu bir konfor hatasi degil: acil durumda enforcement'i
        # durdurmanin yolu budur. Komut calistigini sanan operator,
        # sistemde engellenmeye devam eder.
        if mode:
            set_mode(mode)
            effective = mode
            print_success(f"Mod ayarlandi: {mode}")
        else:
            effective = compiled["mode"]

        print_success(f"Yukleme tamam. Mod: {effective}")

    except PolicyError as e:
        print_error(str(e))
        if e.errors:
            for err in e.errors:
                print_error(f"  - {err}")
        sys.exit(2)
    except DaemonError as e:
        print_error(str(e))
                # Sinifin exit_code'u kullanilir. Sabit 4 her zaman
        # "altyapi hatasi" diyordu; oysa DaemonAppError
        # exit_code=1 doner (uygulama seviyesi ret, orn.
        # "ogrenme modu zaten aktif").
        sys.exit(e.exit_code)


@cli.command()
@click.option("--json", "output_json", is_flag=True, help="JSON çıktı")
def status(output_json):
    """Sistem durumunu gösterir."""
    try:
        status_data = get_status()

        if output_json:
            console.print_json(data=status_data)
        else:
            print_status(status_data)

    except DaemonError as e:
        print_error(str(e))
                # Sinifin exit_code'u kullanilir. Sabit 4 her zaman
        # "altyapi hatasi" diyordu; oysa DaemonAppError
        # exit_code=1 doner (uygulama seviyesi ret, orn.
        # "ogrenme modu zaten aktif").
        sys.exit(e.exit_code)


@cli.command()
@click.option("--follow", "-f", is_flag=True, help="Canlı izleme")
@click.option("--filter", "filter_str", help="Filtre (örn: action=file.read,effect=deny)")
@click.option("--since", help="Zamandan beri (1h, 1d, 1w)")
@click.option("--limit", "-n", default=100, help="Maksimum kayıt sayısı")
@click.option("--json", "output_json", is_flag=True, help="JSON çıktı (status ile aynı)")
@click.option("--subject", help="İşlem adına göre filtre (örn: curl)")
@click.option("--action", help="Aksiyona göre filtre (örn: file.read)")
@click.option(
    "--effect",
    type=click.Choice(["allow", "deny", "allowed", "denied"], case_sensitive=False),
    help="Karara göre filtre (allow/deny; allowed/denied de kabul edilir)",
)
def logs(follow, filter_str, since, limit, output_json, subject, action, effect):
    """Audit log'u okur."""
    try:
        filters = {}
        if filter_str:
            for part in filter_str.split(","):
                if "=" in part:
                    key, value = part.split("=", 1)
                    filters[key.strip()] = value.strip()

        # Alan bazli secenekler --filter SOZLESMESINE cevrilir.
        # Once yalnizca --filter vardi; "axctl logs --effect denied"
        # yazmak click tarafindan "bilinmeyen secenek" hatasina
        # dusuyordu (rc=2). "status --json" varken "logs --json"
        # olmamasi da tutarsizdi: audit kayitlarini arac olarak
        # islemek isteyen kullanici elle metin ayiklamak
        # zorunda kaliyordu.
        if subject:
            filters["subject"] = subject
        if action:
            filters["action"] = action
        if effect:
            # Audit kayitlari "denied"/"allowed" yaziyor, --filter
            # yardimi ise "deny" ornegi gosteriyordu. Ikisi de
            # kabul edilsin ve DAIMONUN bekledigi deger gonderilsin
            # ("deny"/"allow"): kullanicinin yazdigi bicim degisse
            # de filtre hep calissin.
            filters["effect"] = (
                "deny" if effect.lower().startswith("den") else "allow"
            )

        # since AYRI gonderilir: sunucu "since"u bilinen bir
        # filtre alani olarak tanimaz. Filtreye karistirilirsa
        # sunucu "bilinmeyen filtre alani" uyarisi verir ve
        # --since sessizce etkisiz kalir.
        if since:
            filters.pop("since", None)

        # get_logs bir DICT doner: hem kayitlari hem de sunucunun
        # uygulamadigi filtre uyarisini tasir. Kayitlar "logs"
        # anahtarinin altindadir.
        payload = get_logs(filters=filters, limit=limit, since=since)
        log_entries = payload.get("logs", []) if isinstance(payload, dict) else []

        if output_json:
            console.print_json(data=payload)
        else:
            print_logs(log_entries)
        _warn_ignored_filters(payload)

        if follow:
            print_info("Canlı izleme başlatıldı. Durdurmak için Ctrl+C.")
            # GORULEN KAYITLARIN KIMLIGI TUTULUR.
            #
            # Onceki surum her saniye get_logs(limit=10) cagirip
            # son 10 kaydi oldugu gibi yaziyordu; kullanici ayni
            # satirlari tekrar tekrar goruyordu. Yeni kayitlar
            # (pid, timestamp, comm, path, action) imzasiyla
            # ayirt edilir; daha once gorulmus olanlar atlanir.
            seen = {log_key(e) for e in log_entries}
            try:
                while True:
                    time.sleep(1)
                    fresh = get_logs(filters=filters, limit=50,
                                     since=since)
                    new_logs = []
                    for entry in (fresh.get("logs", [])
                                  if isinstance(fresh, dict) else []):
                        k = log_key(entry)
                        if k in seen:
                            continue
                        seen.add(k)
                        new_logs.append(entry)
                    if new_logs:
                        print_logs(new_logs)
            except KeyboardInterrupt:
                print_info("İzleme durduruldu.")

    except DaemonError as e:
        print_error(str(e))
                # Sinifin exit_code'u kullanilir. Sabit 4 her zaman
        # "altyapi hatasi" diyordu; oysa DaemonAppError
        # exit_code=1 doner (uygulama seviyesi ret, orn.
        # "ogrenme modu zaten aktif").
        sys.exit(e.exit_code)


def log_key(entry: dict) -> tuple:
    """Bir log kaydinin kimligi.

    Ayirt edici olmasi gerekir: ayni surec ayni yolu ayni anda
    yeniden deneyebilir, ama kayitlar farkli zamanlarda farkli
    olaylari gosterir. Zaman damgasi tek basina yetmez (cift
    kayit ayni nanoyu alabilir), o yuzden tum alanlar birlikte
    kullanilir.
    """
    return (
        entry.get("timestamp"),
        entry.get("pid"),
        entry.get("comm"),
        entry.get("path"),
        entry.get("action"),
        entry.get("rule_id"),
    )


def _warn_ignored_filters(payload) -> None:
    """Sunucunun uygulamadigi filtre varsa kullaniciyi uyarir.

    Filtre sessizce yok sayilirsa kullanici "deny kayitlarini
    filtreledim" sanir ve listede allow kayitlari gorup dogru
    calistigini dusundugunu sanar.
    """
    warning = payload.get("filter_warning") if isinstance(payload, dict) else None
    if warning:
        print_warning(warning)


@cli.group()
def learn():
    """Öğrenme modu yönetimi."""
    pass


@learn.command("start")
@click.option("--days", default=3, help="Öğrenme süresi (gün)")
def learn_start_cmd(days):
    """Öğrenme modunu başlatır."""
    try:
        result = learn_start(days=days)
        # Sunucu artık gerçek bir bitiş zamanı döndürüyor. Eski
        # sürümde "3 gün izlenecek" yazıp hiçbir şey yapmıyordu.
        if result.get("until"):
            print_success(
                f"Öğrenme modu başlatıldı. {result.get('days', days)} "
                f"gün boyunca kayıt tutulacak.")
            print_info(f"Bitiş: {result['until']}")
        else:
            print_success("Öğrenme modu başlatıldı.")
        if result.get("how"):
            print_info(result["how"])
    except DaemonError as e:
        print_error(str(e))
                # Sinifin exit_code'u kullanilir. Sabit 4 her zaman
        # "altyapi hatasi" diyordu; oysa DaemonAppError
        # exit_code=1 doner (uygulama seviyesi ret, orn.
        # "ogrenme modu zaten aktif").
        sys.exit(e.exit_code)


@learn.command("stop")
def learn_stop_cmd():
    """Öğrenme modunu durdurur."""
    try:
        result = learn_stop()
        n = result.get("observations", 0)
        if n:
            print_success(
                f"Öğrenme modu durduruldu. {n} gözlem toplandı.")
            print_info("Raporu görmek için: axctl learn report")
        else:
            print_warning(
                "Öğrenme modu durduruldu ama HİÇ gözlem toplanmadı.")
            print_info(
                "Bu iki şeyden biri: sistemde hiç işlem yapılmadı, "
                "ya da gözlem toplama bağlantısı hiç kurulmadı. "
                "Çalışırken 'axctl status' ile learning_active "
                "alanını kontrol edin.")
    except DaemonError as e:
        print_error(str(e))
                # Sinifin exit_code'u kullanilir. Sabit 4 her zaman
        # "altyapi hatasi" diyordu; oysa DaemonAppError
        # exit_code=1 doner (uygulama seviyesi ret, orn.
        # "ogrenme modu zaten aktif").
        sys.exit(e.exit_code)


@learn.command("report")
@click.option("--format", "output_format", type=click.Choice(["text", "json"]), default="text")
def learn_report_cmd(output_format):
    """Öğrenme raporunu gösterir."""
    try:
        report = learn_report()

        if output_format == "json":
            console.print_json(data=report)
            return

        console.print("\n" + "=" * 40)
        console.print("[bold]Öğrenme Raporu[/bold]")
        if report.get("duration"):
            console.print(f"Süre: {report['duration']}")
        if report.get("total_count"):
            console.print(f"Toplam gözlem: {report['total_count']} "
                          f"({report.get('pattern_count', 0)} desen)")
        console.print("=" * 40)

        # Sunucu, ogrenme aktif DEGILSE ve hic gozlem yoksa
        # bunu acikca bildirir. Eski surumde anahtarlar uyusmadigi
        # icin rapor sessizce bos gorunuyordu; kullanici "sistemde
        # hicbir sey olmadi" saniyordu. Oysa hic gozlem
        # TOPLANMAMISTI. Bu ayrim, ogrenme aracinin varlik
        # nedenidir.
        if not report.get("active"):
            print_warning(
                report.get("message")
                or "Öğrenme modu aktif değil. "
                   "'axctl learn start' ile başlatın.")
        if not report.get("total_count"):
            print_info(
                "Gözlem yok. Öğrenme modu açıkken yaptığınız "
                "işlemler (dosya okuma, ağ bağlantısı) kaydedilir.")
            return

        for subject, actions in (report.get("observations") or {}).items():
            console.print(f"\n[bold]{subject}:[/bold]")
            for action, count in sorted(
                    actions.items(), key=lambda kv: -kv[1]):
                console.print(f"  → {action}: {count} kez")

        # suggestions DUNYAYA DUZ YAML metnidir. Onceki surumde
        # yaml.dump() ile bir kez daha sariliyordu ve cift
        # tirnakli, hatali bir blok basiliyordu. Metin oldugu
        # icin oldugu gibi yazilir.
        if report.get("suggestions"):
            console.print("\n[bold]Önerilen Politika:[/bold]")
            console.print(
                "[dim]Bu kuralları ~/.axlinux/policy.yaml içine "
                "yapıştırıp 'axctl policy check' ile doğrulayın.[/dim]")
            # SOFT_WRAP ZORUNLU. rich varsayilan olarak metni
            # ekran genisligine gore KAYDIRIR ve satirlari boler.
            # Oneriler tek satirlik YAML degerleri icerir:
            #     name: "ogrenme: curl file.read /usr/lib/x86_64...so"
            # ~82 karakterlik bu satir kaydirildiginda soyle oluyor:
            #     name: "ogrenme: curl file.read
            #     /usr/lib/x86_64...so"
            # Artik tirnak disinda bir YAML parcasi kaliyor ve dosya
            # AYRIŞMAZ.
            #
            # Dogrulama: ham suggestions YAML olarak GECERLI
            # (yaml.safe_load basarili, 1477 satir); yalnizca ekran
            # ciktisi bozuktu. Ama kullaniciya yapistirilacak metin
            # ekran ciktisidir: "policy.yaml'a yapistirip policy
            # check ile dogrulayin" diyen mesajin yaninda bozuk
            # metin gostermek, komutu calistirmaya calisan
            # kullaniciya hatayi bizzat uretmek demektir.
            console.print(report["suggestions"], soft_wrap=True)

    except DaemonError as e:
        print_error(str(e))
                # Sinifin exit_code'u kullanilir. Sabit 4 her zaman
        # "altyapi hatasi" diyordu; oysa DaemonAppError
        # exit_code=1 doner (uygulama seviyesi ret, orn.
        # "ogrenme modu zaten aktif").
        sys.exit(e.exit_code)


@cli.group()
def label():
    """Etiket yönetimi."""
    pass


@label.command("ls")
def label_ls():
    """Etiketleri listeler."""
    try:
        policy = load_policy()
        labels = policy.get("labels", {})

        if not labels:
            print_info("Henüz etiket tanımlanmamış.")
            return

        from rich.table import Table
        table = Table(title="Etiketler", border_style="cyan")
        table.add_column("Etiket", style="bold")
        table.add_column("İşlemler")

        for name, processes in labels.items():
            table.add_row(name, ", ".join(processes))

        console.print(table)

    except PolicyError as e:
        print_error(str(e))
        sys.exit(2)


@label.command("add")
@click.argument("name")
@click.argument("process", nargs=-1, required=True)
def label_add(name, process):
    """Etiket ekler."""
    try:
        policy = load_policy()
        labels = policy.get("labels", {})

        if name not in labels:
            labels[name] = []

        for proc in process:
            if proc not in labels[name]:
                labels[name].append(proc)

        policy["labels"] = labels
        save_policy(get_policy_path(), policy)

        print_success(f"Etiket '{name}' güncellendi: {', '.join(labels[name])}")

    except PolicyError as e:
        print_error(str(e))
        sys.exit(2)


@label.command("rm")
@click.argument("name")
def label_rm(name):
    """Bir etiketi siler.

    Once "label" komutu yalnizca "add" ve "ls" destekliyordu:
    etiket EKLENIRDI ama SILINEMEZDI. Politika elle
    duzeltilmeden bir etiketi kaldirmenin hicbir yolu yoktu;
    kullanici policy.yaml'i duzenlemek zorunda kaliyordu.
    """
    try:
        policy = load_policy()
        labels = policy.get("labels", {})

        if name not in labels:
            # Zaten yoksa hata: kullanici "silindi" sanip sistemi
            # yanlis varsaymasin.
            raise PolicyError(
                f"Etiket bulunamadı: {name}. "
                f"Mevcut etiketler: axctl label ls"
            )

        del labels[name]
        policy["labels"] = labels
        save_policy(get_policy_path(), policy)

        print_success(f"Etiket silindi: {name}")
        print_info("Değişikliği etkinleştirmek için: axctl reload")

    except PolicyError as e:
        print_error(str(e))
        sys.exit(e.exit_code)


@cli.command()
@click.argument("mode", type=click.Choice(["enforcing", "permissive", "disabled"]))
def mode(mode):
    """Modu değiştirir."""
    try:
        result = set_mode(mode)
        print_success(f"Mod değiştirildi: {mode}")

        if mode == "enforcing":
            print_warning("İhlal edilen eylemler engellenecek ve loglanacak.")
        elif mode == "permissive":
            print_info("İhlal edilen eylemler sadece loglanacak.")
        elif mode == "disabled":
            print_warning("Tüm kısıtlamalar kaldırıldı.")

    except DaemonError as e:
        print_error(str(e))
                # Sinifin exit_code'u kullanilir. Sabit 4 her zaman
        # "altyapi hatasi" diyordu; oysa DaemonAppError
        # exit_code=1 doner (uygulama seviyesi ret, orn.
        # "ogrenme modu zaten aktif").
        sys.exit(e.exit_code)


@cli.group()
def template():
    """Şablon yönetimi."""
    pass


@template.command("ls")
def template_ls():
    """Şablonları listeler."""
    templates = list_templates()

    from rich.table import Table
    table = Table(title="Şablonlar", border_style="cyan")
    table.add_column("İsim", style="bold")
    table.add_column("Açıklama")

    for t in templates:
        table.add_row(t["name"], t["description"])

    console.print(table)


@template.command("apply")
@click.argument("name")
def template_apply(name):
    """Şablon uygular."""
    try:
        path = apply_template(name)
        print_success(f"Şablon '{name}' uygulandı: {path}")
        print_info("'axctl reload' ile politikanı yükleyebilirsin.")
    except TemplateError as e:
        print_error(str(e))
        sys.exit(5)


def main():
    """CLI giriş noktası."""
    try:
        cli()
    except AxctlError as e:
        print_error(str(e))
        sys.exit(1)
    except KeyboardInterrupt:
        print_info("İptal edildi.")
        sys.exit(130)


if __name__ == "__main__":
    main()
