"""Çıktı biçimlendirme - Rich kütüphanesi ile."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


console = Console()


def print_success(message: str) -> None:
    """Başarı mesajı yazdırır."""
    console.print(f"[green]✓[/green] {message}")


def print_error(message: str) -> None:
    """Hata mesajı yazdırır."""
    console.print(f"[red]✗[/red] {message}")


def print_warning(message: str) -> None:
    """Uyarı mesajı yazdırır."""
    console.print(f"[yellow]⚠[/yellow] {message}")


def print_info(message: str) -> None:
    """Bilgi mesajı yazdırır."""
    console.print(f"[blue]ℹ[/blue] {message}")


def print_status(status: dict) -> None:
    """Durum tablosu yazdırır.

    Anahtar adları axdaemon'un get_status yanıtıyla birebir aynıdır.
    Sözleşme: src/go/axdaemon/internal/handlers/handlers.go (handleGetStatus)
    """
    table = Table(title="AXlinux Durumu", show_header=False, border_style="cyan")
    table.add_column("Alan", style="bold")
    table.add_column("Değer")

    mode = status.get("mode", "unknown")
    mode_color = {"enforcing": "red", "permissive": "yellow", "disabled": "green"}
    color = mode_color.get(mode, "white")

    rules = status.get("rules_loaded", 0)
    labels = status.get("labels_loaded", 0)

    table.add_row("Mod", f"[bold {color}]{mode}[/bold {color}]")
    table.add_row("Çalışma Süresi", status.get("uptime", "unknown"))
    table.add_row("Aktif Politika", f"{rules} kural, {labels} etiket")

    loaded = status.get("bpf_programs_loaded", 0)
    total = status.get("bpf_programs_total", 0)
    table.add_row("eBPF Programları", f"{loaded}/{total} yüklü")

    active = status.get("lsm_hooks_active", 0)
    htotal = status.get("lsm_hooks_total", 0)
    table.add_row("LSM Kancaları", f"{active}/{htotal} aktif")

    # Hangi kanca baglanmadi? "3/5 aktif" yazisi tek basina
    # yeterli degil; operator hangi kancayi test edecegini
    # bilmezse sorunu bulamaz.
    missing = status.get("hooks_missing") or []
    if missing:
        table.add_row(
            "Bağlanmayan Kancalar",
            "[bold yellow]" + ", ".join(missing) + "[/bold yellow]",
        )

    last = status.get("last_reload", "")
    table.add_row("Son Yükleme", last if last else "henüz yok")

    console.print(table)

    # Enforcement gercekten calisiyor mu? Kancalar bagli olsa bile
    # kernel 'bpf' LSM zincirinde degilse hicbir politika uygulanmaz.
    # Bunu saklamak guvenlik araci icin en tehlikeli hatadir.
    if status.get("enforcement_active") is False:
        notice = status.get("enforcement_notice", "")
        console.print()
        console.print(Panel(
            "[bold red]POLITIKA UYGULANMIYOR[/bold red]\n\n"
            + (notice or "bpf LSM etkin degil."),
            title="Dikkat",
            border_style="red",
        ))

    if status.get("map_allow_entries") is not None:
        console.print(
            f"\n[dim]eBPF map: {status.get('map_allow_entries', 0)} allow, "
            f"{status.get('map_deny_entries', 0)} deny kayıt[/dim]"
        )

    if status.get("audit_log_count") is not None:
        console.print(
            f"[dim]Audit log: {status['audit_log_count']} kayıt "
            f"(deny: {status.get('audit_denied_count', 0)}, "
            f"allow: {status.get('audit_allowed_count', 0)})[/dim]"
        )

    # Audit sagligi ayri bir panel olarak gosterilir. Sayi sifir
    # oldugunda "hicbir olay olmadi" ile "dongu oldu" ayirt
    # edilemez; enforcement calisiyor olsa bile audit olmus
    # durumda operator korundugunu sanar.
    if status.get("audit_healthy") is False:
        notice = status.get("audit_notice", "")
        # Kalici olarak yazilamayan kayitlar varsa onlari ayrica
        # belirt: enforcement karar verdi ama kanit KAYDEDILMEDI.
        lost = status.get("audit_send_failures", 0)
        lost_line = (
            f"\n\n[bold red]{lost} kayıt kalıcı olarak yazılamadı.[/bold red] "
            "Denetim izinde boşluk var; bu kararlar kanıtlanamaz."
            if lost else ""
        )
        console.print()
        console.print(Panel(
            "[bold yellow]AUDIT AKIŞI DURDU[/bold yellow]\n\n"
            "Politika uygulanmaya devam ediyor ama kararlar "
            "[bold]kaydedilmiyor[/bold].\nGeçmiş deneme ve ihlal "
            "kanıtı tutulamaz." + lost_line + "\n\n"
            + (notice or "perf okuma döngüsü sonlandı."),
            title="Dikkat",
            border_style="yellow",
        ))

    if status.get("learning_active"):
        console.print(
            f"[dim]Öğrenme modu: AKTİF "
            f"({status.get('learning_observations', 0)} gözlem)[/dim]"
        )


def print_simulation(simulation: dict) -> None:
    """Simülasyon sonucu yazdırır."""
    mode_color = {"enforcing": "red", "permissive": "yellow", "disabled": "green"}
    mode = simulation.get("mode", "enforcing")

    console.print(Panel(
        f"[bold]Mod:[/bold] [{mode_color.get(mode, 'white')}]{mode}[/{mode_color.get(mode, 'white')}]\n"
        f"[bold]Toplam kural:[/bold] {simulation['total_rules']}\n"
        f"[bold]Etiket:[/bold] {simulation['total_labels']}",
        title="Politika Simülasyonu",
        border_style="cyan",
    ))

    console.print()

    for i, rule in enumerate(simulation["rules"], 1):
        effect_color = "green" if rule["effect"] == "ALLOW" else "red"
        subjects_str = ", ".join(rule["subjects"])

        console.print(f"[bold][{i}][/bold] {rule['name']}")
        console.print(f"    subject: {subjects_str}")
        console.print(f"    object: {rule['object']}")
        console.print(f"    action: {rule['action']}")
        console.print(f"    effect: [{effect_color}]{rule['effect']}[/{effect_color}]")
        # Korumali surece yazilan kurallar etkisizdir. Bunu
        # belirtmezsek kullanici politikasi yukler, daemon
        # reddeder ve neden calismadigini anlamaz.
        if rule.get("effective") is False:
            console.print("    [yellow]ETKİSİZ: hedef süreçler korumalı[/yellow]")
        console.print()

    if simulation.get("affected_processes"):
        console.print(f"[dim]Etkilenen işlemler: {', '.join(simulation['affected_processes'])}[/dim]")

    # Etkisiz kurallar ozetlenir: kullanici simulasyonu okuyup
    # "her sey yolunda" sanmasin.
    ineffective = simulation.get("ineffective_rules") or []
    if ineffective:
        console.print()
        console.print(Panel(
            "\n".join(
                f"• {r['name']} → {', '.join(r['blocked_subjects'])}"
                for r in ineffective
            ),
            title="Etkisiz kurallar (korumalı süreç)",
            border_style="yellow",
        ))
        console.print(
            "[dim]Bu kurallar yazılıdır ama uygulanmaz: hedef süreçler "
            "kurtarma yoludur ve korumalıdır.[/dim]"
        )

    if simulation.get("conflicts"):
        console.print()
        for conflict in simulation["conflicts"]:
            print_warning(conflict)


def print_logs(logs: list) -> None:
    """Log kayıtlarını tablo olarak yazdırır."""
    if not logs:
        console.print("[dim]Log kaydı yok.[/dim]")
        return

    table = Table(title="Audit Log", border_style="cyan")
    table.add_column("Zaman", style="dim")
    table.add_column("İşlem")
    table.add_column("Nesne")
    table.add_column("Aksiyon")
    table.add_column("Karar")

    for log in logs:
        # get_logs RPC'si DUZ SATIR dondurur; ic ice axlog semasi
        # DEGIL. Onceki kod burada log["subject"]["comm"] ve
        # log["timestamp"][:19] bekliyordu, ikisi de yanlis:
        #   - subject/objekt anahtarlari sunucuda hic yok -> sessiz
        #     bos hucre
        #   - timestamp bir uint64 (ktime), string degil -> Python
        #     "'int' object is not subscriptable" ile audit
        #     GORUNTULEME tamamen cokuyordu.
        #
        # Yani enforcement calisiyor olsa bile operator kayitlari
        # hicbir zaman goremiyordu. Guvenlik aracinda kanit
        # gorunmezse kanit yoktur.
        decision = _log_decision_name(log)
        decision_color = "red" if decision == "denied" else "green"
        comm = log.get("comm", "") or log.get("subject", "")
        path = log.get("path", "") or log.get("object", "")
        if isinstance(path, dict):
            path = path.get("path", "")
        if isinstance(comm, dict):
            comm = comm.get("comm", "")

        table.add_row(
            _format_log_time(log.get("timestamp", 0)),
            str(comm),
            str(path)[:40],
            _format_log_action(log.get("action", 0)),
            f"[{decision_color}]{decision.upper()}[/{decision_color}]",
        )

    console.print(table)


def _log_decision_name(log: dict) -> str:
    """Karar degerini isme cevirir.

    Sunucu karari NUMERIC dondurur (DECISION_ALLOWED=0,
    DECISION_DENIED=1). Metin olarak geliyorsa oldugu gibi
    kullanilir; boylece iki yol da calisir.
    """
    d = log.get("decision", "")
    if isinstance(d, str):
        return d or "unknown"
    try:
        return "denied" if int(d) == 1 else "allowed"
    except (TypeError, ValueError):
        return "unknown"


def _format_log_action(action) -> str:
    """Aksiyonu isme cevirir (sayisal gelirse)."""
    if isinstance(action, str):
        return action
    names = {
        1: "file.read", 2: "file.write", 3: "file.execute",
        4: "file.delete", 5: "file.create",
        6: "net.connect", 7: "net.bind", 8: "net.accept",
        9: "process.exec",
    }
    return names.get(int(action), f"action({action})")


def _format_log_time(ts) -> str:
    """ktime damgasini okunur hale getirir.

    timestamp musteriye gonderilirken SISTEMDEN ALINAN bir
    Unix zamani degil, bpf_ktime_get_ns degeridir (boot'tan
    itibaren monotonik nanosaniye). Bu tam olarak JSONL tarafinda
    alinan zaman DEGILDIR; orada axlog kaydin ALDIGI zaman
    yazilir. Burada ayni islem yapilamaz - elimizde boot ani
    yoktur - ama operatora "boot'tan bu kadar sure" demek,
    saat:dakika gostermekten hem daha dogru hem daha faydalidir.
    """
    try:
        ns = int(ts)
    except (TypeError, ValueError):
        return str(ts)
    if ns <= 0:
        return "-"
    sec = ns // 1_000_000_000
    if sec < 60:
        return f"boot+{sec}s"
    if sec < 3600:
        return f"boot+{sec // 60}m{sec % 60}s"
    return f"boot+{sec // 3600}h{(sec % 3600) // 60}m"


def print_validation_result(errors: list) -> None:
    """Doğrulama sonucunu yazdırır."""
    if not errors:
        print_success("Politika geçerli")
        return

    for error in errors:
        print_error(error)
