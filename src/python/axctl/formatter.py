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

    table.add_row("Mod", f"[bold {color}]{mode}[/{color}]")
    table.add_row("Çalışma Süresi", status.get("uptime", "unknown"))
    table.add_row("Aktif Politika", f"{rules} kural, {labels} etiket")

    loaded = status.get("bpf_programs_loaded", 0)
    total = status.get("bpf_programs_total", 0)
    table.add_row("eBPF Programları", f"{loaded}/{total} yüklü")

    active = status.get("lsm_hooks_active", 0)
    htotal = status.get("lsm_hooks_total", 0)
    table.add_row("LSM Kancaları", f"{active}/{htotal} aktif")

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
        console.print()

    if simulation.get("affected_processes"):
        console.print(f"[dim]Etkilenen işlemler: {', '.join(simulation['affected_processes'])}[/dim]")

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
        decision = log.get("decision", "unknown")
        decision_color = "red" if decision == "denied" else "green"

        table.add_row(
            log.get("timestamp", "")[:19],
            log.get("subject", {}).get("comm", ""),
            log.get("object", {}).get("path", "")[:40],
            log.get("action", ""),
            f"[{decision_color}]{decision.upper()}[/{decision_color}]",
        )

    console.print(table)


def print_validation_result(errors: list) -> None:
    """Doğrulama sonucunu yazdırır."""
    if not errors:
        print_success("Politika geçerli")
        return

    for error in errors:
        print_error(error)
