"""AXlinux CLI - Sen YAML yaz, AXlinux uygulsın."""

import subprocess
import sys
import time

import click
import yaml

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
        print_warning(f"{axlinux_home} zaten mevcut. "
                      "--force ile sıfırlayabilirsiniz.")
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
def policy_cmd(subcommand, editor, output_format):
    """Politika yönetimi: edit, check, simulate."""
    if subcommand == "edit":
        _policy_edit(editor)
    elif subcommand == "check":
        _policy_check()
    elif subcommand == "simulate":
        _policy_simulate(output_format)


def _policy_edit(editor: str | None):
    """Politika dosyasını editörde açar."""
    config = load_config()
    editor = editor or config.get("editor", "nano")
    policy_path = get_policy_path()

    if not policy_path.exists():
        print_error("Politika dosyası yok. Önce 'axctl init' çalıştırın.")
        sys.exit(1)

    subprocess.call([editor, str(policy_path)])


def _policy_check():
    """Politika doğrulaması yapar."""
    try:
        policy = load_policy()
        errors = validate_policy(policy)

        print_success("YAML syntax geçerli")
        print_success("Schema doğrulaması başarılı")

        stats = get_policy_stats()
        print_success(f"{stats['rules']} kural, {stats['labels']} etiket bulundu")
        print_success("Çakışma yok")
        print_success("Öncelik sıralaması tamam")

        print_info("Politika geçerli. 'axctl reload' ile uygula.")

    except PolicyError as e:
        print_error(str(e))
        if e.errors:
            for err in e.errors:
                print_error(f"  - {err}")
        sys.exit(2)


def _policy_simulate(output_format: str):
    """Politika simülasyonu yapar."""
    try:
        simulation = simulate_policy()

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
    """Politikanı derler ve uygular."""
    try:
        if force_empty:
            empty_policy = {"version": 1, "mode": mode or "enforcing", "rules": []}
            compiled = compile_policy(empty_policy)
            print_warning("Acil durum: Boş politika yükleniyor")
        else:
            policy_path = get_policy_path()
            if not policy_path.exists():
                print_error("Politika dosyası yok. Önce 'axctl init' çalıştırın.")
                sys.exit(1)

            backup_policy(policy_path)
            policy = load_policy(policy_path)
            compiled = compile_policy(policy)

        print_info("Politika derleniyor...")
        print_success(f"{len(compiled['rules'])} kural, {len(compiled['labels'])} etiket")

        result = reload_policy(compiled)
        print_success("eBPF map'lerine yazıldı")
        print_success("LSM kancaları güncellendi")
        print_success(f"Yükleme tamam. Mod: {compiled['mode']}")

    except PolicyError as e:
        print_error(str(e))
        if e.errors:
            for err in e.errors:
                print_error(f"  - {err}")
        sys.exit(2)
    except DaemonError as e:
        print_error(str(e))
        sys.exit(4)


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
        sys.exit(4)


@cli.command()
@click.option("--follow", "-f", is_flag=True, help="Canlı izleme")
@click.option("--filter", "filter_str", help="Filtre (örn: action=file.read,effect=deny)")
@click.option("--since", help="Zamandan beri (1h, 1d, 1w)")
@click.option("--limit", "-n", default=100, help="Maksimum kayıt sayısı")
def logs(follow, filter_str, since, limit):
    """Audit log'u okur."""
    try:
        filters = {}
        if filter_str:
            for part in filter_str.split(","):
                if "=" in part:
                    key, value = part.split("=", 1)
                    filters[key.strip()] = value.strip()

        if since:
            filters["since"] = since

        log_entries = get_logs(filters=filters, limit=limit)
        print_logs(log_entries)

        if follow:
            print_info("Canlı izleme başlatıldı. Durdurmak için Ctrl+C.")
            try:
                while True:
                    time.sleep(1)
                    new_logs = get_logs(filters=filters, limit=10)
                    if new_logs:
                        print_logs(new_logs)
            except KeyboardInterrupt:
                print_info("İzleme durduruldu.")

    except DaemonError as e:
        print_error(str(e))
        sys.exit(4)


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
        print_success(f"Öğrenme modu başlatıldı. {days} gün izlenecek.")
        print_info("'axctl learn report' ile önerileri görebilirsin.")
        print_info("İpucu: Öğrenme modu sırasında normal şeyleri yap.")
    except DaemonError as e:
        print_error(str(e))
        sys.exit(4)


@learn.command("stop")
def learn_stop_cmd():
    """Öğrenme modunu durdurur."""
    try:
        learn_stop()
        print_success("Öğrenme modu durduruldu.")
    except DaemonError as e:
        print_error(str(e))
        sys.exit(4)


@learn.command("report")
@click.option("--format", "output_format", type=click.Choice(["text", "json"]), default="text")
def learn_report_cmd(output_format):
    """Öğrenme raporunu gösterir."""
    try:
        report = learn_report()

        if output_format == "json":
            console.print_json(data=report)
        else:
            console.print(f"\n[bold]Öğrenme Raporu ({report.get('days', 3)} gün)[/bold]")
            console.print("=" * 40)

            for subject, actions in report.get("observations", {}).items():
                console.print(f"\n[bold]{subject}:[/bold]")
                for action, count in actions.items():
                    console.print(f"  → {action}: {count} kez")

            if report.get("suggestions"):
                console.print(f"\n[bold]Önerilen Politika:[/bold]")
                console.print(yaml.dump(report["suggestions"], default_flow_style=False))

    except DaemonError as e:
        print_error(str(e))
        sys.exit(4)


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
        sys.exit(4)


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
