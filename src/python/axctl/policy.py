"""Politika dosya yönetimi."""

import shutil
from datetime import datetime
from pathlib import Path

import yaml

from axctl.config import load_config
from axctl.exceptions import PolicyError
from axctl.paths import get_backup_dir, get_policy_path


def load_policy(path: str | Path | None = None) -> dict:
    """Politika dosyasını yükler."""
    if path is None:
        path = get_policy_path()

    policy_path = Path(path)

    if not policy_path.exists():
        raise PolicyError(
            f"Politika dosyası bulunamadı: {policy_path}. "
            "Önce 'axctl init' çalıştırın."
        )

    try:
        with open(policy_path, "r", encoding="utf-8") as f:
            policy = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise PolicyError(f"YAML ayrıştırma hatası: {e}")

    if policy is None:
        raise PolicyError("Politika dosyası boş")

    return policy


def save_policy(path: str | Path, policy: dict) -> None:
    """Politika dosyasını kaydeder."""
    policy_path = Path(path)
    policy_path.parent.mkdir(parents=True, exist_ok=True)

    with open(policy_path, "w", encoding="utf-8") as f:
        yaml.dump(policy, f, default_flow_style=False,
                  allow_unicode=True, sort_keys=False)


def backup_policy(path: str | Path | None = None) -> Path:
    """Politika dosyasının zaman damgalı yedeğini alır."""
    if path is None:
        path = get_policy_path()

    policy_path = Path(path)
    if not policy_path.exists():
        raise PolicyError("Yedeklenecek politika dosyası yok")

    config = load_config()
    backup_dir = get_backup_dir()
    backup_dir.mkdir(parents=True, exist_ok=True)

    # Mikrosaniye cozunurlugu: saniye yeterli degil, arka arkaya
    # reload'larda yedekler birbirini ezmesin.
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    backup_path = backup_dir / f"policy_{timestamp}.yaml"
    shutil.copy2(policy_path, backup_path)

    # Yedek sayısını sınırla
    try:
        max_backups = int(config.get("backup_count", 10))
    except (TypeError, ValueError):
        max_backups = 10
    if max_backups > 0:
        backups = sorted(backup_dir.glob("policy_*.yaml"), reverse=True)
        for old in backups[max_backups:]:
            try:
                old.unlink()
            except OSError:
                pass

    return backup_path


def list_backups() -> list:
    """Yedekleri yeniden eskiye sırayla listeler."""
    backup_dir = get_backup_dir()
    if not backup_dir.exists():
        return []
    return sorted(backup_dir.glob("policy_*.yaml"), reverse=True)


def get_policy_stats(path: str | Path | None = None) -> dict:
    """Politika istatistiklerini döndürür."""
    if path is None:
        path = get_policy_path()

    policy_path = Path(path)
    if not policy_path.exists():
        return {"exists": False, "rules": 0, "labels": 0, "actions": []}

    policy = load_policy(policy_path)

    rules = policy.get("rules", [])
    labels = policy.get("labels", {})
    actions = sorted({r.get("action", "unknown") for r in rules})

    return {
        "exists": True,
        "path": str(policy_path),
        "rules": len(rules),
        "labels": len(labels),
        "actions": actions,
        "mode": policy.get("mode", "enforcing"),
    }
