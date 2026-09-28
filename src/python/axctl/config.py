"""Yapılandırma yönetimi."""

import yaml

from axctl.exceptions import ConfigError
from axctl.paths import get_config_path

#: Eksik anahtarlar için varsayılanlar
DEFAULT_CONFIG = {
    "editor": "nano",
    "log_level": "info",
    "mode": "enforcing",
    "auto_reload": False,
    "backup_count": 10,
}

_VALID_MODES = {"enforcing", "permissive", "disabled"}


def load_config() -> dict:
    """Yapılandırmayı yükler; yoksa varsayılanları yazar."""
    config_path = get_config_path()

    if not config_path.exists():
        config = dict(DEFAULT_CONFIG)
        save_config(config)
        return config

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            user_config = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        raise ConfigError(f"Yapılandırma dosyası bozuk: {e}")
    except OSError as e:
        raise ConfigError(f"Yapılandırma okunamadı: {e}")

    if not isinstance(user_config, dict):
        raise ConfigError(
            f"Yapılandırma bir sözlük olmalı: {config_path}"
        )

    config = dict(DEFAULT_CONFIG)
    config.update(user_config)

    # Geçersiz değerleri varsayılana düşür, çökme yerine düzelt.
    if config.get("mode") not in _VALID_MODES:
        config["mode"] = DEFAULT_CONFIG["mode"]

    return config


def save_config(config: dict) -> None:
    """Yapılandırmayı kaydeder."""
    config_path = get_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)

    with open(config_path, "w", encoding="utf-8") as f:
        yaml.dump(config, f, default_flow_style=False, allow_unicode=True)


def get_editor() -> str:
    """Kullanılacak editörü belirler.

    Sıra: --editor bayrağı, $VISUAL, $EDITOR, yapılandırma, nano
    """
    import os
    for env in ("VISUAL", "EDITOR"):
        v = os.environ.get(env)
        if v:
            return v
    cfg = load_config()
    return cfg.get("editor") or "nano"
