"""Dosya ve soket yollarının tek kaynağı.

Tüm modüller buradan yol alır; AXLINUX_HOME ve AXLINUX_SOCKET
ortam değişkenleri her yerde geçerlidir. Testler AXLINUX_HOME ile
geçici dizin kullanabilir.
"""
import os
from pathlib import Path

#: Kullanıcı veri dizini (politika, yedekler, loglar)
AXLINUX_HOME_ENV = "AXLINUX_HOME"
#: axdaemon Unix socket yolu
AXLINUX_SOCKET_ENV = "AXLINUX_SOCKET"
#: Varsayılan soket
DEFAULT_SOCKET = "/run/axlinux/axdaemon.sock"


def get_axlinux_home() -> Path:
    """Kullanıcı veri dizinini döndürür.

    Sıra: $AXLINUX_HOME, yoksa ~/.axlinux
    """
    env = os.environ.get(AXLINUX_HOME_ENV)
    if env:
        return Path(env).expanduser()
    return Path.home() / ".axlinux"


def get_policy_path() -> Path:
    """Politika dosyasının tam yolunu döndürür."""
    return get_axlinux_home() / "policy.yaml"


def get_config_path() -> Path:
    """Yapılandırma dosyasının tam yolunu döndürür."""
    return get_axlinux_home() / "config.yaml"


def get_backup_dir() -> Path:
    """Politika yedekleri dizini."""
    return get_axlinux_home() / "backups"


def get_audit_dir() -> Path:
    """Yerel audit log dizini."""
    return get_axlinux_home() / "audit"


def get_socket_path() -> str:
    """axdaemon socket yolunu döndürür.

    Sıra: $AXLINUX_SOCKET, yoksa /run/axlinux/axdaemon.sock
    """
    env = os.environ.get(AXLINUX_SOCKET_ENV)
    if env:
        return env
    return DEFAULT_SOCKET


def ensure_layout() -> None:
    """Gerekli dizinleri oluşturur."""
    home = get_axlinux_home()
    for d in (home, get_backup_dir(), get_audit_dir()):
        d.mkdir(parents=True, exist_ok=True)
