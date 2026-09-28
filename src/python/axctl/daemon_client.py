"""axdaemon Unix socket istemcisi.

Soket yolu $AXLINUX_SOCKET ile ezilebilir; varsayılan değer
axctl.paths.DEFAULT_SOCKET içinde tanımlıdır.
"""
import json
import socket
from pathlib import Path

from axctl.exceptions import DaemonError
from axctl.paths import get_socket_path

#: Tek istek için bekleme süresi (saniye)
DEFAULT_TIMEOUT = 10.0


def _connect(timeout: float = DEFAULT_TIMEOUT) -> socket.socket:
    """Daemon socket'ine bağlanır."""
    path = get_socket_path()

    if not Path(path).exists():
        raise DaemonError(
            f"axdaemon çalışmıyor veya socket bulunamadı: {path}\n"
            "  Başlatmak için: sudo systemctl start axdaemon"
        )

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(path)
    except PermissionError as e:
        s.close()
        raise DaemonError(
            f"Socket izni yok: {path}\n"
            "  axctl'i root olarak çalıştırın ya da socket izinlerini "
            "düzenleyin."
        ) from e
    except ConnectionRefusedError as e:
        s.close()
        raise DaemonError(
            f"Bağlantı reddedildi: {path}\n"
            "  axdaemon çalışmıyor gibi görünüyor."
        ) from e
    except OSError as e:
        s.close()
        raise DaemonError(f"Socket'e bağlanılamadı ({path}): {e}") from e
    return s


def _send_request(method: str, params: dict | None = None,
                  timeout: float = DEFAULT_TIMEOUT) -> dict:
    """axdaemon'a JSON-RPC isteği gönderir, yanıtı döndürür."""
    request = {"method": method, "params": params or {}, "id": 1}

    s = _connect(timeout)
    try:
        s.sendall((json.dumps(request) + "\n").encode())

        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65535)
            if not chunk:
                break
            buf += chunk
    except socket.timeout as e:
        raise DaemonError(
            f"axdaemon yanıt vermedi ({timeout:.0f}s zaman aşımı)"
        ) from e
    except (BrokenPipeError, ConnectionResetError) as e:
        raise DaemonError("axdaemon bağlantıyı kapattı") from e
    finally:
        s.close()

    if not buf:
        raise DaemonError("axdaemon boş yanıt döndü")

    try:
        response = json.loads(buf.decode().strip())
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise DaemonError(f"Geçersiz yanıt: {e}") from e

    if isinstance(response, dict) and response.get("error"):
        raise DaemonError(f"Daemon hatası: {response['error']}")

    result = response.get("result") if isinstance(response, dict) else None
    if result is None:
        raise DaemonError("Daemon yanıtında 'result' alanı yok")
    return result


# --- Yüksek seviyeli API ---


def reload_policy(policy_json: dict) -> dict:
    """Derlenmiş politikayı daemon'a yükler."""
    return _send_request("reload_policy", {"policy": policy_json})


def get_status() -> dict:
    """Daemon durumunu döndürür."""
    return _send_request("get_status")


def get_logs(filters: dict | None = None, limit: int = 100) -> list:
    """Audit log kayıtlarını döndürür."""
    params: dict = {"limit": limit}
    if filters:
        params["filters"] = filters
    result = _send_request("get_logs", params)
    logs = result.get("logs", []) if isinstance(result, dict) else []
    return logs


def set_mode(mode: str) -> dict:
    """Çalışma modunu değiştirir."""
    return _send_request("set_mode", {"mode": mode})


def learn_start(days: int = 3) -> dict:
    """Öğrenme modunu başlatır."""
    return _send_request("learn_start", {"days": days})


def learn_stop() -> dict:
    """Öğrenme modunu durdurur."""
    return _send_request("learn_stop")


def learn_report() -> dict:
    """Öğrenme raporunu döndürür."""
    return _send_request("learn_report")


def is_available() -> bool:
    """Daemon erişilebilir mi?"""
    try:
        get_status()
        return True
    except DaemonError:
        return False
