"""Özel hata sınıfları."""


class AxctlError(Exception):
    """AXlinux CLI temel hata."""

    exit_code = 1


class PolicyError(AxctlError):
    """Politika doğrulama hatası.

    Detaylı hata listesi hem ``.errors`` alanında hem de mesaj
    metninde bulunur; böylece ``str(err)`` doğrudan kullanılabilir
    ve ayrıca ``.errors`` üzerinden programatik işlenebilir.
    """

    exit_code = 2

    def __init__(self, message: str, errors: list | None = None):
        self.errors = list(errors or [])
        if self.errors:
            joined = "\n".join(f"  - {e}" for e in self.errors)
            super().__init__(f"{message}\n{joined}")
        else:
            super().__init__(message)


class DaemonError(AxctlError):
    """Daemon ile iletişim hatası."""

    exit_code = 4


class ConfigError(AxctlError):
    """Yapılandırma hatası."""

    exit_code = 5


class TemplateError(AxctlError):
    """Şablon hatası."""

    exit_code = 5
