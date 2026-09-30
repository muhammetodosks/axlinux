"""Özel hata sınıfları."""


# CIKIS KODU SEMASI (betikler bunlara guvenir)
# ---------------------------------------------
#   0  basari
#   1  AxctlError / DaemonAppError  -> gecersiz kullanim ya da
#                                       daemon'in reddettigi istek
#                                       (orn. "ogrenme modu zaten aktif")
#   2  PolicyError   -> politika dosyasi yok, YAML bozuk, sema hatasi
#   4  DaemonError   -> altyapi: soket yok, baglanilamiyor,
#                       axdaemon kapali
#   5  ConfigError / TemplateError -> yapilandirma veya sablon hatasi
#
# Bu ayrim operasyonel olarak onemli: 4 "makineyi kontrol et"
# demek, 1 "komutu dogru yaz" demek. Once bircok yol sabit 1
# donuyordu ve bu ayrim yapilamiyordu; ayrica politika hatasi
# olan reload, politika dosyasi yokken 1 donuyordu (2 olmali).
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


class DaemonAppError(DaemonError):
    """Daemon'in UYGULAMA seviyesinde reddettigi istek.

    Once tum daemon hatalari tek sinifti: exit_code 4. Bu iki
    durumu birbirine karistiriyordu.

      - "ogrenme modu zaten aktif"   -> kullanici bunu ZATEN
        baslatmis, yani bir sey yapmasi gerekiyor
      - "socket izni yok" / "baglanamadi" -> altyapi hatasi

    Ikisi de "DaemonError: {dict}" olarak basiliyordu. Cozumun
    icinde ham Python sozlugu gorunuyordu:
        x Daemon hatasi: {'code': -32000, 'message': '...'}
    Kullanici ne oldugunu okuyamiyor, komutun neden basarisiz
    oldugunu anlayamiyor ve exit code 4 "altyapi hatasi" ima
    ettigi icin uygulama hatasini da arıyor.

    Bu sinif mesaji temizler, sozlugu gizler ve ayri bir exit
    code verir.
    """

    exit_code = 1



class ConfigError(AxctlError):
    """Yapılandırma hatası."""

    exit_code = 5


class TemplateError(AxctlError):
    """Şablon hatası."""

    exit_code = 5
