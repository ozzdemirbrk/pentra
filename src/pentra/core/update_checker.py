"""GitHub Releases üzerinden yeni sürüm kontrolü.

Arka plan QThread'de çalışır. Yeni sürüm varsa `update_available` sinyalini
yayar; UI bu sinyale bağlanıp kullanıcıya küçük bir bildirim gösterir.

Tasarım kararları:
    - İnternet yoksa sessizce geçer (uygulamanın offline çalışma prensibini bozmaz)
    - 5 saniye timeout — kullanıcıyı geciktirmez
    - Pre-release sürümler dahil edilmez (sadece stable release'ler sayılır)
    - Yanlış yapılandırılmış yanıtlara karşı savunmacı parsing
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QThread, Signal

from pentra import __github_repo__, __version__

_GITHUB_API_URL: str = f"https://api.github.com/repos/{__github_repo__}/releases/latest"
_TIMEOUT_SEC: float = 5.0
_USER_AGENT: str = f"Pentra/{__version__} (update-check)"


class UpdateChecker(QThread):
    """GitHub Releases API'sini arka planda sorgular.

    Kullanım::

        checker = UpdateChecker()
        checker.update_available.connect(on_update)
        checker.start()
    """

    #: (yeni_sürüm, release_url) parametreleriyle yayılır
    update_available = Signal(str, str)

    #: Hata oluşursa (log için — UI göstermez)
    check_failed = Signal(str)

    def run(self) -> None:  # Qt'nin beklediği isim
        # Lazy import — requests ağ hatasında thread sessizce çıksın
        try:
            import requests
        except ImportError:
            self.check_failed.emit("requests kütüphanesi yok")
            return

        try:
            response = requests.get(
                _GITHUB_API_URL,
                timeout=_TIMEOUT_SEC,
                headers={"User-Agent": _USER_AGENT, "Accept": "application/vnd.github+json"},
            )
        except requests.RequestException as e:
            # Offline / DNS hatası / timeout — sessiz geç
            self.check_failed.emit(f"Ağ hatası: {e}")
            return

        if response.status_code != 200:
            self.check_failed.emit(f"HTTP {response.status_code}")
            return

        try:
            data: dict[str, Any] = response.json()
        except ValueError:
            self.check_failed.emit("Geçersiz JSON")
            return

        latest_tag: str = str(data.get("tag_name", "")).lstrip("vV")
        html_url: str = str(data.get("html_url", ""))
        prerelease: bool = bool(data.get("prerelease", False))

        if not latest_tag or not html_url:
            self.check_failed.emit("tag_name veya html_url eksik")
            return

        if _is_newer(latest_tag, __version__, allow_prerelease=prerelease):
            self.update_available.emit(latest_tag, html_url)


def _is_newer(
    remote: str, local: str, *, allow_prerelease: bool = False,
) -> bool:
    """remote > local ise True.

    - `packaging.version.Version` kullanır (PEP 440 uyumlu)
    - Karşılaştırma yapılamazsa (exotic tag) güvenli varsayılan: False
    - `allow_prerelease=False` ise pre-release remote'lar güncellenme olarak sayılmaz
    """
    try:
        from packaging.version import InvalidVersion, Version
    except ImportError:
        return False

    try:
        remote_ver = Version(remote)
        local_ver = Version(local)
    except InvalidVersion:
        return False

    if remote_ver.is_prerelease and not allow_prerelease:
        # Uzaktaki pre-release; kullanıcı stable kullanıyorsa önerme
        if not local_ver.is_prerelease:
            return False

    return remote_ver > local_ver
