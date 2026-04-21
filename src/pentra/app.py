"""Uygulamanın QApplication ve sihirbaz başlatma noktası.

Şu an iskelet: PySide6 henüz entegre edilmedi. Faz 2'de gerçek
QApplication + Wizard devreye alınacak.
"""

from __future__ import annotations

import sys

from pentra import __app_name__, __version__


def main(argv: list[str] | None = None) -> int:
    """Uygulama girişi. Başarılı çıkışta 0 döner."""
    args = sys.argv if argv is None else argv
    del args  # placeholder; Faz 2'de CLI flag'leri parse edilecek

    print(f"{__app_name__} v{__version__}")
    print("Uygulama iskeleti. GUI Faz 2'de entegre edilecek.")
    return 0
