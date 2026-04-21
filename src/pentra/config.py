"""Uygulama genelinde kullanılan sabitler ve varsayılan ayarlar.

Kullanıcı tercihleri (tema, dil, son hedef) burada DEĞİL;
%APPDATA%/Pentra/config.json içinde tutulur.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

# ---------------------------------------------------------------------
# Uygulama meta
# ---------------------------------------------------------------------
APP_NAME: Final[str] = "Pentra"
ORG_NAME: Final[str] = "Pentra"

# ---------------------------------------------------------------------
# Yol sabitleri (Windows)
# ---------------------------------------------------------------------
def get_appdata_dir() -> Path:
    """%APPDATA%/Pentra dizinini döndürür, yoksa oluşturur."""
    import os

    base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    path = base / APP_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_desktop_dir() -> Path:
    """Kullanıcı masaüstü dizinini döndürür. Rapor çıktıları buraya yazılır."""
    return Path.home() / "Desktop"


# ---------------------------------------------------------------------
# Tarama sabitleri
# ---------------------------------------------------------------------
# Rate limit — paket/saniye. Kullanıcı ağında DoS etkisi yaratmamak için.
DEFAULT_RATE_LIMIT_PPS: Final[int] = 500
MAX_RATE_LIMIT_PPS: Final[int] = 2000

# Zaman aşımları (saniye)
DEFAULT_SCAN_TIMEOUT_SEC: Final[int] = 7200  # 2 saat (derin tarama)
DEFAULT_HOST_TIMEOUT_SEC: Final[int] = 30
DEFAULT_CONNECT_TIMEOUT_SEC: Final[int] = 5

# Özel ağ aralıkları (RFC1918 + loopback)
# scope_validator.py bu listeye karşı doğrulama yapar.
PRIVATE_NETWORK_RANGES: Final[tuple[str, ...]] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
)

# ---------------------------------------------------------------------
# Loglama
# ---------------------------------------------------------------------
LOG_FILE_MAX_BYTES: Final[int] = 10 * 1024 * 1024  # 10 MB
LOG_FILE_BACKUP_COUNT: Final[int] = 5
