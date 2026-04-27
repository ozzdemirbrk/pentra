"""Constants and default settings used across the application.

User preferences (theme, language, last target) are NOT stored here;
they live in %APPDATA%/Pentra/config.json.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

# ---------------------------------------------------------------------
# Application metadata
# ---------------------------------------------------------------------
APP_NAME: Final[str] = "Pentra"
ORG_NAME: Final[str] = "Pentra"


# ---------------------------------------------------------------------
# Path constants (Windows)
# ---------------------------------------------------------------------
def get_appdata_dir() -> Path:
    """Return the %APPDATA%/Pentra directory, creating it if missing."""
    import os

    base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    path = base / APP_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_desktop_dir() -> Path:
    """Return the user's desktop directory. Report output is written here."""
    return Path.home() / "Desktop"


# ---------------------------------------------------------------------
# Scan constants
# ---------------------------------------------------------------------
# Rate limit — packets/second. Prevents unintended DoS on the user's network.
DEFAULT_RATE_LIMIT_PPS: Final[int] = 500
MAX_RATE_LIMIT_PPS: Final[int] = 2000

# Timeouts (seconds)
DEFAULT_SCAN_TIMEOUT_SEC: Final[int] = 7200  # 2 hours (deep scan)
DEFAULT_HOST_TIMEOUT_SEC: Final[int] = 30
DEFAULT_CONNECT_TIMEOUT_SEC: Final[int] = 5

# Private network ranges (RFC1918 + loopback)
# scope_validator.py validates targets against this list.
PRIVATE_NETWORK_RANGES: Final[tuple[str, ...]] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
)

# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------
LOG_FILE_MAX_BYTES: Final[int] = 10 * 1024 * 1024  # 10 MB
LOG_FILE_BACKUP_COUNT: Final[int] = 5
