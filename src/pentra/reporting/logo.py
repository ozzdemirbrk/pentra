"""Pentra logo yükleyici — raporlarda kullanılacak base64 data URI üretir.

HTML raporlarda `<img src="{{ logo_data_uri }}">` ile gömülür. Browser
data URI'yi direkt render eder, ayrı dosya gerekmez. PDF exporter da
aynı URI'yi kullanır.
"""

from __future__ import annotations

import base64
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def _find_logo_path() -> Path | None:
    """Logo dosyasını proje kökünden ara — ilk bulduğuna dön."""
    here = Path(__file__).resolve()
    # Paket/üst dizinleri tara: src/pentra/reporting/logo.py → ../../../public/logo/
    for parent in [here.parent, *here.parents]:
        candidate = parent / "public" / "logo" / "Pentra.png"
        if candidate.exists():
            return candidate
    return None


def get_logo_data_uri() -> str:
    """Logo PNG'yi base64 data URI olarak döndür. Bulunamazsa boş string."""
    path = _find_logo_path()
    if path is None:
        logger.info("Logo bulunamadı (public/logo/Pentra.png) — rapor logosuz olacak")
        return ""

    try:
        encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    except OSError as e:
        logger.warning("Logo okunamadı: %s", e)
        return ""

    return f"data:image/png;base64,{encoded}"
