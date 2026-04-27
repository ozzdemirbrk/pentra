"""Pentra logo loader — produces a base64 data URI used in reports.

Embedded via `<img src="{{ logo_data_uri }}">` in HTML reports. The browser
renders the data URI directly, so no separate file is needed. The PDF
exporter uses the same URI.
"""

from __future__ import annotations

import base64
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def _find_logo_path() -> Path | None:
    """Search for the logo starting at the project root — return the first hit."""
    here = Path(__file__).resolve()
    # Walk parent dirs: src/pentra/reporting/logo.py -> ../../../public/logo/
    for parent in [here.parent, *here.parents]:
        candidate = parent / "public" / "logo" / "Pentra.png"
        if candidate.exists():
            return candidate
    return None


def get_logo_data_uri() -> str:
    """Return the logo PNG as a base64 data URI. Empty string when missing."""
    path = _find_logo_path()
    if path is None:
        logger.info("Logo not found (public/logo/Pentra.png) — report will have no logo")
        return ""

    try:
        encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    except OSError as e:
        logger.warning("Could not read logo: %s", e)
        return ""

    return f"data:image/png;base64,{encoded}"
