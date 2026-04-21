"""İlk smoke test — paket import edilebiliyor mu?"""

from __future__ import annotations

import pentra


def test_version_string() -> None:
    """Sürüm string'i tanımlı ve beklenen formatta."""
    assert isinstance(pentra.__version__, str)
    assert pentra.__version__.count(".") >= 1


def test_app_name() -> None:
    """Uygulama adı sabiti tanımlı."""
    assert pentra.__app_name__ == "Pentra"
