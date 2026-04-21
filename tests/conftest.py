"""Pytest global yapılandırması.

- Ortak fixture'lar burada tanımlanır.
- Tüm testler için path düzenlemeleri, geçici dizin kurulumu yapılır.
"""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

import pytest


@pytest.fixture
def tmp_appdata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[Path, None, None]:
    """%APPDATA% dizinini geçici bir klasöre yönlendirir.

    config.get_appdata_dir() çağrıları test izolasyonunda bu yolu kullanır.
    """
    monkeypatch.setenv("APPDATA", str(tmp_path))
    yield tmp_path
