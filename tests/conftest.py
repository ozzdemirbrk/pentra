"""Global pytest configuration.

- Shared fixtures are defined here.
- Path adjustments and temporary-directory setup for all tests.
"""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

import pytest

from pentra.i18n import Translator


@pytest.fixture(autouse=True)
def _pin_translator_to_english() -> Generator[None, None, None]:
    # Without this, tests that assert on translated strings would depend on the
    # host's OS locale (Turkish dev box passes, English CI runner fails).
    Translator.instance().set_language("en")
    yield


@pytest.fixture
def tmp_appdata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[Path, None, None]:
    """Redirect the %APPDATA% directory to a temporary folder.

    Calls to config.get_appdata_dir() use this path for test isolation.
    """
    monkeypatch.setenv("APPDATA", str(tmp_path))
    yield tmp_path
