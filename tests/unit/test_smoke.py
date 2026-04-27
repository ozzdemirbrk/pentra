"""First smoke test — can the package be imported?"""

from __future__ import annotations

import pentra


def test_version_string() -> None:
    """Version string is defined and has the expected format."""
    assert isinstance(pentra.__version__, str)
    assert pentra.__version__.count(".") >= 1


def test_app_name() -> None:
    """Application-name constant is defined."""
    assert pentra.__app_name__ == "Pentra"
