"""translator.py — multi-language translator tests.

QSettings is redirected to a temporary INI location for test isolation.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from PySide6.QtCore import QCoreApplication, QSettings
from PySide6.QtWidgets import QApplication

from pentra.i18n.translator import Translator, t


@pytest.fixture(autouse=True)
def _isolated_qsettings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Give every test a fresh QSettings directory and a new Translator instance."""
    # QApplication is a singleton; create one if missing
    app = QApplication.instance() or QApplication([])
    QCoreApplication.setOrganizationName("PentraTest")
    QCoreApplication.setApplicationName("PentraTest")
    QSettings.setDefaultFormat(QSettings.Format.IniFormat)
    QSettings.setPath(
        QSettings.Format.IniFormat,
        QSettings.Scope.UserScope,
        str(tmp_path),
    )
    # Reset the Translator singleton — every test starts fresh
    Translator._instance = None
    yield
    Translator._instance = None
    _ = app  # keep a reference so GC doesn't collect it; silence the linter


# =====================================================================
# Basic translation
# =====================================================================
class TestTranslation:
    def test_english_key_returns_english(self) -> None:
        tr = Translator.instance()
        tr.set_language("en")
        assert t("auth.title") == "Authorization"

    def test_turkish_key_returns_turkish(self) -> None:
        tr = Translator.instance()
        tr.set_language("tr")
        assert t("auth.title") == "Yetki Onayı"

    def test_missing_key_returns_key(self) -> None:
        tr = Translator.instance()
        tr.set_language("en")
        assert t("this.does.not.exist") == "this.does.not.exist"

    def test_fallback_to_english_when_missing_in_current(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A key missing in TR should fall back to EN."""
        tr = Translator.instance()
        tr.set_language("tr")
        # Assume it exists in EN but not in TR — mutate the EN table for the test
        tr._translations["en"]["_only_in_en"] = "only-en"
        assert t("_only_in_en") == "only-en"


# =====================================================================
# Language switch + signal
# =====================================================================
class TestLanguageSwitching:
    def test_set_language_emits_signal(self) -> None:
        tr = Translator.instance()
        tr.set_language("en")
        received: list[str] = []
        tr.languageChanged.connect(received.append)
        tr.set_language("tr")
        assert received == ["tr"]

    def test_set_same_language_does_not_emit(self) -> None:
        tr = Translator.instance()
        tr.set_language("en")
        received: list[str] = []
        tr.languageChanged.connect(received.append)
        tr.set_language("en")
        assert received == []

    def test_invalid_language_raises(self) -> None:
        tr = Translator.instance()
        with pytest.raises(ValueError):
            tr.set_language("de")

    def test_set_language_persists_across_instances(self) -> None:
        """A saved language preference should be picked up by a new Translator instance."""
        tr = Translator.instance()
        tr.set_language("tr")
        # Reset the singleton — a fresh instance should read from QSettings
        Translator._instance = None
        tr2 = Translator.instance()
        assert tr2.current_language == "tr"


# =====================================================================
# Formatting
# =====================================================================
class TestFormatting:
    def test_kwargs_format_value(self) -> None:
        tr = Translator.instance()
        tr._translations["en"]["greet"] = "Hello {name}"
        tr.set_language("en")
        assert t("greet", name="World") == "Hello World"

    def test_format_error_returns_unformatted(self) -> None:
        """Missing kwarg -> format error -> raw string should be returned."""
        tr = Translator.instance()
        tr._translations["en"]["greet"] = "Hello {name}"
        tr.set_language("en")
        # 'name' is missing — KeyError should be caught and the raw string returned
        assert t("greet", wrong="x") == "Hello {name}"


# =====================================================================
# Singleton
# =====================================================================
class TestSingleton:
    def test_instance_returns_same_object(self) -> None:
        a = Translator.instance()
        b = Translator.instance()
        assert a is b
