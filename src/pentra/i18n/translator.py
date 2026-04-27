"""Dict-based i18n translator — supports dynamic language switching via Qt signals.

Design:
- Singleton (`Translator.instance()`) — every widget binds to the same object.
- JSON locale files live at `locales/<lang>.json`.
- When the language changes the `languageChanged` signal is emitted;
  widgets then call their own `retranslate_ui()`.
- If a key is missing, it falls back to English and then to the raw key.
"""

from __future__ import annotations

import json
import locale as _locale
from pathlib import Path
from typing import Any, ClassVar

from PySide6.QtCore import QObject, QSettings, Signal


class Translator(QObject):
    """Singleton that manages every text translation in Pentra."""

    #: Emitted when the language changes; carries the new language code ("en" / "tr").
    languageChanged = Signal(str)

    SUPPORTED_LANGUAGES: ClassVar[tuple[str, ...]] = ("en", "tr")
    DEFAULT_LANGUAGE: ClassVar[str] = "en"
    FALLBACK_LANGUAGE: ClassVar[str] = "en"

    _instance: ClassVar[Translator | None] = None

    # -----------------------------------------------------------------
    # Singleton access
    # -----------------------------------------------------------------
    def __init__(self) -> None:
        super().__init__()
        self._translations: dict[str, dict[str, str]] = {}
        self._current_language: str = self.DEFAULT_LANGUAGE
        self._load_translations()
        self._current_language = self._resolve_initial_language()

    @classmethod
    def instance(cls) -> Translator:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    # -----------------------------------------------------------------
    # Language management
    # -----------------------------------------------------------------
    @property
    def current_language(self) -> str:
        return self._current_language

    def set_language(self, lang: str) -> None:
        """Change the active language and persist it as a preference."""
        if lang not in self.SUPPORTED_LANGUAGES:
            raise ValueError(f"Unsupported language: {lang}")
        if lang == self._current_language:
            return
        self._current_language = lang
        settings = QSettings()
        settings.setValue("language", lang)
        settings.sync()
        self.languageChanged.emit(lang)

    # -----------------------------------------------------------------
    # Translation
    # -----------------------------------------------------------------
    def t(self, key: str, **kwargs: Any) -> str:
        """Translate a key into the active language.

        - If the key is missing in the active language, try the fallback (English)
        - If that's also missing, return the key itself (stays visible for debugging)
        - When `kwargs` is provided, the template is filled via `str.format(**kwargs)`
        """
        value = self._translations.get(self._current_language, {}).get(key)
        if value is None and self._current_language != self.FALLBACK_LANGUAGE:
            value = self._translations.get(self.FALLBACK_LANGUAGE, {}).get(key)
        if value is None:
            # Key missing entirely — return the raw key so the developer spots it
            return key
        if kwargs:
            try:
                return value.format(**kwargs)
            except (KeyError, IndexError):
                return value
        return value

    # -----------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------
    def _load_translations(self) -> None:
        locales_dir = Path(__file__).parent / "locales"
        for lang in self.SUPPORTED_LANGUAGES:
            path = locales_dir / f"{lang}.json"
            if path.exists():
                with path.open(encoding="utf-8") as f:
                    self._translations[lang] = json.load(f)
            else:
                self._translations[lang] = {}

    def _resolve_initial_language(self) -> str:
        """Prefer the QSettings value, then the OS locale, then the default."""
        saved = QSettings().value("language", None)
        if isinstance(saved, str) and saved in self.SUPPORTED_LANGUAGES:
            return saved

        # OS locale — Turkish -> tr, otherwise default
        try:
            sys_locale = _locale.getdefaultlocale()[0] or ""
            if sys_locale.lower().startswith("tr"):
                return "tr"
        except Exception:
            pass

        return self.DEFAULT_LANGUAGE


def t(key: str, **kwargs: Any) -> str:
    """Shortcut for `Translator.instance().t(...)`."""
    return Translator.instance().t(key, **kwargs)
