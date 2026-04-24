"""Dict tabanlı i18n çevirmeni — Qt sinyalleri ile dinamik dil değişimi destekler.

Tasarım:
- Singleton (`Translator.instance()`) — tüm widget'lar aynı objeye bağlanır.
- JSON locale dosyaları `locales/<lang>.json` yolunda tutulur.
- Dil değiştiğinde `languageChanged` sinyali yayılır; widget'lar
  `retranslate_ui()` çağırır.
- Anahtar bulunmazsa önce İngilizceye, ardından anahtarın kendisine düşer.
"""

from __future__ import annotations

import json
import locale as _locale
from pathlib import Path
from typing import Any, ClassVar

from PySide6.QtCore import QObject, QSettings, Signal


class Translator(QObject):
    """Pentra'nın tüm metin çevirilerini yöneten singleton."""

    #: Dil değiştiğinde yayınlanır; yeni dil kodunu taşır ("en" / "tr").
    languageChanged = Signal(str)

    SUPPORTED_LANGUAGES: ClassVar[tuple[str, ...]] = ("en", "tr")
    DEFAULT_LANGUAGE: ClassVar[str] = "en"
    FALLBACK_LANGUAGE: ClassVar[str] = "en"

    _instance: ClassVar["Translator | None"] = None

    # -----------------------------------------------------------------
    # Singleton erişimi
    # -----------------------------------------------------------------
    def __init__(self) -> None:
        super().__init__()
        self._translations: dict[str, dict[str, str]] = {}
        self._current_language: str = self.DEFAULT_LANGUAGE
        self._load_translations()
        self._current_language = self._resolve_initial_language()

    @classmethod
    def instance(cls) -> "Translator":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    # -----------------------------------------------------------------
    # Dil yönetimi
    # -----------------------------------------------------------------
    @property
    def current_language(self) -> str:
        return self._current_language

    def set_language(self, lang: str) -> None:
        """Aktif dili değiştirir ve tercih olarak kaydeder."""
        if lang not in self.SUPPORTED_LANGUAGES:
            raise ValueError(f"Desteklenmeyen dil: {lang}")
        if lang == self._current_language:
            return
        self._current_language = lang
        settings = QSettings()
        settings.setValue("language", lang)
        settings.sync()
        self.languageChanged.emit(lang)

    # -----------------------------------------------------------------
    # Çeviri
    # -----------------------------------------------------------------
    def t(self, key: str, **kwargs: Any) -> str:
        """Anahtarı aktif dile çevirir.

        - Aktif dilde anahtar yoksa fallback (İngilizce) dene
        - O da yoksa anahtarın kendisini döndür (debug için görünür kalır)
        - `kwargs` verilmişse `str.format(**kwargs)` ile şablon doldurulur
        """
        value = self._translations.get(self._current_language, {}).get(key)
        if value is None and self._current_language != self.FALLBACK_LANGUAGE:
            value = self._translations.get(self.FALLBACK_LANGUAGE, {}).get(key)
        if value is None:
            # Anahtar tamamen eksik — geliştirici görmesi için ham anahtarı döndür
            return key
        if kwargs:
            try:
                return value.format(**kwargs)
            except (KeyError, IndexError):
                return value
        return value

    # -----------------------------------------------------------------
    # İç yardımcılar
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
        """Önce QSettings'teki tercihi, yoksa OS locale'ini, yoksa default döner."""
        saved = QSettings().value("language", None)
        if isinstance(saved, str) and saved in self.SUPPORTED_LANGUAGES:
            return saved

        # OS locale — Türkçe ise tr, değilse default
        try:
            sys_locale = _locale.getdefaultlocale()[0] or ""
            if sys_locale.lower().startswith("tr"):
                return "tr"
        except Exception:
            pass

        return self.DEFAULT_LANGUAGE


def t(key: str, **kwargs: Any) -> str:
    """`Translator.instance().t(...)` için kısayol."""
    return Translator.instance().t(key, **kwargs)
