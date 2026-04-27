"""Language-selector dropdown — a QComboBox bound to the Translator singleton.

When the user picks another language, `Translator.set_language()` is called
and every subscribed widget retranslates immediately via the
`languageChanged` signal.
"""

from __future__ import annotations

from PySide6.QtWidgets import QComboBox, QWidget

from pentra.i18n import Translator, t


class LanguageSelector(QComboBox):
    """Two-language (EN/TR) language-selector dropdown."""

    #: (language_code, translation_key) pairs — order determines the dropdown order.
    _LANGUAGES: list[tuple[str, str]] = [
        ("en", "lang.english"),
        ("tr", "lang.turkish"),
    ]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        translator = Translator.instance()

        for code, label_key in self._LANGUAGES:
            self.addItem(t(label_key), code)

        # Mark the active language as selected
        for i in range(self.count()):
            if self.itemData(i) == translator.current_language:
                self.setCurrentIndex(i)
                break

        self.currentIndexChanged.connect(self._on_selection_changed)
        translator.languageChanged.connect(self._retranslate_items)

    # -----------------------------------------------------------------
    def _on_selection_changed(self, index: int) -> None:
        code = self.itemData(index)
        if isinstance(code, str):
            Translator.instance().set_language(code)

    def _retranslate_items(self, _lang: str) -> None:
        """Refresh the dropdown labels after a language change."""
        # Prevent signal retriggering — the change came from outside
        self.blockSignals(True)
        try:
            for i, (_code, label_key) in enumerate(self._LANGUAGES):
                self.setItemText(i, t(label_key))
        finally:
            self.blockSignals(False)
