"""Dil seçici dropdown — QComboBox Translator singleton'una bağlanır.

Kullanıcı diğer dili seçtiğinde `Translator.set_language()` çağrılır ve tüm
abone widget'lar `languageChanged` sinyali ile anında yeniden çevirilir.
"""

from __future__ import annotations

from PySide6.QtWidgets import QComboBox, QWidget

from pentra.i18n import Translator, t


class LanguageSelector(QComboBox):
    """İki dilli (EN/TR) dil seçici dropdown."""

    #: (dil_kodu, çeviri_anahtarı) çiftleri — sıra dropdown sırasını belirler.
    _LANGUAGES: list[tuple[str, str]] = [
        ("en", "lang.english"),
        ("tr", "lang.turkish"),
    ]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        translator = Translator.instance()

        for code, label_key in self._LANGUAGES:
            self.addItem(t(label_key), code)

        # Aktif dili seçili göster
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
        """Dil değişimi sonrası dropdown etiketlerini günceller."""
        # Sinyal tetiklenmesini engelle — dışarıdan dil değiştiği için
        self.blockSignals(True)
        try:
            for i, (_code, label_key) in enumerate(self._LANGUAGES):
                self.setItemText(i, t(label_key))
        finally:
            self.blockSignals(False)
