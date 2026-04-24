"""Ekran 1 — Yetki Onayı.

Kullanıcı iki zorunlu onay kutusunu işaretlemeden İleri butonu pasif kalır.
Sayfanın sağ üstünde dil seçici bulunur; seçilen dil tüm arayüzü günceller.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWizardPage,
)

from pentra.gui.widgets.language_selector import LanguageSelector
from pentra.gui.wizard import PentraWizard
from pentra.i18n import Translator, t


class AuthorizationPage(QWizardPage):
    """Sihirbazın ilk sayfası — yasal/etik onay + dil seçici."""

    def __init__(self) -> None:
        super().__init__()

        layout = QVBoxLayout(self)

        # ---- Üst bar: sağ üstte dil seçici ----
        top_bar = QHBoxLayout()
        self._lang_label = QLabel()
        top_bar.addStretch()
        top_bar.addWidget(self._lang_label)
        top_bar.addWidget(LanguageSelector())
        layout.addLayout(top_bar)

        # ---- Giriş metni ----
        self._intro = QLabel()
        self._intro.setWordWrap(True)
        self._intro.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(self._intro)

        # ---- Ayrım çizgisi ----
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(line)

        # ---- Ne yapar / ne yapmaz ----
        self._features = QLabel()
        self._features.setWordWrap(True)
        self._features.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(self._features)

        # ---- Onay kutuları ----
        self._chk_owner = QCheckBox()
        self._chk_owner.setStyleSheet("QCheckBox { font-weight: bold; }")
        self._chk_owner.stateChanged.connect(self._on_state_changed)
        layout.addWidget(self._chk_owner)

        self._chk_terms = QCheckBox()
        self._chk_terms.setStyleSheet("QCheckBox { font-weight: bold; }")
        self._chk_terms.stateChanged.connect(self._on_state_changed)
        layout.addWidget(self._chk_terms)

        layout.addStretch()

        # İlk çeviri + dil değişimine abone ol
        self.retranslate_ui()
        Translator.instance().languageChanged.connect(lambda _l: self.retranslate_ui())

    # -----------------------------------------------------------------
    # Çeviri
    # -----------------------------------------------------------------
    def retranslate_ui(self) -> None:
        """Tüm metinleri aktif dilden yeniden yükler."""
        self.setTitle(t("auth.title"))
        self.setSubTitle(t("auth.subtitle"))
        self._lang_label.setText(t("lang.selector.label"))
        self._intro.setText(t("auth.intro_html"))
        self._features.setText(t("auth.features_html"))
        self._chk_owner.setText(t("auth.checkbox_owner"))
        self._chk_terms.setText(t("auth.checkbox_terms"))

    # -----------------------------------------------------------------
    # QWizardPage entegrasyonu
    # -----------------------------------------------------------------
    def isComplete(self) -> bool:  # noqa: N802 — Qt metodu
        """İki onay da işaretliyken İleri butonu aktif."""
        return self._chk_owner.isChecked() and self._chk_terms.isChecked()

    def validatePage(self) -> bool:  # noqa: N802
        """Sayfa terk edilirken context'e yaz."""
        wizard = self.wizard()
        if isinstance(wizard, PentraWizard):
            wizard.context.user_accepted_terms = (
                self._chk_owner.isChecked() and self._chk_terms.isChecked()
            )
        return True

    # -----------------------------------------------------------------
    # İç
    # -----------------------------------------------------------------
    def _on_state_changed(self, _state: int) -> None:
        self.completeChanged.emit()
