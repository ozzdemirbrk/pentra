"""Screen 1 — Authorization.

The Next button stays disabled until both required checkboxes are ticked.
A language selector sits in the top-right corner; changing it updates the
entire UI.
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
    """First wizard page — legal/ethical consent + language selector."""

    def __init__(self) -> None:
        super().__init__()

        layout = QVBoxLayout(self)

        # ---- Top bar: language selector in the top-right ----
        top_bar = QHBoxLayout()
        self._lang_label = QLabel()
        top_bar.addStretch()
        top_bar.addWidget(self._lang_label)
        top_bar.addWidget(LanguageSelector())
        layout.addLayout(top_bar)

        # ---- Intro text ----
        self._intro = QLabel()
        self._intro.setWordWrap(True)
        self._intro.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(self._intro)

        # ---- Separator line ----
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(line)

        # ---- What it does / doesn't do ----
        self._features = QLabel()
        self._features.setWordWrap(True)
        self._features.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(self._features)

        # ---- Consent checkboxes ----
        self._chk_owner = QCheckBox()
        self._chk_owner.setStyleSheet("QCheckBox { font-weight: bold; }")
        self._chk_owner.stateChanged.connect(self._on_state_changed)
        layout.addWidget(self._chk_owner)

        self._chk_terms = QCheckBox()
        self._chk_terms.setStyleSheet("QCheckBox { font-weight: bold; }")
        self._chk_terms.stateChanged.connect(self._on_state_changed)
        layout.addWidget(self._chk_terms)

        layout.addStretch()

        # First translation pass + subscribe to language changes
        self.retranslate_ui()
        Translator.instance().languageChanged.connect(lambda _l: self.retranslate_ui())

    # -----------------------------------------------------------------
    # Translation
    # -----------------------------------------------------------------
    def retranslate_ui(self) -> None:
        """Reload every text from the active language."""
        self.setTitle(t("auth.title"))
        self.setSubTitle(t("auth.subtitle"))
        self._lang_label.setText(t("lang.selector.label"))
        self._intro.setText(t("auth.intro_html"))
        self._features.setText(t("auth.features_html"))
        self._chk_owner.setText(t("auth.checkbox_owner"))
        self._chk_terms.setText(t("auth.checkbox_terms"))

    # -----------------------------------------------------------------
    # QWizardPage integration
    # -----------------------------------------------------------------
    def isComplete(self) -> bool:  # noqa: N802 — Qt method
        """Next is enabled only when both consent boxes are ticked."""
        return self._chk_owner.isChecked() and self._chk_terms.isChecked()

    def validatePage(self) -> bool:  # noqa: N802
        """Write state into the context when the page is left."""
        wizard = self.wizard()
        if isinstance(wizard, PentraWizard):
            wizard.context.user_accepted_terms = (
                self._chk_owner.isChecked() and self._chk_terms.isChecked()
            )
        return True

    # -----------------------------------------------------------------
    # Internal
    # -----------------------------------------------------------------
    def _on_state_changed(self, _state: int) -> None:
        self.completeChanged.emit()
