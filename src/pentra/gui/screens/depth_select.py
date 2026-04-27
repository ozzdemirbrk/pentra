"""Screen 3 — Depth Selection.

Three choices: Quick (top 100 ports), Standard (top 1000 + CVE),
Deep (all 65k ports + NSE safe + OS detection).
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QLabel,
    QRadioButton,
    QVBoxLayout,
    QWizardPage,
)

from pentra.gui.wizard import PentraWizard
from pentra.i18n import Translator, t
from pentra.models import ScanDepth


class DepthSelectPage(QWizardPage):
    """Pick the scan depth (which in turn picks duration/coverage)."""

    def __init__(self) -> None:
        super().__init__()

        layout = QVBoxLayout(self)

        self._group = QButtonGroup(self)

        # --- Quick ---
        self._rb_quick = QRadioButton()
        self._rb_quick.setChecked(True)
        self._rb_quick.setStyleSheet("QRadioButton { font-size: 14px; font-weight: bold; padding: 6px; }")
        self._group.addButton(self._rb_quick, 0)
        layout.addWidget(self._rb_quick)

        self._desc_quick = QLabel()
        self._desc_quick.setWordWrap(True)
        self._desc_quick.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(self._desc_quick)

        line1 = QFrame()
        line1.setFrameShape(QFrame.Shape.HLine)
        line1.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(line1)

        # --- Standard ---
        self._rb_standard = QRadioButton()
        self._rb_standard.setStyleSheet("QRadioButton { font-size: 14px; font-weight: bold; padding: 6px; }")
        self._group.addButton(self._rb_standard)
        layout.addWidget(self._rb_standard)

        self._desc_std = QLabel()
        self._desc_std.setWordWrap(True)
        self._desc_std.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(self._desc_std)

        line2 = QFrame()
        line2.setFrameShape(QFrame.Shape.HLine)
        line2.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(line2)

        # --- Deep ---
        self._rb_deep = QRadioButton()
        self._rb_deep.setStyleSheet("QRadioButton { font-size: 14px; font-weight: bold; padding: 6px; }")
        self._group.addButton(self._rb_deep)
        layout.addWidget(self._rb_deep)

        self._desc_deep = QLabel()
        self._desc_deep.setWordWrap(True)
        self._desc_deep.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(self._desc_deep)

        layout.addStretch()

        self.retranslate_ui()
        Translator.instance().languageChanged.connect(lambda _l: self.retranslate_ui())

    # -----------------------------------------------------------------
    def retranslate_ui(self) -> None:
        self.setTitle(t("depth.title"))
        self.setSubTitle(t("depth.subtitle"))

        self._rb_quick.setText(t("depth.quick.label"))
        self._desc_quick.setText(t("depth.quick.desc_html"))

        self._rb_standard.setText(t("depth.standard.label"))
        self._desc_std.setText(t("depth.standard.desc_html"))

        self._rb_deep.setText(t("depth.deep.label"))
        self._desc_deep.setText(t("depth.deep.desc_html"))

    # -----------------------------------------------------------------
    def validatePage(self) -> bool:  # noqa: N802
        wizard = self.wizard()
        if isinstance(wizard, PentraWizard):
            if self._rb_quick.isChecked():
                wizard.context.depth = ScanDepth.QUICK
            elif self._rb_standard.isChecked():
                wizard.context.depth = ScanDepth.STANDARD
            elif self._rb_deep.isChecked():
                wizard.context.depth = ScanDepth.DEEP
        return True
