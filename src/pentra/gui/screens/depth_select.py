"""Ekran 3 — Derinlik Seçimi.

MVP: sadece Hızlı aktif. Standart ve Derin "yakında".
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
from pentra.models import ScanDepth


class DepthSelectPage(QWizardPage):
    """Tarama derinliğini (ve dolayısıyla süre/kapsam) seçer."""

    def __init__(self) -> None:
        super().__init__()
        self.setTitle("Tarama Derinliği")
        self.setSubTitle("Ne kadar derinleşmeli? Daha derin = daha uzun ama daha kapsamlı.")

        layout = QVBoxLayout(self)

        self._group = QButtonGroup(self)

        # --- Hızlı (aktif) ---
        self._rb_quick = QRadioButton("🟢  Hızlı  —  yaklaşık 1-2 dk")
        self._rb_quick.setChecked(True)
        self._rb_quick.setStyleSheet("QRadioButton { font-size: 14px; font-weight: bold; padding: 6px; }")
        self._group.addButton(self._rb_quick, 0)
        layout.addWidget(self._rb_quick)

        desc_quick = QLabel(
            "<div style='margin-left: 24px; margin-bottom: 8px;'>"
            "<b>Yapılanlar:</b> En yaygın 100 portu tarar, açık olanları ve üzerinde çalışan servisin adını tespit eder.<br>"
            "<b>Yapılmayanlar:</b> Servis versiyonu, zafiyet taraması, OS tespiti.<br>"
            "<span style='color: #555;'><i>Genel sağlık kontrolü için ideal.</i></span>"
            "</div>",
        )
        desc_quick.setWordWrap(True)
        desc_quick.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(desc_quick)

        line1 = QFrame()
        line1.setFrameShape(QFrame.Shape.HLine)
        line1.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(line1)

        # --- Standart (yakında) ---
        self._rb_standard = QRadioButton("🟡  Standart  —  yaklaşık 15-30 dk   (yakında)")
        self._rb_standard.setEnabled(False)
        self._rb_standard.setStyleSheet("QRadioButton { font-size: 14px; padding: 6px; color: #888; }")
        self._group.addButton(self._rb_standard)
        layout.addWidget(self._rb_standard)

        desc_std = QLabel(
            "<div style='margin-left: 24px; margin-bottom: 8px; color: #888;'>"
            "<b>Yapılanlar:</b> Top 1000 port + servis versiyonu tespiti, temel zafiyet taraması.<br>"
            "<b>Yapılmayanlar:</b> Derinlemesine exploit script'leri.<br>"
            "<i>Sonraki sürümde aktif olacak.</i>"
            "</div>",
        )
        desc_std.setWordWrap(True)
        desc_std.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(desc_std)

        line2 = QFrame()
        line2.setFrameShape(QFrame.Shape.HLine)
        line2.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(line2)

        # --- Derin (yakında) ---
        self._rb_deep = QRadioButton("🔴  Derin  —  yaklaşık 1-2 saat   (yakında)")
        self._rb_deep.setEnabled(False)
        self._rb_deep.setStyleSheet("QRadioButton { font-size: 14px; padding: 6px; color: #888; }")
        self._group.addButton(self._rb_deep)
        layout.addWidget(self._rb_deep)

        desc_deep = QLabel(
            "<div style='margin-left: 24px; color: #888;'>"
            "<b>Yapılanlar:</b> Tüm portlar (1-65535), servis versiyonu, OS tespiti, "
            "varsayılan zafiyet script'leri, zayıf kimlik kontrolü.<br>"
            "<b>Yapılmayanlar:</b> Exploit yürütme (hiçbir sürümde yapmayız).<br>"
            "<i>Sonraki sürümde aktif olacak.</i>"
            "</div>",
        )
        desc_deep.setWordWrap(True)
        desc_deep.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(desc_deep)

        layout.addStretch()

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
