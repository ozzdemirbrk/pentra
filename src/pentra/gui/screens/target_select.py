"""Ekran 2 — Hedef Seçimi.

MVP (Faz 2): sadece "Bu bilgisayar" (localhost) aktif.
Diğer seçenekler disabled + "yakında" etiketi ile görünür.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QButtonGroup,
    QLabel,
    QRadioButton,
    QVBoxLayout,
    QWizardPage,
)

from pentra.gui.wizard import PentraWizard
from pentra.models import Target, TargetType


class TargetSelectPage(QWizardPage):
    """Kullanıcı neyi taramak istediğini seçer."""

    def __init__(self) -> None:
        super().__init__()
        self.setTitle("Hedef Seçimi")
        self.setSubTitle("Hangi sistemi taramak istiyorsunuz?")

        layout = QVBoxLayout(self)

        info = QLabel(
            "<p>Pentra birkaç tür hedefi destekler. Başlangıç sürümünde yalnızca "
            "<b>bu bilgisayar</b> üzerinde tarama yapılabilmektedir; diğer seçenekler "
            "sonraki güncellemelerde açılacaktır.</p>",
        )
        info.setWordWrap(True)
        info.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(info)

        self._group = QButtonGroup(self)

        # --- 1) Bu bilgisayar (aktif) ---
        self._rb_localhost = QRadioButton("🖥️  Bu bilgisayar (localhost — 127.0.0.1)")
        self._rb_localhost.setChecked(True)
        self._rb_localhost.setStyleSheet("QRadioButton { font-size: 13px; padding: 6px; }")
        self._group.addButton(self._rb_localhost, 0)
        layout.addWidget(self._rb_localhost)

        desc_local = QLabel(
            "&nbsp;&nbsp;&nbsp;&nbsp;<small>Kullandığınız bilgisayardaki açık portları ve servisleri "
            "tarar. En güvenli seçenek — sadece kendi makinenize paket gönderilir.</small>",
        )
        desc_local.setWordWrap(True)
        desc_local.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(desc_local)

        # --- 2-5) Yakında seçenekleri (disabled) ---
        soon_options = [
            ("🏠  Yerel ağım (192.168.x.x)", "Ev/ofis ağınızdaki tüm cihazları keşfeder"),
            ("🌐  Belirli bir IP veya IP aralığı", "Tek bir IP veya CIDR notasyonunda aralık"),
            ("🔗  Web sitesi (URL)", "Belirtilen URL'nin güvenlik durumunu tarar"),
            ("📡  Çevredeki Wi-Fi ağları", "Pasif Wi-Fi taraması — paket gönderilmez"),
        ]
        for label, desc in soon_options:
            rb = QRadioButton(f"{label}   — yakında")
            rb.setEnabled(False)
            rb.setStyleSheet(
                "QRadioButton { font-size: 13px; padding: 6px; color: #888; }",
            )
            self._group.addButton(rb)
            layout.addWidget(rb)
            desc_lbl = QLabel(
                f"&nbsp;&nbsp;&nbsp;&nbsp;<small style='color: #aaa;'>{desc}</small>",
            )
            desc_lbl.setWordWrap(True)
            desc_lbl.setTextFormat(Qt.TextFormat.RichText)
            layout.addWidget(desc_lbl)

        layout.addStretch()

    # -----------------------------------------------------------------
    def validatePage(self) -> bool:  # noqa: N802
        """Seçime göre context.target ayarla."""
        wizard = self.wizard()
        if isinstance(wizard, PentraWizard):
            if self._rb_localhost.isChecked():
                wizard.context.target = Target(
                    target_type=TargetType.LOCALHOST,
                    value="127.0.0.1",
                    description="Bu bilgisayar",
                )
        return True
