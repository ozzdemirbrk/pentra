"""Ekran 1 — Yetki Onayı.

Kullanıcı iki zorunlu onay kutusunu işaretlemeden İleri butonu pasif kalır.
TCK 243-245 uyarısı ve etik kullanım beyanı bu ekranda gösterilir.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QFrame,
    QLabel,
    QVBoxLayout,
    QWizardPage,
)

from pentra.gui.wizard import PentraWizard


class AuthorizationPage(QWizardPage):
    """Sihirbazın ilk sayfası — yasal/etik onay."""

    def __init__(self) -> None:
        super().__init__()
        self.setTitle("Yetki Onayı")
        self.setSubTitle(
            "Devam etmeden önce bu aracın kullanım koşullarını okuyup onaylayın.",
        )

        layout = QVBoxLayout(self)

        # Başlık + kısa açıklama
        intro = QLabel(
            "<p>Pentra, <b>yalnızca sahibi olduğunuz</b> veya "
            "<b>yazılı yetki aldığınız</b> sistemlerde kullanılmak üzere tasarlanmıştır.</p>"
            "<p>Yetkisiz tarama, Türk Ceza Kanunu'nun <b>243, 244, 245. maddeleri</b> "
            "uyarınca suç teşkil eder ve hapis cezası gerektirir.</p>",
        )
        intro.setWordWrap(True)
        intro.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(intro)

        # Ayrım çizgisi
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(line)

        # Ne yapıyor / ne yapmıyor
        features = QLabel(
            "<p><b>Pentra ne yapar?</b></p>"
            "<ul>"
            "<li>Açık portları ve servisleri tespit eder</li>"
            "<li>Bilinen güvenlik sorunlarını raporlar</li>"
            "<li>Türkçe onarım önerileri sunar</li>"
            "<li>Raporu yalnızca <b>sizin masaüstünüze</b> kaydeder — internete göndermez</li>"
            "</ul>"
            "<p><b>Pentra ne yapmaz?</b></p>"
            "<ul>"
            "<li>Saldırı/exploit çalıştırmaz — sadece tespit yapar</li>"
            "<li>Parola kırma, kötü amaçlı yük gönderme, iz silme yapmaz</li>"
            "<li>Verilerinizi uzak sunucuya göndermez</li>"
            "</ul>",
        )
        features.setWordWrap(True)
        features.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(features)

        # Onay kutuları
        self._chk_owner = QCheckBox(
            "Tarayacağım sistemlerin sahibi olduğumu veya yazılı izne sahip olduğumu beyan ederim.",
        )
        self._chk_owner.setStyleSheet("QCheckBox { font-weight: bold; }")
        self._chk_owner.stateChanged.connect(self._on_state_changed)
        layout.addWidget(self._chk_owner)

        self._chk_terms = QCheckBox(
            "Pentra'nın kullanım koşullarını (yalnızca tespit, rapor yalnızca yerel) okudum ve kabul ediyorum.",
        )
        self._chk_terms.setStyleSheet("QCheckBox { font-weight: bold; }")
        self._chk_terms.stateChanged.connect(self._on_state_changed)
        layout.addWidget(self._chk_terms)

        layout.addStretch()

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
