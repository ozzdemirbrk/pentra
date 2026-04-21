"""Ekran 2 — Hedef Seçimi.

Faz 3: "Bu bilgisayar" + "Web sitesi (URL)" aktif.
Diğer seçenekler (yerel ağ, IP aralığı, Wi-Fi) Faz 4/5'te açılacak.
"""

from __future__ import annotations

from urllib.parse import urlparse

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QLabel,
    QLineEdit,
    QMessageBox,
    QRadioButton,
    QVBoxLayout,
    QWidget,
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
            "<p>Pentra birkaç tür hedefi destekler. Aşağıdaki aktif seçeneklerden "
            "birini tıklayıp gerekli alanları doldurun.</p>",
        )
        info.setWordWrap(True)
        info.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(info)

        self._group = QButtonGroup(self)

        # --- 1) Bu bilgisayar (aktif) ---
        self._rb_localhost = QRadioButton("🖥️  Bu bilgisayar (localhost — 127.0.0.1)")
        self._rb_localhost.setChecked(True)
        self._rb_localhost.setStyleSheet("QRadioButton { font-size: 13px; padding: 6px; }")
        self._rb_localhost.toggled.connect(self._update_url_panel)
        self._group.addButton(self._rb_localhost, 0)
        layout.addWidget(self._rb_localhost)

        desc_local = QLabel(
            "&nbsp;&nbsp;&nbsp;&nbsp;<small>Kullandığınız bilgisayardaki açık portları ve servisleri "
            "tarar. En güvenli seçenek — sadece kendi makinenize paket gönderilir.</small>",
        )
        desc_local.setWordWrap(True)
        desc_local.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(desc_local)

        # --- 2) Web sitesi (aktif — Faz 3) ---
        self._rb_url = QRadioButton("🔗  Web sitesi (URL)")
        self._rb_url.setStyleSheet("QRadioButton { font-size: 13px; padding: 6px; }")
        self._rb_url.toggled.connect(self._update_url_panel)
        self._group.addButton(self._rb_url, 1)
        layout.addWidget(self._rb_url)

        desc_url = QLabel(
            "&nbsp;&nbsp;&nbsp;&nbsp;<small>Belirttiğiniz URL üzerinde güvenlik header'ları, "
            "SSL/TLS zafiyetleri, açıkta kalan hassas dosyalar, yol sızıntısı, SQL injection ve "
            "XSS tespiti yapar. <b>Yalnızca sahibi olduğunuz veya yazılı yetki aldığınız siteler.</b></small>",
        )
        desc_url.setWordWrap(True)
        desc_url.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(desc_url)

        # URL alt paneli — sadece URL seçiliyken görünür
        self._url_panel = QWidget()
        panel_layout = QVBoxLayout(self._url_panel)
        panel_layout.setContentsMargins(24, 4, 4, 4)

        self._url_input = QLineEdit()
        self._url_input.setPlaceholderText("https://example.com")
        self._url_input.setStyleSheet(
            "QLineEdit { padding: 6px; font-size: 13px; font-family: Consolas, monospace; }",
        )
        self._url_input.textChanged.connect(lambda _: self.completeChanged.emit())
        panel_layout.addWidget(self._url_input)

        self._url_chk_auth = QCheckBox(
            "Bu URL'nin sahibiyim veya yazılı yetkim var (public/dış hedef için zorunlu)",
        )
        self._url_chk_auth.stateChanged.connect(lambda _: self.completeChanged.emit())
        panel_layout.addWidget(self._url_chk_auth)

        self._url_panel.setVisible(False)
        layout.addWidget(self._url_panel)

        # --- 3-5) Yakında seçenekleri (disabled) ---
        soon_options = [
            ("🏠  Yerel ağım (192.168.x.x)", "Ev/ofis ağınızdaki tüm cihazları keşfeder"),
            ("🌐  Belirli bir IP veya IP aralığı", "Tek bir IP veya CIDR notasyonunda aralık"),
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
    # Dinamik görünüm
    # -----------------------------------------------------------------
    def _update_url_panel(self) -> None:
        self._url_panel.setVisible(self._rb_url.isChecked())
        self.completeChanged.emit()

    # -----------------------------------------------------------------
    # QWizardPage entegrasyonu
    # -----------------------------------------------------------------
    def isComplete(self) -> bool:  # noqa: N802
        """İleri aktif kriterleri."""
        if self._rb_localhost.isChecked():
            return True
        if self._rb_url.isChecked():
            url_text = self._url_input.text().strip()
            if not url_text:
                return False
            if not self._url_chk_auth.isChecked():
                return False
            return self._is_url_valid(url_text)
        return False

    def validatePage(self) -> bool:  # noqa: N802
        """Seçime göre context.target ve external_confirmed ayarla."""
        wizard = self.wizard()
        if not isinstance(wizard, PentraWizard):
            return True

        if self._rb_localhost.isChecked():
            wizard.context.target = Target(
                target_type=TargetType.LOCALHOST,
                value="127.0.0.1",
                description="Bu bilgisayar",
            )
            wizard.context.external_target_confirmed = False
            return True

        if self._rb_url.isChecked():
            url_text = self._url_input.text().strip()
            if not self._is_url_valid(url_text):
                QMessageBox.warning(
                    self, "Geçersiz URL",
                    "Lütfen http:// veya https:// ile başlayan geçerli bir URL girin.",
                )
                return False
            wizard.context.target = Target(
                target_type=TargetType.URL,
                value=url_text,
                description=f"Web sitesi: {url_text}",
            )
            wizard.context.external_target_confirmed = self._url_chk_auth.isChecked()
            return True

        return False

    # -----------------------------------------------------------------
    @staticmethod
    def _is_url_valid(url_text: str) -> bool:
        """http(s) şemalı, hostname içeren URL kontrolü."""
        try:
            parsed = urlparse(url_text)
        except ValueError:
            return False
        return parsed.scheme in ("http", "https") and bool(parsed.hostname)
