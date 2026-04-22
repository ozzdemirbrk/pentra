"""Ekran 2 — Hedef Seçimi.

Tüm hedef tipleri aktif: localhost, URL, Wi-Fi, yerel ağ, IP aralığı.
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
from pentra.utils.network_utils import guess_local_cidr, is_valid_cidr


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

        # --- 3) Wi-Fi ağları (aktif — Faz 5) ---
        self._rb_wifi = QRadioButton("📡  Çevredeki Wi-Fi ağları")
        self._rb_wifi.setStyleSheet("QRadioButton { font-size: 13px; padding: 6px; }")
        self._group.addButton(self._rb_wifi)
        layout.addWidget(self._rb_wifi)

        desc_wifi = QLabel(
            "&nbsp;&nbsp;&nbsp;&nbsp;<small>Çevrenizdeki Wi-Fi ağlarını (pasif) listeler — "
            "paket gönderilmez. Zayıf şifrelemeli (WEP, şifresiz) veya modası geçmiş ağları "
            "tespit eder.</small>",
        )
        desc_wifi.setWordWrap(True)
        desc_wifi.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(desc_wifi)

        # --- 4) Yerel ağ (otomatik tespit — Faz 5/Batch 4) ---
        self._rb_local_net = QRadioButton("🏠  Yerel ağım (otomatik tespit)")
        self._rb_local_net.setStyleSheet("QRadioButton { font-size: 13px; padding: 6px; }")
        self._rb_local_net.toggled.connect(self._update_local_net_hint)
        self._group.addButton(self._rb_local_net)
        layout.addWidget(self._rb_local_net)

        # Otomatik tespit edilen CIDR (ör. "192.168.1.0/24") — panel içinde göster
        self._local_net_hint = QLabel(
            "&nbsp;&nbsp;&nbsp;&nbsp;<small>Ev/ofis ağınızdaki tüm cihazları keşfeder. "
            "Bağlı olduğunuz subnet'i otomatik tespit eder (genelde /24 = 254 host).</small>",
        )
        self._local_net_hint.setWordWrap(True)
        self._local_net_hint.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(self._local_net_hint)

        # --- 5) IP aralığı (manuel CIDR — Faz 5/Batch 4) ---
        self._rb_ip_range = QRadioButton("🌐  Belirli bir IP veya IP aralığı (CIDR)")
        self._rb_ip_range.setStyleSheet("QRadioButton { font-size: 13px; padding: 6px; }")
        self._rb_ip_range.toggled.connect(self._update_ip_range_panel)
        self._group.addButton(self._rb_ip_range)
        layout.addWidget(self._rb_ip_range)

        self._ip_range_panel = QWidget()
        ip_panel_layout = QVBoxLayout(self._ip_range_panel)
        ip_panel_layout.setContentsMargins(24, 4, 4, 4)

        self._ip_range_input = QLineEdit()
        self._ip_range_input.setPlaceholderText(
            "192.168.1.0/24   veya   10.0.0.1   (tek IP = /32)",
        )
        self._ip_range_input.setStyleSheet(
            "QLineEdit { padding: 6px; font-size: 13px; font-family: Consolas, monospace; }",
        )
        self._ip_range_input.textChanged.connect(lambda _: self.completeChanged.emit())
        ip_panel_layout.addWidget(self._ip_range_input)

        self._ip_range_external_chk = QCheckBox(
            "Bu aralığın sahibiyim veya yazılı yetkim var (dış IP için zorunlu)",
        )
        self._ip_range_external_chk.stateChanged.connect(
            lambda _: self.completeChanged.emit(),
        )
        ip_panel_layout.addWidget(self._ip_range_external_chk)

        self._ip_range_panel.setVisible(False)
        layout.addWidget(self._ip_range_panel)

        layout.addStretch()

    # -----------------------------------------------------------------
    # Dinamik görünüm
    # -----------------------------------------------------------------
    def _update_url_panel(self) -> None:
        self._url_panel.setVisible(self._rb_url.isChecked())
        self.completeChanged.emit()

    def _update_ip_range_panel(self) -> None:
        self._ip_range_panel.setVisible(self._rb_ip_range.isChecked())
        self.completeChanged.emit()

    def _update_local_net_hint(self) -> None:
        """Yerel ağ seçiliyse tespit edilen CIDR'yi kullanıcıya göster."""
        if not self._rb_local_net.isChecked():
            self.completeChanged.emit()
            return
        detected = guess_local_cidr()
        if detected:
            self._local_net_hint.setText(
                f"&nbsp;&nbsp;&nbsp;&nbsp;<small>Tespit edildi: <b>{detected}</b> "
                f"— bu ağdaki cihazlar taranacak (~254 host).</small>",
            )
        else:
            self._local_net_hint.setText(
                "&nbsp;&nbsp;&nbsp;&nbsp;<small style='color: #d32f2f;'>"
                "Yerel ağ tespit edilemedi — bilgisayarın bir ağa bağlı olduğundan "
                "emin olun veya 'IP aralığı' seçeneğini kullanın.</small>",
            )
        self.completeChanged.emit()

    # -----------------------------------------------------------------
    # QWizardPage entegrasyonu
    # -----------------------------------------------------------------
    def isComplete(self) -> bool:  # noqa: N802
        """İleri aktif kriterleri."""
        if self._rb_localhost.isChecked():
            return True
        if self._rb_wifi.isChecked():
            return True
        if self._rb_local_net.isChecked():
            return guess_local_cidr() is not None
        if self._rb_ip_range.isChecked():
            cidr_text = self._ip_range_input.text().strip()
            if not cidr_text:
                return False
            # Tek IP de kabul et — /32 olarak ele alınır
            if not (is_valid_cidr(cidr_text) or self._is_bare_ip(cidr_text)):
                return False
            return True  # external_confirmed sahiplik alanına validatePage'de karar verilir
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

        if self._rb_wifi.isChecked():
            wizard.context.target = Target(
                target_type=TargetType.WIFI,
                value="*",
                description="Çevredeki Wi-Fi ağları",
            )
            wizard.context.external_target_confirmed = False
            return True

        if self._rb_local_net.isChecked():
            detected = guess_local_cidr()
            if detected is None:
                QMessageBox.warning(
                    self, "Yerel ağ tespit edilemedi",
                    "Bilgisayarın bir ağa bağlı olduğundan emin olun veya "
                    "'IP aralığı' seçeneği ile manuel CIDR girin.",
                )
                return False
            wizard.context.target = Target(
                target_type=TargetType.LOCAL_NETWORK,
                value=detected,
                description=f"Yerel ağ: {detected}",
            )
            wizard.context.external_target_confirmed = False
            return True

        if self._rb_ip_range.isChecked():
            cidr_text = self._ip_range_input.text().strip()
            # Tek IP ise /32 ekle
            if self._is_bare_ip(cidr_text):
                cidr_text = f"{cidr_text}/32"
            if not is_valid_cidr(cidr_text):
                QMessageBox.warning(
                    self, "Geçersiz CIDR",
                    "Lütfen geçerli bir IP veya CIDR formatı girin "
                    "(ör. 192.168.1.0/24, 10.0.0.1).",
                )
                return False
            wizard.context.target = Target(
                target_type=TargetType.IP_RANGE,
                value=cidr_text,
                description=f"IP aralığı: {cidr_text}",
            )
            wizard.context.external_target_confirmed = self._ip_range_external_chk.isChecked()
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

    @staticmethod
    def _is_bare_ip(text: str) -> bool:
        """'192.168.1.1' gibi CIDR'siz tek IP kontrolü (/ yoksa)."""
        if "/" in text:
            return False
        import ipaddress
        try:
            ipaddress.IPv4Address(text.strip())
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False
