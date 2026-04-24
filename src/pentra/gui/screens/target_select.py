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
from pentra.i18n import Translator, t
from pentra.models import Target, TargetType
from pentra.utils.network_utils import guess_local_cidr, is_valid_cidr


class TargetSelectPage(QWizardPage):
    """Kullanıcı neyi taramak istediğini seçer."""

    def __init__(self) -> None:
        super().__init__()

        layout = QVBoxLayout(self)

        self._info = QLabel()
        self._info.setWordWrap(True)
        self._info.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(self._info)

        self._group = QButtonGroup(self)

        # --- 1) Bu bilgisayar ---
        self._rb_localhost = QRadioButton()
        self._rb_localhost.setChecked(True)
        self._rb_localhost.setStyleSheet("QRadioButton { font-size: 13px; padding: 6px; }")
        self._rb_localhost.toggled.connect(self._update_url_panel)
        self._group.addButton(self._rb_localhost, 0)
        layout.addWidget(self._rb_localhost)

        self._desc_local = QLabel()
        self._desc_local.setWordWrap(True)
        self._desc_local.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(self._desc_local)

        # --- 2) Web sitesi ---
        self._rb_url = QRadioButton()
        self._rb_url.setStyleSheet("QRadioButton { font-size: 13px; padding: 6px; }")
        self._rb_url.toggled.connect(self._update_url_panel)
        self._group.addButton(self._rb_url, 1)
        layout.addWidget(self._rb_url)

        self._desc_url = QLabel()
        self._desc_url.setWordWrap(True)
        self._desc_url.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(self._desc_url)

        # URL alt paneli — sadece URL seçiliyken görünür
        self._url_panel = QWidget()
        panel_layout = QVBoxLayout(self._url_panel)
        panel_layout.setContentsMargins(24, 4, 4, 4)

        self._url_input = QLineEdit()
        self._url_input.setStyleSheet(
            "QLineEdit { padding: 6px; font-size: 13px; font-family: Consolas, monospace; }",
        )
        self._url_input.textChanged.connect(lambda _: self.completeChanged.emit())
        panel_layout.addWidget(self._url_input)

        self._url_chk_auth = QCheckBox()
        self._url_chk_auth.stateChanged.connect(lambda _: self.completeChanged.emit())
        panel_layout.addWidget(self._url_chk_auth)

        self._url_panel.setVisible(False)
        layout.addWidget(self._url_panel)

        # --- 3) Wi-Fi ağları ---
        self._rb_wifi = QRadioButton()
        self._rb_wifi.setStyleSheet("QRadioButton { font-size: 13px; padding: 6px; }")
        self._group.addButton(self._rb_wifi)
        layout.addWidget(self._rb_wifi)

        self._desc_wifi = QLabel()
        self._desc_wifi.setWordWrap(True)
        self._desc_wifi.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(self._desc_wifi)

        # --- 4) Yerel ağ ---
        self._rb_local_net = QRadioButton()
        self._rb_local_net.setStyleSheet("QRadioButton { font-size: 13px; padding: 6px; }")
        self._rb_local_net.toggled.connect(self._update_local_net_hint)
        self._group.addButton(self._rb_local_net)
        layout.addWidget(self._rb_local_net)

        self._local_net_hint = QLabel()
        self._local_net_hint.setWordWrap(True)
        self._local_net_hint.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(self._local_net_hint)

        # --- 5) IP aralığı ---
        self._rb_ip_range = QRadioButton()
        self._rb_ip_range.setStyleSheet("QRadioButton { font-size: 13px; padding: 6px; }")
        self._rb_ip_range.toggled.connect(self._update_ip_range_panel)
        self._group.addButton(self._rb_ip_range)
        layout.addWidget(self._rb_ip_range)

        self._ip_range_panel = QWidget()
        ip_panel_layout = QVBoxLayout(self._ip_range_panel)
        ip_panel_layout.setContentsMargins(24, 4, 4, 4)

        self._ip_range_input = QLineEdit()
        self._ip_range_input.setStyleSheet(
            "QLineEdit { padding: 6px; font-size: 13px; font-family: Consolas, monospace; }",
        )
        self._ip_range_input.textChanged.connect(lambda _: self.completeChanged.emit())
        ip_panel_layout.addWidget(self._ip_range_input)

        self._ip_range_external_chk = QCheckBox()
        self._ip_range_external_chk.stateChanged.connect(
            lambda _: self.completeChanged.emit(),
        )
        ip_panel_layout.addWidget(self._ip_range_external_chk)

        self._ip_range_panel.setVisible(False)
        layout.addWidget(self._ip_range_panel)

        layout.addStretch()

        # İlk çeviri + dil değişimine abone ol
        self.retranslate_ui()
        Translator.instance().languageChanged.connect(lambda _l: self.retranslate_ui())

    # -----------------------------------------------------------------
    # Çeviri
    # -----------------------------------------------------------------
    def retranslate_ui(self) -> None:
        self.setTitle(t("target.title"))
        self.setSubTitle(t("target.subtitle"))
        self._info.setText(t("target.info_html"))

        self._rb_localhost.setText(t("target.localhost.label"))
        self._desc_local.setText(t("target.localhost.desc_html"))

        self._rb_url.setText(t("target.url.label"))
        self._desc_url.setText(t("target.url.desc_html"))
        self._url_input.setPlaceholderText(t("target.url.placeholder"))
        self._url_chk_auth.setText(t("target.url.checkbox"))

        self._rb_wifi.setText(t("target.wifi.label"))
        self._desc_wifi.setText(t("target.wifi.desc_html"))

        self._rb_local_net.setText(t("target.local_net.label"))
        # Hint — seçili değilse default açıklama; seçiliyse tespit sonucu
        if self._rb_local_net.isChecked():
            self._update_local_net_hint()
        else:
            self._local_net_hint.setText(t("target.local_net.desc_html"))

        self._rb_ip_range.setText(t("target.ip_range.label"))
        self._ip_range_input.setPlaceholderText(t("target.ip_range.placeholder"))
        self._ip_range_external_chk.setText(t("target.ip_range.checkbox"))

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
            self._local_net_hint.setText(t("target.local_net.desc_html"))
            self.completeChanged.emit()
            return
        detected = guess_local_cidr()
        if detected:
            self._local_net_hint.setText(
                t("target.local_net.detected_html", cidr=detected),
            )
        else:
            self._local_net_hint.setText(t("target.local_net.not_detected_html"))
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
            if not (is_valid_cidr(cidr_text) or self._is_bare_ip(cidr_text)):
                return False
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
                description=t("target.desc.localhost"),
            )
            wizard.context.external_target_confirmed = False
            return True

        if self._rb_wifi.isChecked():
            wizard.context.target = Target(
                target_type=TargetType.WIFI,
                value="*",
                description=t("target.desc.wifi"),
            )
            wizard.context.external_target_confirmed = False
            return True

        if self._rb_local_net.isChecked():
            detected = guess_local_cidr()
            if detected is None:
                QMessageBox.warning(
                    self,
                    t("target.dialog.local_not_detected.title"),
                    t("target.dialog.local_not_detected.body"),
                )
                return False
            wizard.context.target = Target(
                target_type=TargetType.LOCAL_NETWORK,
                value=detected,
                description=t("target.desc.local_net", cidr=detected),
            )
            wizard.context.external_target_confirmed = False
            return True

        if self._rb_ip_range.isChecked():
            cidr_text = self._ip_range_input.text().strip()
            if self._is_bare_ip(cidr_text):
                cidr_text = f"{cidr_text}/32"
            if not is_valid_cidr(cidr_text):
                QMessageBox.warning(
                    self,
                    t("target.dialog.invalid_cidr.title"),
                    t("target.dialog.invalid_cidr.body"),
                )
                return False
            wizard.context.target = Target(
                target_type=TargetType.IP_RANGE,
                value=cidr_text,
                description=t("target.desc.ip_range", cidr=cidr_text),
            )
            wizard.context.external_target_confirmed = self._ip_range_external_chk.isChecked()
            return True

        if self._rb_url.isChecked():
            url_text = self._url_input.text().strip()
            if not self._is_url_valid(url_text):
                QMessageBox.warning(
                    self,
                    t("target.dialog.invalid_url.title"),
                    t("target.dialog.invalid_url.body"),
                )
                return False
            wizard.context.target = Target(
                target_type=TargetType.URL,
                value=url_text,
                description=t("target.desc.url", url=url_text),
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
