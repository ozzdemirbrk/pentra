"""New-version notification dialog.

Not modal — the user can dismiss it. Doesn't open at all when offline.
"""

from __future__ import annotations

import webbrowser

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from pentra import __version__
from pentra.i18n import Translator, t


class UpdateNotificationDialog(QDialog):
    """Notification shown when a new version is detected."""

    def __init__(
        self,
        *,
        new_version: str,
        release_url: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._release_url = release_url
        self._new_version = new_version

        self.setWindowFlags(
            Qt.WindowType.Dialog
            | Qt.WindowType.WindowTitleHint
            | Qt.WindowType.WindowCloseButtonHint,
        )
        self.setModal(False)
        self.setMinimumWidth(420)

        self._title_label = QLabel()
        self._title_label.setStyleSheet("QLabel { font-size: 14px; font-weight: 700; }")
        self._body_label = QLabel()
        self._body_label.setWordWrap(True)
        self._body_label.setTextFormat(Qt.TextFormat.RichText)

        self._btn_open = QPushButton()
        self._btn_open.setStyleSheet(
            "QPushButton { padding: 8px 16px; background: #2196f3; color: white; "
            "border: none; border-radius: 6px; font-weight: 600; }"
            "QPushButton:hover { background: #1976d2; }",
        )
        self._btn_open.clicked.connect(self._on_open_clicked)

        self._btn_later = QPushButton()
        self._btn_later.clicked.connect(self.reject)

        buttons = QHBoxLayout()
        buttons.addStretch()
        buttons.addWidget(self._btn_later)
        buttons.addWidget(self._btn_open)

        layout = QVBoxLayout(self)
        layout.addWidget(self._title_label)
        layout.addWidget(self._body_label)
        layout.addLayout(buttons)

        self.retranslate_ui()
        Translator.instance().languageChanged.connect(lambda _l: self.retranslate_ui())

    def retranslate_ui(self) -> None:
        self.setWindowTitle(t("update.dialog.title"))
        self._title_label.setText(
            t("update.dialog.heading", new_version=self._new_version),
        )
        self._body_label.setText(
            t(
                "update.dialog.body_html",
                new_version=self._new_version,
                current_version=__version__,
            ),
        )
        self._btn_open.setText(t("update.dialog.btn_open"))
        self._btn_later.setText(t("update.dialog.btn_later"))

    def _on_open_clicked(self) -> None:
        webbrowser.open(self._release_url)
        self.accept()
