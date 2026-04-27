"""Screen 4 — Live Progress.

Shows the real-time scan status. The scan runs on a separate QThread; the
UI updates through Scanner signals (progress_updated, finding_discovered, ...).
"""

from __future__ import annotations

from datetime import UTC, datetime

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QLabel,
    QListWidget,
    QListWidgetItem,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWizardPage,
)

from pentra.core.scan_orchestrator import ScanRequest
from pentra.core.scanner_base import ScannerBase
from pentra.gui.wizard import PentraWizard
from pentra.i18n import Translator, t
from pentra.models import (
    AuthorizationToken,
    Finding,
    ScanDepth,
    Severity,
    Target,
)
from pentra.safety.authorization import AuthorizationDenied


# ---------------------------------------------------------------------
# QThread: scan worker
# ---------------------------------------------------------------------
class _ScanWorker(QThread):
    """Worker thread that runs Scanner.scan() in the background."""

    def __init__(
        self,
        scanner: ScannerBase,
        target: Target,
        depth: ScanDepth,
        token: AuthorizationToken,
    ) -> None:
        super().__init__()
        self._scanner = scanner
        self._target = target
        self._depth = depth
        self._token = token

    def run(self) -> None:  # Qt's expected name
        self._scanner.scan(self._target, self._depth, self._token)


# ---------------------------------------------------------------------
# Main page
# ---------------------------------------------------------------------
class ProgressPage(QWizardPage):
    """Live progress + finding stream during a scan."""

    scan_finished = Signal()

    def __init__(self) -> None:
        super().__init__()
        self.setCommitPage(True)

        self._worker: _ScanWorker | None = None
        self._scanner: ScannerBase | None = None
        self._completed: bool = False

        layout = QVBoxLayout(self)

        # Target info
        self._target_label = QLabel()
        self._target_label.setStyleSheet("QLabel { font-size: 13px; color: #444; }")
        layout.addWidget(self._target_label)

        # Progress bar
        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        self._progress_bar.setTextVisible(True)
        layout.addWidget(self._progress_bar)

        # Current step description
        self._step_label = QLabel()
        self._step_label.setStyleSheet("QLabel { font-size: 12px; color: #666; padding: 4px; }")
        self._step_label.setWordWrap(True)
        layout.addWidget(self._step_label)

        # Live event list
        self._events_label = QLabel()
        self._events_label.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(self._events_label)

        self._events = QListWidget()
        self._events.setStyleSheet(
            "QListWidget { font-family: Consolas, monospace; font-size: 12px; "
            "background: #1a1a2e; color: #e5e9f0; border-radius: 6px; padding: 8px; }",
        )
        layout.addWidget(self._events, stretch=1)

        # Cancel button
        self._btn_cancel = QPushButton()
        self._btn_cancel.clicked.connect(self._on_cancel_clicked)
        layout.addWidget(self._btn_cancel)

        self.retranslate_ui()
        Translator.instance().languageChanged.connect(lambda _l: self.retranslate_ui())

    # -----------------------------------------------------------------
    # Translation — only updates static text; the live event list is
    # left as a historical stream.
    # -----------------------------------------------------------------
    def retranslate_ui(self) -> None:
        self.setTitle(t("progress.title"))
        self.setSubTitle(t("progress.subtitle"))
        self._events_label.setText(t("progress.events_header_html"))
        self._btn_cancel.setText(t("progress.btn_cancel"))

        # Show the initial message if the scan hasn't started yet
        if not self._completed and self._worker is None:
            self._target_label.setText(t("progress.target_initial"))
            self._step_label.setText(t("progress.step_initial"))

    # -----------------------------------------------------------------
    # QWizardPage integration
    # -----------------------------------------------------------------
    def initializePage(self) -> None:  # noqa: N802
        """Start the scan as soon as the page becomes active."""
        self._completed = False
        self._events.clear()
        self._progress_bar.setValue(0)
        self._step_label.setText(t("progress.step_running"))

        wizard = self.wizard()
        if not isinstance(wizard, PentraWizard):
            return
        ctx = wizard.context

        if ctx.target is None or ctx.depth is None:
            self._on_error(t("progress.error_missing_target"))
            return

        self._target_label.setText(
            t("progress.target_display_html", value=ctx.target.value, depth=ctx.depth.value),
        )
        self._target_label.setTextFormat(Qt.TextFormat.RichText)

        # 1) Run the safety chain via the orchestrator
        request = ScanRequest(
            target=ctx.target,
            depth=ctx.depth,
            user_accepted_terms=ctx.user_accepted_terms,
            external_target_confirmed=ctx.external_target_confirmed,
        )

        try:
            prepared = wizard.orchestrator.prepare(request)
        except AuthorizationDenied as e:
            self._on_error(t("progress.error_auth_denied", reason=str(e)))
            return

        ctx.prepared_scan = prepared
        ctx.scan_started_at = datetime.now(UTC)

        self._append_event(t("progress.event_security_passed"), color="#4caf50")
        self._append_event(t("progress.event_target", value=ctx.target.value))

        # 2) Subscribe to Scanner signals
        self._scanner = prepared.scanner
        self._scanner.progress_updated.connect(self._on_progress)
        self._scanner.finding_discovered.connect(self._on_finding)
        self._scanner.scan_completed.connect(self._on_scan_completed)
        self._scanner.error_occurred.connect(self._on_error)

        # 3) Start the worker thread
        self._worker = _ScanWorker(
            scanner=self._scanner,
            target=prepared.target,
            depth=prepared.depth,
            token=prepared.token,
        )
        self._worker.start()

    def isComplete(self) -> bool:  # noqa: N802
        return self._completed

    def cleanupPage(self) -> None:  # noqa: N802
        if self._worker is not None and self._worker.isRunning():
            if self._scanner is not None:
                self._scanner.cancel()
            self._worker.quit()
            self._worker.wait(3000)

    # -----------------------------------------------------------------
    # Slots — receive Scanner signals
    # -----------------------------------------------------------------
    def _on_progress(self, percent: int, message: str) -> None:
        self._progress_bar.setValue(percent)
        self._step_label.setText(message)
        self._append_event(f"[%{percent:>3}] {message}")

    def _on_finding(self, finding: Finding) -> None:
        icon = _severity_icon(finding.severity)
        color = _severity_color_hex(finding.severity)
        self._append_event(
            f"{icon} {finding.title} — {finding.target}",
            color=color,
        )
        wizard = self.wizard()
        if isinstance(wizard, PentraWizard):
            wizard.context.findings.append(finding)

    def _on_scan_completed(self) -> None:
        self._append_event(t("progress.event_completed"), color="#4caf50")
        self._progress_bar.setValue(100)
        self._btn_cancel.setEnabled(False)
        self._completed = True

        wizard = self.wizard()
        if isinstance(wizard, PentraWizard):
            wizard.context.scan_ended_at = datetime.now(UTC)

        self.completeChanged.emit()

    def _on_error(self, message: str) -> None:
        self._append_event(t("progress.event_error", message=message), color="#f44336")
        self._step_label.setText(t("progress.step_error", message=message))
        self._btn_cancel.setEnabled(False)
        self._completed = True

        wizard = self.wizard()
        if isinstance(wizard, PentraWizard):
            wizard.context.scan_error = message
            wizard.context.scan_ended_at = datetime.now(UTC)

        self.completeChanged.emit()

    # -----------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------
    def _on_cancel_clicked(self) -> None:
        if self._scanner is not None:
            self._scanner.cancel()
        self._append_event(t("progress.event_cancelled"), color="#ff9800")
        self._btn_cancel.setEnabled(False)

    def _append_event(self, text: str, color: str | None = None) -> None:
        item = QListWidgetItem(text)
        if color is not None:
            item.setForeground(QColor(color))
        self._events.addItem(item)
        self._events.scrollToBottom()


# ---------------------------------------------------------------------
# Severity visuals
# ---------------------------------------------------------------------
def _severity_icon(sev: Severity) -> str:
    return {
        Severity.CRITICAL: "🔴",
        Severity.HIGH: "🟠",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🔵",
        Severity.INFO: "⚪",
    }.get(sev, "•")


def _severity_color_hex(sev: Severity) -> str:
    return {
        Severity.CRITICAL: "#ff5252",
        Severity.HIGH: "#ff7043",
        Severity.MEDIUM: "#ffca28",
        Severity.LOW: "#42a5f5",
        Severity.INFO: "#9e9e9e",
    }.get(sev, "#e5e9f0")
