"""Ekran 4 — Canlı İlerleme.

Taramanın gerçek zamanlı durumunu gösterir. Tarama ayrı bir QThread'de
koşar; Scanner sinyalleri (progress_updated, finding_discovered, ...)
üzerinden UI güncellenir.
"""

from __future__ import annotations

from datetime import datetime, timezone

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
from pentra.gui.wizard import PageId, PentraWizard
from pentra.models import (
    AuthorizationToken,
    Finding,
    ScanDepth,
    Severity,
    Target,
)
from pentra.safety.authorization import AuthorizationDenied


# ---------------------------------------------------------------------
# QThread: Tarama işçisi
# ---------------------------------------------------------------------
class _ScanWorker(QThread):
    """Scanner.scan() metodunu arka planda koşturan işçi thread."""

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

    def run(self) -> None:  # Qt'nin beklediği isim
        # Bu fonksiyon worker thread'de çalışır. Scanner sinyalleri ana
        # thread'e queued connection ile otomatik iletilir.
        self._scanner.scan(self._target, self._depth, self._token)


# ---------------------------------------------------------------------
# Ana sayfa
# ---------------------------------------------------------------------
class ProgressPage(QWizardPage):
    """Tarama sırasındaki ilerleme + bulgu akışı."""

    # Rapor sayfasına geçiş için tetikleyici
    scan_finished = Signal()

    def __init__(self) -> None:
        super().__init__()
        self.setTitle("Tarama İlerliyor")
        self.setSubTitle("Lütfen bekleyin — bu işlem birkaç dakika sürebilir.")
        self.setCommitPage(True)  # Bu sayfadan sonra geri dönüş kapalı

        self._worker: _ScanWorker | None = None
        self._scanner: ScannerBase | None = None
        self._completed: bool = False

        layout = QVBoxLayout(self)

        # Hedef bilgisi
        self._target_label = QLabel("Hedef: (hazırlanıyor...)")
        self._target_label.setStyleSheet("QLabel { font-size: 13px; color: #444; }")
        layout.addWidget(self._target_label)

        # İlerleme çubuğu
        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        self._progress_bar.setTextVisible(True)
        layout.addWidget(self._progress_bar)

        # Mevcut adım açıklaması
        self._step_label = QLabel("Başlıyor...")
        self._step_label.setStyleSheet("QLabel { font-size: 12px; color: #666; padding: 4px; }")
        self._step_label.setWordWrap(True)
        layout.addWidget(self._step_label)

        # Canlı olay listesi
        events_label = QLabel("<b>Canlı akış:</b>")
        events_label.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(events_label)

        self._events = QListWidget()
        self._events.setStyleSheet(
            "QListWidget { font-family: Consolas, monospace; font-size: 12px; "
            "background: #1a1a2e; color: #e5e9f0; border-radius: 6px; padding: 8px; }",
        )
        layout.addWidget(self._events, stretch=1)

        # İptal butonu
        self._btn_cancel = QPushButton("❌  İptal et")
        self._btn_cancel.clicked.connect(self._on_cancel_clicked)
        layout.addWidget(self._btn_cancel)

    # -----------------------------------------------------------------
    # QWizardPage entegrasyonu
    # -----------------------------------------------------------------
    def initializePage(self) -> None:  # noqa: N802
        """Sayfa aktifleştiğinde taramayı başlat."""
        # Önceki state'i temizle (kullanıcı geri-ileri yaparsa)
        self._completed = False
        self._events.clear()
        self._progress_bar.setValue(0)
        self._step_label.setText("Güvenlik kontrolleri yapılıyor...")

        wizard = self.wizard()
        if not isinstance(wizard, PentraWizard):
            return
        ctx = wizard.context

        if ctx.target is None or ctx.depth is None:
            self._on_error("Hedef veya derinlik seçilmedi")
            return

        self._target_label.setText(
            f"Hedef: <b>{ctx.target.value}</b> · Derinlik: <b>{ctx.depth.value}</b>",
        )
        self._target_label.setTextFormat(Qt.TextFormat.RichText)

        # 1) Orchestrator üzerinden güvenlik zincirini geç
        request = ScanRequest(
            target=ctx.target,
            depth=ctx.depth,
            user_accepted_terms=ctx.user_accepted_terms,
            external_target_confirmed=ctx.external_target_confirmed,
        )

        try:
            prepared = wizard.orchestrator.prepare(request)
        except AuthorizationDenied as e:
            self._on_error(f"Yetki reddedildi: {e}")
            return

        ctx.prepared_scan = prepared
        ctx.scan_started_at = datetime.now(timezone.utc)

        self._append_event("✔️ Güvenlik zinciri geçildi (scope + auth + token)", color="#4caf50")
        self._append_event(f"🎯 Hedef: {ctx.target.value}")

        # 2) Scanner sinyallerine abone ol
        self._scanner = prepared.scanner
        self._scanner.progress_updated.connect(self._on_progress)
        self._scanner.finding_discovered.connect(self._on_finding)
        self._scanner.scan_completed.connect(self._on_scan_completed)
        self._scanner.error_occurred.connect(self._on_error)

        # 3) Worker thread başlat
        self._worker = _ScanWorker(
            scanner=self._scanner,
            target=prepared.target,
            depth=prepared.depth,
            token=prepared.token,
        )
        self._worker.start()

    def isComplete(self) -> bool:  # noqa: N802
        """İleri (Finish) butonu sadece tarama bitince aktif."""
        return self._completed

    def cleanupPage(self) -> None:  # noqa: N802
        """Kullanıcı geri giderse işçiyi durdur."""
        if self._worker is not None and self._worker.isRunning():
            if self._scanner is not None:
                self._scanner.cancel()
            self._worker.quit()
            self._worker.wait(3000)

    # -----------------------------------------------------------------
    # Slot'lar — Scanner sinyallerini yakalar
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
        self._append_event("✅ Tarama tamamlandı!", color="#4caf50")
        self._progress_bar.setValue(100)
        self._btn_cancel.setEnabled(False)
        self._completed = True

        wizard = self.wizard()
        if isinstance(wizard, PentraWizard):
            wizard.context.scan_ended_at = datetime.now(timezone.utc)

        self.completeChanged.emit()
        # Kullanıcı İleri'ye basınca rapor sayfasına geçecek

    def _on_error(self, message: str) -> None:
        self._append_event(f"❌ HATA: {message}", color="#f44336")
        self._step_label.setText(f"Hata: {message}")
        self._btn_cancel.setEnabled(False)
        self._completed = True  # Hata da bitme sayılır; rapor sayfası boş rapor gösterecek

        wizard = self.wizard()
        if isinstance(wizard, PentraWizard):
            wizard.context.scan_error = message
            wizard.context.scan_ended_at = datetime.now(timezone.utc)

        self.completeChanged.emit()

    # -----------------------------------------------------------------
    # Yardımcılar
    # -----------------------------------------------------------------
    def _on_cancel_clicked(self) -> None:
        if self._scanner is not None:
            self._scanner.cancel()
        self._append_event("⏹️  Kullanıcı iptal etti", color="#ff9800")
        self._btn_cancel.setEnabled(False)

    def _append_event(self, text: str, color: str | None = None) -> None:
        item = QListWidgetItem(text)
        if color is not None:
            item.setForeground(QColor(color))
        self._events.addItem(item)
        self._events.scrollToBottom()


# ---------------------------------------------------------------------
# Severity görselleri
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
