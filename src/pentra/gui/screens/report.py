"""Ekran 5 — Rapor Önizleme + Kaydet.

Bulguları severity'ye göre listeler, özet sayaçları gösterir ve
kullanıcının raporu masaüstüne kaydetmesine izin verir.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
    QWizardPage,
)

from pentra.config import get_desktop_dir
from pentra.gui.wizard import PentraWizard
from pentra.models import Finding, Severity
from pentra.reporting.exporters.html_exporter import HtmlExporter
from pentra.reporting.report_builder import Report, ReportBuilder, ReportSummary


class ReportPage(QWizardPage):
    """Rapor önizlemesi + HTML olarak masaüstüne kaydet butonu."""

    def __init__(self) -> None:
        super().__init__()
        self.setTitle("Tarama Raporu")
        self.setSubTitle("Bulgular aşağıdadır. Raporu masaüstüne kaydetmek için butonu kullanın.")
        self.setFinalPage(True)

        self._report: Report | None = None
        self._builder = ReportBuilder()
        self._exporter = HtmlExporter()

        layout = QVBoxLayout(self)

        # Özet alanı
        self._summary_area = QFrame()
        self._summary_area.setStyleSheet(
            "QFrame { background: #f5f7fa; border-radius: 8px; padding: 12px; }",
        )
        self._summary_layout = QHBoxLayout(self._summary_area)
        layout.addWidget(self._summary_area)

        # Bulgu listesi (scroll)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        self._findings_container = QWidget()
        self._findings_layout = QVBoxLayout(self._findings_container)
        self._findings_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        scroll.setWidget(self._findings_container)
        layout.addWidget(scroll, stretch=1)

        # Aksiyon butonları
        buttons = QHBoxLayout()
        self._btn_save = QPushButton("💾  Raporu Masaüstüne Kaydet")
        self._btn_save.setStyleSheet(
            "QPushButton { padding: 10px 20px; background: #2196f3; color: white; "
            "border: none; border-radius: 6px; font-size: 14px; } "
            "QPushButton:hover { background: #1976d2; }",
        )
        self._btn_save.clicked.connect(self._on_save_clicked)
        buttons.addWidget(self._btn_save)

        self._btn_save_as = QPushButton("📁  Farklı Yere Kaydet...")
        self._btn_save_as.clicked.connect(self._on_save_as_clicked)
        buttons.addWidget(self._btn_save_as)

        buttons.addStretch()
        layout.addLayout(buttons)

        self._save_status = QLabel("")
        self._save_status.setStyleSheet("QLabel { color: #4caf50; font-weight: bold; padding: 4px; }")
        layout.addWidget(self._save_status)

    # -----------------------------------------------------------------
    # QWizardPage entegrasyonu
    # -----------------------------------------------------------------
    def initializePage(self) -> None:  # noqa: N802
        wizard = self.wizard()
        if not isinstance(wizard, PentraWizard):
            return
        ctx = wizard.context

        if ctx.target is None or ctx.depth is None or ctx.scan_started_at is None:
            self._show_error_state("Tarama bilgileri eksik")
            return

        self._report = self._builder.build(
            target=ctx.target,
            depth=ctx.depth,
            findings=ctx.findings,
            started_at=ctx.scan_started_at,
            ended_at=ctx.scan_ended_at,
        )

        self._populate_summary(self._report.summary)
        self._populate_findings(self._report.findings)

    def validatePage(self) -> bool:  # noqa: N802
        """Bitir butonuna basıldığında token'ı iptal et (orchestrator cleanup)."""
        wizard = self.wizard()
        if isinstance(wizard, PentraWizard) and wizard.context.prepared_scan is not None:
            wizard.orchestrator.cleanup(wizard.context.prepared_scan)
        return True

    # -----------------------------------------------------------------
    # UI doldurma
    # -----------------------------------------------------------------
    def _populate_summary(self, summary: ReportSummary) -> None:
        # Eski widget'ları temizle
        while self._summary_layout.count():
            item = self._summary_layout.takeAt(0)
            w = item.widget() if item else None
            if w is not None:
                w.deleteLater()

        cards = [
            ("Kritik", summary.critical, "#8b0000"),
            ("Yüksek", summary.high, "#d32f2f"),
            ("Orta", summary.medium, "#ef6c00"),
            ("Düşük", summary.low, "#fbc02d"),
            ("Bilgi", summary.info, "#0288d1"),
        ]
        for label, count, color in cards:
            card = QFrame()
            card.setStyleSheet(
                f"QFrame {{ background: {color}; border-radius: 8px; padding: 8px 12px; }}",
            )
            cl = QVBoxLayout(card)
            cl.setContentsMargins(8, 4, 8, 4)
            count_lbl = QLabel(str(count))
            count_lbl.setStyleSheet("QLabel { color: white; font-size: 22px; font-weight: bold; }")
            count_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            label_lbl = QLabel(label)
            label_lbl.setStyleSheet("QLabel { color: white; font-size: 11px; }")
            label_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            cl.addWidget(count_lbl)
            cl.addWidget(label_lbl)
            self._summary_layout.addWidget(card)

    def _populate_findings(self, findings: list[Finding]) -> None:
        # Temizle
        while self._findings_layout.count():
            item = self._findings_layout.takeAt(0)
            w = item.widget() if item else None
            if w is not None:
                w.deleteLater()

        if not findings:
            empty = QLabel(
                "<div style='text-align: center; padding: 32px; color: #666;'>"
                "<p style='font-size: 16px;'>✅ <b>Herhangi bir bulgu tespit edilmedi.</b></p>"
                "<p>Seçtiğiniz derinlikte görünür bir sorun bulunamadı. Daha kapsamlı tarama için "
                "sonraki sürümde Standart/Derin seçeneği aktif olacak.</p>"
                "</div>",
            )
            empty.setTextFormat(Qt.TextFormat.RichText)
            empty.setWordWrap(True)
            self._findings_layout.addWidget(empty)
            return

        for f in findings:
            self._findings_layout.addWidget(_build_finding_card(f))

    def _show_error_state(self, message: str) -> None:
        lbl = QLabel(f"<p style='color: #d32f2f;'><b>Hata:</b> {message}</p>")
        lbl.setTextFormat(Qt.TextFormat.RichText)
        self._findings_layout.addWidget(lbl)

    # -----------------------------------------------------------------
    # Kaydet aksiyonları
    # -----------------------------------------------------------------
    def _on_save_clicked(self) -> None:
        if self._report is None:
            return
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
        path = get_desktop_dir() / f"Pentra_Rapor_{timestamp}.html"
        self._do_save(path)

    def _on_save_as_clicked(self) -> None:
        if self._report is None:
            return
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
        default_path = str(get_desktop_dir() / f"Pentra_Rapor_{timestamp}.html")
        selected, _ = QFileDialog.getSaveFileName(
            self,
            "Raporu Kaydet",
            default_path,
            "HTML dosyaları (*.html);;Tüm dosyalar (*)",
        )
        if selected:
            self._do_save(Path(selected))

    def _do_save(self, path: Path) -> None:
        if self._report is None:
            return
        try:
            written = self._exporter.export(self._report, path)
        except OSError as e:
            QMessageBox.warning(
                self,
                "Kayıt Başarısız",
                f"Rapor yazılamadı: {e}",
            )
            return

        self._save_status.setText(f"✅ Kaydedildi: {written}")
        wizard = self.wizard()
        if isinstance(wizard, PentraWizard):
            wizard.context.saved_report_path = str(written)


# ---------------------------------------------------------------------
# Bulgu kartı widget'ı
# ---------------------------------------------------------------------
def _build_finding_card(finding: Finding) -> QWidget:
    color = {
        Severity.CRITICAL: "#8b0000",
        Severity.HIGH: "#d32f2f",
        Severity.MEDIUM: "#ef6c00",
        Severity.LOW: "#fbc02d",
        Severity.INFO: "#0288d1",
    }.get(finding.severity, "#666")

    label_tr = {
        Severity.CRITICAL: "Kritik",
        Severity.HIGH: "Yüksek",
        Severity.MEDIUM: "Orta",
        Severity.LOW: "Düşük",
        Severity.INFO: "Bilgi",
    }.get(finding.severity, finding.severity.value)

    card = QFrame()
    card.setStyleSheet(
        f"QFrame {{ border: 1px solid #e0e0e0; border-left: 4px solid {color}; "
        f"border-radius: 6px; padding: 12px; margin: 4px 0; background: white; }}",
    )
    cl = QVBoxLayout(card)

    # Başlık satırı
    header = QHBoxLayout()
    badge = QLabel(label_tr)
    badge.setStyleSheet(
        f"QLabel {{ background: {color}; color: white; padding: 2px 8px; "
        f"border-radius: 10px; font-size: 11px; font-weight: bold; }}",
    )
    header.addWidget(badge)
    title = QLabel(f"<b>{finding.title}</b>")
    title.setTextFormat(Qt.TextFormat.RichText)
    header.addWidget(title, stretch=1)
    target = QLabel(f"<code>{finding.target}</code>")
    target.setTextFormat(Qt.TextFormat.RichText)
    target.setStyleSheet("QLabel { color: #666; font-size: 11px; }")
    header.addWidget(target)
    cl.addLayout(header)

    # Açıklama
    desc = QLabel(finding.description)
    desc.setWordWrap(True)
    desc.setStyleSheet("QLabel { color: #444; padding: 4px 0; }")
    cl.addWidget(desc)

    # Onarım
    if finding.remediation:
        rem = QLabel(f"<b>🔧 Öneri:</b> {finding.remediation}")
        rem.setTextFormat(Qt.TextFormat.RichText)
        rem.setWordWrap(True)
        rem.setStyleSheet(
            "QLabel { background: #e3f2fd; padding: 8px 12px; border-radius: 4px; "
            "color: #0d47a1; margin-top: 4px; }",
        )
        cl.addWidget(rem)

    return card
