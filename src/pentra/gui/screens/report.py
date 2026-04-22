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
from pentra.reporting.exporters.markdown_exporter import MarkdownExporter
from pentra.reporting.exporters.pdf_exporter import PdfExporter, PdfExportError
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
        self._html_exporter = HtmlExporter()
        self._md_exporter = MarkdownExporter()
        self._pdf_exporter = PdfExporter(html_exporter=self._html_exporter)

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

        # Aksiyon butonları — 3 format
        buttons = QHBoxLayout()

        self._btn_save_html = QPushButton("💾  HTML Kaydet")
        self._btn_save_html.setStyleSheet(
            "QPushButton { padding: 10px 20px; background: #2196f3; color: white; "
            "border: none; border-radius: 6px; font-size: 14px; } "
            "QPushButton:hover { background: #1976d2; }",
        )
        self._btn_save_html.clicked.connect(self._on_save_html_clicked)
        buttons.addWidget(self._btn_save_html)

        self._btn_save_pdf = QPushButton("📄  PDF Kaydet")
        self._btn_save_pdf.setStyleSheet(
            "QPushButton { padding: 10px 20px; background: #d32f2f; color: white; "
            "border: none; border-radius: 6px; font-size: 14px; } "
            "QPushButton:hover { background: #b71c1c; }",
        )
        self._btn_save_pdf.clicked.connect(self._on_save_pdf_clicked)
        buttons.addWidget(self._btn_save_pdf)

        self._btn_save_md = QPushButton("📝  Markdown Kaydet")
        self._btn_save_md.setStyleSheet(
            "QPushButton { padding: 10px 20px; background: #424242; color: white; "
            "border: none; border-radius: 6px; font-size: 14px; } "
            "QPushButton:hover { background: #212121; }",
        )
        self._btn_save_md.clicked.connect(self._on_save_md_clicked)
        buttons.addWidget(self._btn_save_md)

        self._btn_save_as = QPushButton("📁  Farklı Yere...")
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
    def _timestamped_path(self, extension: str) -> Path:
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M")
        return get_desktop_dir() / f"Pentra_Rapor_{ts}.{extension}"

    def _on_save_html_clicked(self) -> None:
        if self._report is None:
            return
        self._do_save_html(self._timestamped_path("html"))

    def _on_save_pdf_clicked(self) -> None:
        if self._report is None:
            return
        self._do_save_pdf(self._timestamped_path("pdf"))

    def _on_save_md_clicked(self) -> None:
        if self._report is None:
            return
        self._do_save_md(self._timestamped_path("md"))

    def _on_save_as_clicked(self) -> None:
        """Format seçimli kaydetme — uzantıya göre exporter seçer."""
        if self._report is None:
            return
        default_path = str(self._timestamped_path("html"))
        selected, chosen_filter = QFileDialog.getSaveFileName(
            self,
            "Raporu Kaydet",
            default_path,
            "HTML dosyaları (*.html);;PDF dosyaları (*.pdf);;Markdown (*.md);;Tüm dosyalar (*)",
        )
        if not selected:
            return
        path = Path(selected)
        ext = path.suffix.lower()
        if ext == ".pdf":
            self._do_save_pdf(path)
        elif ext == ".md":
            self._do_save_md(path)
        else:
            self._do_save_html(path)

    def _do_save_html(self, path: Path) -> None:
        if self._report is None:
            return
        try:
            written = self._html_exporter.export(self._report, path)
        except OSError as e:
            QMessageBox.warning(self, "Kayıt Başarısız", f"HTML yazılamadı: {e}")
            return
        self._save_status.setText(f"✅ Kaydedildi: {written}")
        self._store_saved_path(written)

    def _do_save_pdf(self, path: Path) -> None:
        if self._report is None:
            return
        try:
            written = self._pdf_exporter.export(self._report, path)
        except (OSError, PdfExportError) as e:
            QMessageBox.warning(self, "PDF Başarısız", f"PDF oluşturulamadı: {e}")
            return
        self._save_status.setText(f"✅ PDF kaydedildi: {written}")
        self._store_saved_path(written)

    def _do_save_md(self, path: Path) -> None:
        if self._report is None:
            return
        try:
            written = self._md_exporter.export(self._report, path)
        except OSError as e:
            QMessageBox.warning(self, "Kayıt Başarısız", f"Markdown yazılamadı: {e}")
            return
        self._save_status.setText(f"✅ Markdown kaydedildi: {written}")
        self._store_saved_path(written)

    def _store_saved_path(self, written: Path) -> None:
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
