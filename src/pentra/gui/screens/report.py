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
from pentra.reporting.comparison import compare as compare_scans
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
        self._html_exporter = HtmlExporter()

        layout = QVBoxLayout(self)

        # Risk skoru + karşılaştırma banner — initializePage'de doldurulur
        self._risk_banner = QFrame()
        self._risk_banner.setStyleSheet(
            "QFrame { background: #f5f7fa; border-radius: 8px; padding: 12px; }",
        )
        self._risk_banner_layout = QVBoxLayout(self._risk_banner)
        self._risk_banner_layout.setContentsMargins(12, 10, 12, 10)
        layout.addWidget(self._risk_banner)

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

        # Aksiyon butonları — HTML raporu kaydet (varsayılan masaüstü / farklı yer)
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

        # 1) Önce risk skoru için bir kez build et (comparison olmadan)
        preliminary = self._builder.build(
            target=ctx.target,
            depth=ctx.depth,
            findings=ctx.findings,
            started_at=ctx.scan_started_at,
            ended_at=ctx.scan_ended_at,
        )

        # 2) Geçmişte aynı hedef için tarama var mı bak
        comparison = None
        history = wizard.scan_history
        if history is not None:
            try:
                previous = history.find_previous(ctx.target)
                if previous is not None:
                    comparison = compare_scans(
                        previous=previous,
                        current_findings=ctx.findings,
                        current_risk_score=preliminary.risk.score,
                    )
            except Exception:  # noqa: BLE001
                # Geçmiş sorgusu başarısız olsa bile rapor çalışmaya devam
                pass

        # 3) Nihai Report — comparison ile
        self._report = self._builder.build(
            target=ctx.target,
            depth=ctx.depth,
            findings=ctx.findings,
            started_at=ctx.scan_started_at,
            ended_at=ctx.scan_ended_at,
            comparison=comparison,
        )

        # 4) Geçmişe kaydet (bir sonraki tarama için karşılaştırma bazı)
        if history is not None:
            try:
                history.record(self._report)
            except Exception:  # noqa: BLE001
                pass

        self._populate_risk_banner(self._report)
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
    def _populate_risk_banner(self, report: Report) -> None:
        """Risk skoru + karşılaştırma bilgisi — GUI üst banner."""
        # Önceki widget'ları temizle
        while self._risk_banner_layout.count():
            item = self._risk_banner_layout.takeAt(0)
            w = item.widget() if item else None
            if w is not None:
                w.deleteLater()

        # Risk skoru satırı
        risk_row = QHBoxLayout()

        risk_label = QLabel(
            f"<div style='font-size: 11px; color: #666;'>GENEL RİSK</div>"
            f"<div style='font-size: 28px; font-weight: 700; color: {report.risk.color};'>"
            f"{report.risk.score_display}/10 &nbsp;"
            f"<span style='font-size: 14px; text-transform: uppercase;'>{report.risk.label}</span>"
            f"</div>",
        )
        risk_label.setTextFormat(Qt.TextFormat.RichText)
        risk_row.addWidget(risk_label)
        risk_row.addStretch()

        if report.comparison is not None:
            cmp = report.comparison
            trend_icon = {
                "improved": "📉 İyileşme",
                "worsened": "📈 Kötüleşme",
                "stable": "➡️ Durağan",
            }.get(cmp.risk_trend, "")
            trend_color = {
                "improved": "#388e3c",
                "worsened": "#d32f2f",
                "stable": "#666",
            }.get(cmp.risk_trend, "#666")

            delta_text = (
                f"{cmp.risk_delta:+.1f}" if abs(cmp.risk_delta) >= 0.1 else "0.0"
            )
            cmp_label = QLabel(
                f"<div style='font-size: 11px; color: #666; text-align: right;'>ÖNCEKİ TARAMAYLA</div>"
                f"<div style='font-size: 14px; color: {trend_color}; font-weight: 600; text-align: right;'>"
                f"{trend_icon} ({delta_text})</div>",
            )
            cmp_label.setTextFormat(Qt.TextFormat.RichText)
            risk_row.addWidget(cmp_label)

        self._risk_banner_layout.addLayout(risk_row)

        # Yönetici özeti satırı
        summary_label = QLabel(report.risk.summary_tr)
        summary_label.setTextFormat(Qt.TextFormat.RichText)
        summary_label.setWordWrap(True)
        summary_label.setStyleSheet(
            "QLabel { color: #444; font-size: 13px; padding: 6px 0 0 0; }",
        )
        self._risk_banner_layout.addWidget(summary_label)

        # Karşılaştırma kartları (önceki tarama varsa)
        if report.comparison is not None:
            cmp = report.comparison
            cmp_row = QHBoxLayout()
            cmp_row.setContentsMargins(0, 10, 0, 0)
            for count, label, color, bg in (
                (cmp.new_count, "Yeni Risk", "#d32f2f", "#ffebee"),
                (cmp.resolved_count, "Çözülmüş", "#388e3c", "#e8f5e9"),
                (cmp.unchanged_count, "Değişmemiş", "#455a64", "#eceff1"),
            ):
                card = QFrame()
                card.setStyleSheet(
                    f"QFrame {{ background: {bg}; border-left: 3px solid {color}; "
                    f"border-radius: 4px; padding: 6px 10px; }}",
                )
                cl = QVBoxLayout(card)
                cl.setContentsMargins(6, 4, 6, 4)
                num = QLabel(str(count))
                num.setStyleSheet(f"QLabel {{ color: {color}; font-size: 20px; font-weight: 700; }}")
                txt = QLabel(label)
                txt.setStyleSheet("QLabel { color: #555; font-size: 10px; text-transform: uppercase; }")
                cl.addWidget(num)
                cl.addWidget(txt)
                cmp_row.addWidget(card, stretch=1)

            self._risk_banner_layout.addLayout(cmp_row)

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
    def _timestamped_path(self) -> Path:
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M")
        return get_desktop_dir() / f"Pentra_Rapor_{ts}.html"

    def _on_save_clicked(self) -> None:
        if self._report is None:
            return
        self._do_save(self._timestamped_path())

    def _on_save_as_clicked(self) -> None:
        if self._report is None:
            return
        selected, _ = QFileDialog.getSaveFileName(
            self,
            "Raporu Kaydet",
            str(self._timestamped_path()),
            "HTML dosyaları (*.html);;Tüm dosyalar (*)",
        )
        if selected:
            self._do_save(Path(selected))

    def _do_save(self, path: Path) -> None:
        if self._report is None:
            return
        try:
            written = self._html_exporter.export(self._report, path)
        except OSError as e:
            QMessageBox.warning(self, "Kayıt Başarısız", f"Rapor yazılamadı: {e}")
            return
        self._save_status.setText(f"✅ Kaydedildi: {written}")
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
