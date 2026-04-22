"""PDF exporter — HtmlExporter çıktısını xhtml2pdf ile PDF'e dönüştürür.

xhtml2pdf modern CSS'nin bazı özelliklerini (flexbox, grid) tam desteklemez,
ama Pentra raporu için yeterli düzeyde render edebilir. Rapor grafiği
görsel olarak HTML sürümü kadar şık olmayabilir ama okunur ve paylaşılabilir.
"""

from __future__ import annotations

from io import BytesIO
from pathlib import Path

from pentra.reporting.exporters.html_exporter import HtmlExporter
from pentra.reporting.report_builder import Report


class PdfExportError(Exception):
    """PDF üretimi başarısız olduğunda fırlatılır."""


class PdfExporter:
    """Report → PDF dosyası (xhtml2pdf üzerinden HTML'den dönüştürme)."""

    def __init__(self, html_exporter: HtmlExporter | None = None) -> None:
        # HtmlExporter'ı enjeksiyon için bırakıyoruz; yoksa varsayılanı kullan
        self._html_exporter = html_exporter if html_exporter is not None else HtmlExporter()

    def render_bytes(self, report: Report) -> bytes:
        """Raporu PDF byte dizisine dönüştürür (dosyaya yazmadan, test için de kullanışlı)."""
        html = self._html_exporter.render(report)

        # xhtml2pdf lazy import — ImportError olursa anlamlı mesaj ver
        try:
            from xhtml2pdf import pisa  # type: ignore[import-not-found]
        except ImportError as e:
            raise PdfExportError(
                f"xhtml2pdf yüklü değil: {e}. `pip install xhtml2pdf` ile kurun.",
            ) from e

        buffer = BytesIO()
        # xhtml2pdf bizim HTML'imizi almaya çalışır; bazı CSS desteklenmeyebilir
        pisa_status = pisa.CreatePDF(src=html, dest=buffer, encoding="utf-8")
        if pisa_status.err:
            raise PdfExportError(
                f"PDF üretimi başarısız: {pisa_status.err} hata(lar)ı oluştu. "
                f"HTML'de desteklenmeyen bir yapı olabilir.",
            )
        return buffer.getvalue()

    def export(self, report: Report, output_path: Path) -> Path:
        """PDF'i `output_path`'a yazar, dosya yolunu döner."""
        pdf_bytes = self.render_bytes(report)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(pdf_bytes)
        return output_path
