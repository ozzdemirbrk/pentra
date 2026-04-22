"""PDF exporter — ayrı sade Jinja2 şablonuyla xhtml2pdf'e uygun HTML üretir.

Önceki yaklaşım (HtmlExporter'ın çıktısını dönüştürmek) iki sorun yaratıyordu:
    1. Modern CSS (flexbox, grid) xhtml2pdf'te render olmuyor → tasarım bozuk
    2. Türkçe karakterler default font'larda glyph eksikliğinden kutu

Bu sürümde: PDF için özel hazırlanmış `pdf_report.html.j2` şablonu. Tablo
tabanlı layout, emoji yok, @font-face ile Arial (veya DejaVu) yüklenir,
link_callback TTF yolunu çözer.
"""

from __future__ import annotations

import logging
import platform
from datetime import datetime
from io import BytesIO
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from pentra.knowledge.remediations_tr import get_guide
from pentra.reporting.logo import get_logo_data_uri
from pentra.reporting.report_builder import Report

logger = logging.getLogger(__name__)

_TEMPLATE_DIR: Path = Path(__file__).parent.parent / "templates"
_TEMPLATE_NAME: str = "pdf_report.html.j2"

# Bir kez register ederiz — process ömrü boyunca
_FONT_REGISTERED: bool = False


class PdfExportError(Exception):
    """PDF üretimi başarısız olduğunda fırlatılır."""


def _register_pdf_font() -> bool:
    """Türkçe destekli TTF'yi ReportLab'a register et, başarıda True döner."""
    global _FONT_REGISTERED
    if _FONT_REGISTERED:
        return True

    regular, bold = _find_font_files()
    if regular is None:
        return False

    try:
        from reportlab.pdfbase import pdfmetrics  # type: ignore[import-not-found]
        from reportlab.pdfbase.ttfonts import TTFont  # type: ignore[import-not-found]
    except ImportError:
        return False

    try:
        pdfmetrics.registerFont(TTFont("ArialTR", str(regular)))
        if bold is not None:
            pdfmetrics.registerFont(TTFont("ArialTR-Bold", str(bold)))
        # xhtml2pdf için aynı font'u italic/bolditalic variantları olarak da
        # göster — eksik variant istendiğinde fallback olmasın
        try:
            from reportlab.pdfbase.pdfmetrics import registerFontFamily  # type: ignore[import-not-found]
            registerFontFamily(
                "ArialTR",
                normal="ArialTR",
                bold="ArialTR-Bold" if bold is not None else "ArialTR",
                italic="ArialTR",
                boldItalic="ArialTR-Bold" if bold is not None else "ArialTR",
            )
        except Exception:  # noqa: BLE001
            pass
        _FONT_REGISTERED = True
        logger.info("PDF fontu register edildi: %s", regular)
        return True
    except Exception as e:  # noqa: BLE001
        logger.warning("PDF font register başarısız: %s", e)
        return False


# ---------------------------------------------------------------------
# Font tespiti
# ---------------------------------------------------------------------
def _find_font_files() -> tuple[Path | None, Path | None]:
    """(regular, bold) font dosyalarını tespit et. Yoksa (None, None)."""
    candidates: list[tuple[Path, Path]] = []

    if platform.system() == "Windows":
        fonts = Path("C:/Windows/Fonts")
        candidates.append((fonts / "arial.ttf", fonts / "arialbd.ttf"))
        candidates.append((fonts / "Arial.ttf", fonts / "Arialbd.ttf"))
        candidates.append((fonts / "segoeui.ttf", fonts / "seguisb.ttf"))
    elif platform.system() == "Darwin":
        candidates.append((
            Path("/Library/Fonts/Arial.ttf"),
            Path("/Library/Fonts/Arial Bold.ttf"),
        ))
    else:
        for base in (
            Path("/usr/share/fonts/truetype/dejavu"),
            Path("/usr/share/fonts/TTF"),
        ):
            candidates.append((base / "DejaVuSans.ttf", base / "DejaVuSans-Bold.ttf"))

    for reg, bold in candidates:
        if reg.exists():
            return reg, (bold if bold.exists() else None)
    return None, None


# ---------------------------------------------------------------------
# Jinja filtreleri
# ---------------------------------------------------------------------
def _tr_datetime(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M")


_SEVERITY_TR = {
    "critical": "Kritik",
    "high": "Yuksek",
    "medium": "Orta",
    "low": "Dusuk",
    "info": "Bilgi",
}


def _severity_label(value: str) -> str:
    return _SEVERITY_TR.get(value, value.capitalize())


# ---------------------------------------------------------------------
# PdfExporter
# ---------------------------------------------------------------------
class PdfExporter:
    """Report → PDF (xhtml2pdf ile ayrı sade şablondan)."""

    def __init__(
        self,
        template_dir: Path | None = None,
        *,
        html_exporter: object | None = None,  # Backward-compat
    ) -> None:
        del html_exporter
        self._template_dir = template_dir if template_dir is not None else _TEMPLATE_DIR
        self._env = Environment(
            loader=FileSystemLoader(str(self._template_dir)),
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self._env.filters["tr_datetime"] = _tr_datetime
        self._env.filters["severity_label"] = _severity_label
        self._env.globals["get_remediation_guide"] = get_guide
        self._env.globals["logo_data_uri"] = get_logo_data_uri()

        # Font'u hemen register et — link_callback yerine pdfmetrics yolu
        self._font_available = _register_pdf_font()
        if not self._font_available:
            logger.warning(
                "PDF için Türkçe destekli TTF bulunamadı — kutu karakter oluşabilir.",
            )

    def render_html(self, report: Report) -> str:
        template = self._env.get_template(_TEMPLATE_NAME)
        return template.render(report=report, generated_at=datetime.now())

    def render_bytes(self, report: Report) -> bytes:
        html = self.render_html(report)

        try:
            from xhtml2pdf import pisa  # type: ignore[import-not-found]
        except ImportError as e:
            raise PdfExportError(
                f"xhtml2pdf yüklü değil: {e}. `pip install xhtml2pdf` ile kurun.",
            ) from e

        buffer = BytesIO()
        pisa_status = pisa.CreatePDF(
            src=html,
            dest=buffer,
            encoding="utf-8",
            link_callback=self._link_callback,
        )
        if pisa_status.err:
            raise PdfExportError(
                f"PDF üretimi başarısız: {pisa_status.err} hata(lar)ı oluştu.",
            )
        return buffer.getvalue()

    def export(self, report: Report, output_path: Path) -> Path:
        pdf_bytes = self.render_bytes(report)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(pdf_bytes)
        return output_path

    # -----------------------------------------------------------------
    # xhtml2pdf link_callback — @font-face url() çağrısını engelle,
    # img data URI'lerini değişmeden geçir
    # -----------------------------------------------------------------
    def _link_callback(self, uri: str, rel: str) -> str:
        # Font url()'leri — artık pdfmetrics.registerFont kullanıyoruz
        # @font-face template'te YOK, bu callback'e font URI'si gelmemeli
        if uri.startswith("data:"):
            return uri
        if uri.startswith("file:///"):
            return uri[8:]
        return uri
