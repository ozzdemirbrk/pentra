"""PDF exporter — HtmlExporter çıktısını xhtml2pdf ile PDF'e dönüştürür.

xhtml2pdf iki ciddi sınırlamaya sahip:
    1. Default fontlar (Helvetica/Times) yalnızca Latin-1 destekler — Türkçe
       karakterler (ğ, ş, ı, ç, ö, ü) için glyph yoktur → PDF'te kutu ☐ görünür.
    2. Emoji hiçbir PDF fontunda standart olarak gömülü değil.

Çözümler:
    - PDF üretiminden önce **Arial TTF** (Windows'ta mevcut) register edilir
    - Raporun <head>'ine `@font-face` tanımı enjekte edilir
    - Body stili `font-family: 'Arial-TR'` ile override edilir
    - Emoji karakterleri regex ile strip edilir (PDF'te zaten render olmaz)
"""

from __future__ import annotations

import logging
import platform
import re
from io import BytesIO
from pathlib import Path

from pentra.reporting.exporters.html_exporter import HtmlExporter
from pentra.reporting.report_builder import Report

logger = logging.getLogger(__name__)


class PdfExportError(Exception):
    """PDF üretimi başarısız olduğunda fırlatılır."""


# Geniş emoji unicode aralıkları — PDF'te render olmazlar, kaldır
_EMOJI_RE = re.compile(
    "["
    "\U0001F300-\U0001F9FF"  # Miscellaneous Symbols, Pictographs, Emoticons
    "\U0001FA00-\U0001FAFF"  # Extended-A
    "\U0001F1E0-\U0001F1FF"  # Regional indicator (flags)
    "\U00002600-\U000027BF"  # Miscellaneous Symbols, Dingbats
    "\U0000FE00-\U0000FE0F"  # Variation Selectors
    "\u200d"                  # Zero-width joiner
    "]+",
    flags=re.UNICODE,
)


def _find_turkish_font() -> Path | None:
    """Türkçe destekli bir TrueType font dosyası bul.

    Windows'ta Arial standart olarak vardır. Farklı OS'larda DejaVu veya
    Noto arar.
    """
    candidates: list[Path] = []

    if platform.system() == "Windows":
        fonts_dir = Path("C:/Windows/Fonts")
        candidates.extend([
            fonts_dir / "arial.ttf",
            fonts_dir / "Arial.ttf",
            fonts_dir / "segoeui.ttf",
        ])
    else:
        candidates.extend([
            Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
            Path("/usr/share/fonts/TTF/DejaVuSans.ttf"),
            Path("/Library/Fonts/Arial.ttf"),
            Path("/System/Library/Fonts/Helvetica.ttc"),
        ])

    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


# Font yalnızca bir kez register edilir (process ömrü boyunca)
_FONT_REGISTERED: dict[str, str] = {}


def _ensure_font_registered() -> str | None:
    """Türkçe destekli fontu ReportLab'a register et, font adını döndür.

    Zaten kayıtlıysa tekrar çalıştırılmaz.
    """
    if _FONT_REGISTERED:
        return next(iter(_FONT_REGISTERED))

    font_path = _find_turkish_font()
    if font_path is None:
        logger.warning("PDF için Türkçe destekli TTF bulunamadı — kutu karakterler oluşabilir")
        return None

    try:
        from reportlab.pdfbase import pdfmetrics  # type: ignore[import-not-found]
        from reportlab.pdfbase.ttfonts import TTFont  # type: ignore[import-not-found]
    except ImportError:
        return None

    font_name = "PentraPDF"
    try:
        pdfmetrics.registerFont(TTFont(font_name, str(font_path)))
        _FONT_REGISTERED[font_name] = str(font_path)
        logger.info("PDF için font register edildi: %s → %s", font_name, font_path)
        return font_name
    except Exception as e:  # noqa: BLE001
        logger.warning("Font register başarısız (%s): %s", font_path, e)
        return None


def _strip_emojis(text: str) -> str:
    """PDF'te render olmayan emoji karakterlerini kaldırır."""
    return _EMOJI_RE.sub("", text)


def _inject_pdf_styles(html: str, font_name: str | None) -> str:
    """HTML <head>'ine PDF'e özel CSS enjekte et — font override + basit reset."""
    font_family = font_name if font_name else "Helvetica"
    pdf_css = f"""
<style>
    /* PDF-özel override — xhtml2pdf modern CSS'yi desteklemiyor */
    body, p, div, span, td, th, h1, h2, h3, h4, li, a, pre, code {{
        font-family: "{font_family}", "Helvetica", sans-serif;
    }}
    pre, code {{
        font-size: 9pt;
        background: #f4f4f4;
        padding: 4px;
    }}
    /* Kodu sarmaya zorla — PDF'te overflow scroll olmaz */
    pre {{ white-space: pre-wrap; word-wrap: break-word; }}
</style>
"""
    # <head> kapanmasından önce inject et — varolan CSS'i geçersiz kılsın
    return html.replace("</head>", pdf_css + "</head>", 1)


class PdfExporter:
    """Report → PDF dosyası (xhtml2pdf üzerinden HTML'den dönüştürme)."""

    def __init__(self, html_exporter: HtmlExporter | None = None) -> None:
        self._html_exporter = html_exporter if html_exporter is not None else HtmlExporter()
        # Font'u lazy register et — yalnızca ihtiyaç olunca
        self._font_name: str | None = None

    def render_bytes(self, report: Report) -> bytes:
        """Raporu PDF byte dizisine dönüştürür."""
        # Font'u ilk PDF üretiminde register et
        if self._font_name is None:
            self._font_name = _ensure_font_registered()

        html = self._html_exporter.render(report)

        # PDF-için uyarlama: emoji strip + font CSS inject
        html = _strip_emojis(html)
        html = _inject_pdf_styles(html, self._font_name)

        try:
            from xhtml2pdf import pisa  # type: ignore[import-not-found]
        except ImportError as e:
            raise PdfExportError(
                f"xhtml2pdf yüklü değil: {e}. `pip install xhtml2pdf` ile kurun.",
            ) from e

        buffer = BytesIO()
        pisa_status = pisa.CreatePDF(src=html, dest=buffer, encoding="utf-8")
        if pisa_status.err:
            raise PdfExportError(
                f"PDF üretimi başarısız: {pisa_status.err} hata(lar)ı oluştu.",
            )
        return buffer.getvalue()

    def export(self, report: Report, output_path: Path) -> Path:
        """PDF'i `output_path`'a yazar, dosya yolunu döner."""
        pdf_bytes = self.render_bytes(report)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(pdf_bytes)
        return output_path
