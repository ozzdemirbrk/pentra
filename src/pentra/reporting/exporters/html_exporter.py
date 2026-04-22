"""HTML exporter — Jinja2 ile ReportData'yı standalone HTML dosyasına çevirir."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from pentra.knowledge.remediations_tr import get_guide

from pentra.reporting.report_builder import Report

_TEMPLATE_DIR: Path = Path(__file__).parent.parent / "templates"
_TEMPLATE_NAME: str = "basic_report.html.j2"


# ---------------------------------------------------------------------
# Filtreler
# ---------------------------------------------------------------------
def _tr_datetime(value: datetime) -> str:
    """TR formatında tarih+saat (2026-04-21 14:30)."""
    return value.strftime("%Y-%m-%d %H:%M")


_SEVERITY_TR: dict[str, str] = {
    "critical": "Kritik",
    "high": "Yüksek",
    "medium": "Orta",
    "low": "Düşük",
    "info": "Bilgi",
}

_SEVERITY_COLOR: dict[str, str] = {
    "critical": "#8b0000",
    "high": "#d32f2f",
    "medium": "#ef6c00",
    "low": "#fbc02d",
    "info": "#0288d1",
}


def _severity_label(value: str) -> str:
    return _SEVERITY_TR.get(value, value.capitalize())


def _severity_color(value: str) -> str:
    return _SEVERITY_COLOR.get(value, "#666")


# ---------------------------------------------------------------------
# Exporter
# ---------------------------------------------------------------------
class HtmlExporter:
    """Report → HTML dosyası."""

    def __init__(self, template_dir: Path | None = None) -> None:
        self._template_dir = template_dir if template_dir is not None else _TEMPLATE_DIR
        # Autoescape'i template adında ".html" geçen her şey için aç.
        # (select_autoescape sadece son uzantıya bakar — ".html.j2" kaçar.)
        def _needs_autoescape(name: str | None) -> bool:
            return bool(name) and (".html" in name or ".xml" in name)

        self._env = Environment(
            loader=FileSystemLoader(str(self._template_dir)),
            autoescape=_needs_autoescape,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self._env.filters["tr_datetime"] = _tr_datetime
        self._env.filters["severity_label"] = _severity_label
        self._env.filters["severity_color"] = _severity_color
        # Detaylı onarım rehberi arama — her finding için template'den çağrılır
        self._env.globals["get_remediation_guide"] = get_guide

    def render(self, report: Report) -> str:
        template = self._env.get_template(_TEMPLATE_NAME)
        return template.render(
            report=report,
            generated_at=datetime.now(),
        )

    def export(self, report: Report, output_path: Path) -> Path:
        """Rapor HTML'ini `output_path`'a yazar, dosya yolunu döner."""
        html = self.render(report)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")
        return output_path
