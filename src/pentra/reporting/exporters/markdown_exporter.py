"""Markdown exporter — Jinja2 şablonuyla MD formatında rapor üretir."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from pentra.knowledge.remediations_tr import get_guide
from pentra.reporting.report_builder import Report

_TEMPLATE_DIR: Path = Path(__file__).parent.parent / "templates"
_TEMPLATE_NAME: str = "basic_report.md.j2"


def _tr_datetime(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M")


_SEVERITY_TR: dict[str, str] = {
    "critical": "Kritik",
    "high": "Yüksek",
    "medium": "Orta",
    "low": "Düşük",
    "info": "Bilgi",
}


def _severity_label(value: str) -> str:
    return _SEVERITY_TR.get(value, value.capitalize())


class MarkdownExporter:
    """Report → Markdown metin dosyası."""

    def __init__(self, template_dir: Path | None = None) -> None:
        self._template_dir = template_dir if template_dir is not None else _TEMPLATE_DIR
        # MD için autoescape YOK (Markdown HTML olarak render edilmez burada)
        self._env = Environment(
            loader=FileSystemLoader(str(self._template_dir)),
            autoescape=False,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self._env.filters["tr_datetime"] = _tr_datetime
        self._env.filters["severity_label"] = _severity_label
        self._env.globals["get_remediation_guide"] = get_guide

    def render(self, report: Report) -> str:
        template = self._env.get_template(_TEMPLATE_NAME)
        return template.render(
            report=report,
            generated_at=datetime.now(),
        )

    def export(self, report: Report, output_path: Path) -> Path:
        """Markdown içeriğini `output_path`'a yazar."""
        md = self.render(report)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(md, encoding="utf-8")
        return output_path
