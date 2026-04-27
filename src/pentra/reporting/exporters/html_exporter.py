"""HTML exporter — turns ReportData into a standalone HTML file via Jinja2."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from pentra.i18n import Translator, t
from pentra.knowledge.remediations import get_guide
from pentra.reporting.logo import get_logo_data_uri
from pentra.reporting.report_builder import Report

_TEMPLATE_DIR: Path = Path(__file__).parent.parent / "templates"
_TEMPLATE_NAME: str = "basic_report.html.j2"


# ---------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------
def _tr_datetime(value: datetime) -> str:
    """YYYY-MM-DD HH:MM format — same in both languages."""
    return value.strftime("%Y-%m-%d %H:%M")


def _severity_label(value: str) -> str:
    """severity.value ('critical', 'high', ...) -> label in the active language."""
    key = f"severity.{value}"
    label = t(key)
    # Fall back to the capitalised raw value if the key is missing
    if label == key:
        return value.capitalize()
    return label


_SEVERITY_COLOR: dict[str, str] = {
    "critical": "#8b0000",
    "high": "#d32f2f",
    "medium": "#ef6c00",
    "low": "#fbc02d",
    "info": "#0288d1",
}


def _severity_color(value: str) -> str:
    return _SEVERITY_COLOR.get(value, "#666")


def _depth_label(value: str) -> str:
    """ScanDepth.value ('quick'/'standard'/'deep') -> label in the active language."""
    key = f"depth.value.{value}"
    label = t(key)
    if label == key:
        return value.capitalize()
    return label


# ---------------------------------------------------------------------
# Exporter
# ---------------------------------------------------------------------
class HtmlExporter:
    """Report -> HTML file."""

    def __init__(self, template_dir: Path | None = None) -> None:
        self._template_dir = template_dir if template_dir is not None else _TEMPLATE_DIR

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
        self._env.filters["depth_label"] = _depth_label

        # i18n — called in the template as `{{ t('key', arg=value) }}`
        self._env.globals["t"] = t
        self._env.globals["get_remediation_guide"] = get_guide
        self._env.globals["logo_data_uri"] = get_logo_data_uri()

    def render(self, report: Report) -> str:
        template = self._env.get_template(_TEMPLATE_NAME)
        return template.render(
            report=report,
            generated_at=datetime.now(),
            current_lang=Translator.instance().current_language,
        )

    def export(self, report: Report, output_path: Path) -> Path:
        """Write the report HTML to `output_path` and return the file path."""
        html = self.render(report)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")
        return output_path
