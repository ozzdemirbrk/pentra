"""pdf_exporter.py testleri — mocked xhtml2pdf."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pentra.models import Finding, ScanDepth, Severity, Target, TargetType
from pentra.reporting.exporters.html_exporter import HtmlExporter
from pentra.reporting.exporters.pdf_exporter import PdfExporter, PdfExportError
from pentra.reporting.report_builder import ReportBuilder


def _sample_report():
    target = Target(TargetType.LOCALHOST, "127.0.0.1")
    rb = ReportBuilder()
    return rb.build(
        target=target, depth=ScanDepth.QUICK, findings=[],
        started_at=datetime(2026, 4, 22, tzinfo=timezone.utc),
    )


@pytest.fixture
def mocked_pisa():
    """xhtml2pdf.pisa.CreatePDF mock'u — başarılı PDF üretimi simüle eder."""
    fake_status = MagicMock()
    fake_status.err = 0

    fake_pisa = MagicMock()

    def create_pdf(src, dest, **_kwargs):
        # dest bir BytesIO — içine basit bir PDF byte pattern'i yazalım
        dest.write(b"%PDF-1.4\n%fake pdf content\n%%EOF\n")
        return fake_status

    fake_pisa.CreatePDF = create_pdf

    fake_module = MagicMock()
    fake_module.pisa = fake_pisa

    with patch.dict(sys.modules, {"xhtml2pdf": fake_module, "xhtml2pdf.pisa": fake_pisa}):
        yield fake_status


class TestRenderBytes:
    def test_successful_pdf_generation(self, mocked_pisa) -> None:
        exporter = PdfExporter(html_exporter=HtmlExporter())
        pdf_bytes = exporter.render_bytes(_sample_report())
        assert pdf_bytes.startswith(b"%PDF")
        assert b"%%EOF" in pdf_bytes

    def test_pisa_error_raises(self) -> None:
        """pisa err > 0 dönerse PdfExportError fırlatılmalı."""
        fake_status = MagicMock()
        fake_status.err = 2

        fake_pisa = MagicMock()
        fake_pisa.CreatePDF = MagicMock(return_value=fake_status)

        fake_module = MagicMock()
        fake_module.pisa = fake_pisa

        with patch.dict(sys.modules, {"xhtml2pdf": fake_module, "xhtml2pdf.pisa": fake_pisa}):
            exporter = PdfExporter()
            with pytest.raises(PdfExportError):
                exporter.render_bytes(_sample_report())

    def test_xhtml2pdf_missing_raises(self) -> None:
        with patch.dict(sys.modules, {"xhtml2pdf": None, "xhtml2pdf.pisa": None}):
            exporter = PdfExporter()
            with pytest.raises(PdfExportError, match="xhtml2pdf yüklü değil"):
                exporter.render_bytes(_sample_report())


class TestExport:
    def test_export_writes_file(self, tmp_path: Path, mocked_pisa) -> None:
        exporter = PdfExporter()
        out = tmp_path / "r.pdf"
        written = exporter.export(_sample_report(), out)
        assert written == out
        assert out.exists()
        content = out.read_bytes()
        assert content.startswith(b"%PDF")
