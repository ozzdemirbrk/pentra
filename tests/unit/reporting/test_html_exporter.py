"""html_exporter.py — HTML generation + file-write tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from pentra.models import Finding, ScanDepth, Severity, Target, TargetType
from pentra.reporting.exporters.html_exporter import HtmlExporter
from pentra.reporting.report_builder import ReportBuilder


def _sample_report(findings: list[Finding] | None = None):
    target = Target(TargetType.LOCALHOST, "127.0.0.1", description="This computer")
    rb = ReportBuilder()
    return rb.build(
        target=target,
        depth=ScanDepth.QUICK,
        findings=findings or [],
        started_at=datetime(2026, 4, 21, 10, 0, tzinfo=UTC),
        ended_at=datetime(2026, 4, 21, 10, 2, tzinfo=UTC),
    )


class TestRender:
    def test_render_empty_report(self) -> None:
        exporter = HtmlExporter()
        html = exporter.render(_sample_report())
        assert "<!DOCTYPE html>" in html
        assert "127.0.0.1" in html
        assert "No findings" in html  # empty-state message

    def test_render_includes_finding_title_and_severity(self) -> None:
        findings = [
            Finding(
                scanner_name="network",
                severity=Severity.HIGH,
                title="Açık port: 3389/tcp (ms-wbt-server)",
                description="RDP open.",
                target="127.0.0.1:3389",
                remediation="RDP'yi kapat veya kısıtla.",
            ),
        ]
        exporter = HtmlExporter()
        html = exporter.render(_sample_report(findings))
        assert "3389/tcp" in html
        assert "High" in html  # severity label (active language)
        # The apostrophe is escaped to &#39; in HTML; the "kapat" portion remains
        assert "kapat veya kısıtla" in html

    def test_html_escapes_dangerous_content(self) -> None:
        findings = [
            Finding(
                scanner_name="network",
                severity=Severity.INFO,
                title="<script>alert(1)</script>",
                description="malicious",
                target="127.0.0.1",
            ),
        ]
        exporter = HtmlExporter()
        html = exporter.render(_sample_report(findings))
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html


class TestExport:
    def test_export_writes_file(self, tmp_path: Path) -> None:
        exporter = HtmlExporter()
        out = tmp_path / "report.html"
        returned = exporter.export(_sample_report(), out)

        assert out.exists()
        assert returned == out
        content = out.read_text(encoding="utf-8")
        assert "127.0.0.1" in content

    def test_export_creates_parent_dir(self, tmp_path: Path) -> None:
        exporter = HtmlExporter()
        out = tmp_path / "nested" / "deep" / "report.html"
        exporter.export(_sample_report(), out)
        assert out.exists()
