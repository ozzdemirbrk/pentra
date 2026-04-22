"""markdown_exporter.py testleri."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from pentra.models import Finding, ScanDepth, Severity, Target, TargetType
from pentra.reporting.exporters.markdown_exporter import MarkdownExporter
from pentra.reporting.report_builder import ReportBuilder


def _sample_report(findings: list[Finding] | None = None):
    target = Target(TargetType.LOCALHOST, "127.0.0.1")
    rb = ReportBuilder()
    return rb.build(
        target=target,
        depth=ScanDepth.QUICK,
        findings=findings or [],
        started_at=datetime(2026, 4, 22, 10, 0, tzinfo=timezone.utc),
        ended_at=datetime(2026, 4, 22, 10, 2, tzinfo=timezone.utc),
    )


class TestRender:
    def test_empty_report_markdown(self) -> None:
        exp = MarkdownExporter()
        md = exp.render(_sample_report())
        assert "# 🛡️ Pentra Güvenlik Raporu" in md
        assert "**Hedef:**" in md
        assert "127.0.0.1" in md
        assert "Herhangi bir bulgu tespit edilmedi" in md

    def test_summary_table(self) -> None:
        exp = MarkdownExporter()
        findings = [
            Finding(scanner_name="t", severity=Severity.CRITICAL, title="c", description="d", target="x"),
            Finding(scanner_name="t", severity=Severity.HIGH, title="h", description="d", target="x"),
        ]
        md = exp.render(_sample_report(findings))
        assert "Kritik" in md
        assert "Yüksek" in md
        # Markdown tablo: "| Kritik | 1 |"
        assert "| 1 |" in md

    def test_findings_rendered_with_severity(self) -> None:
        exp = MarkdownExporter()
        findings = [
            Finding(
                scanner_name="web", severity=Severity.HIGH,
                title="HSTS eksik", description="Açıklama.",
                target="https://test",
                remediation="Kısa öneri.",
            ),
        ]
        md = exp.render(_sample_report(findings))
        assert "HSTS eksik" in md
        assert "YÜKSEK" in md.upper() or "Yüksek" in md
        assert "Kısa öneri" in md

    def test_detailed_guide_included_if_matched(self) -> None:
        exp = MarkdownExporter()
        findings = [
            Finding(
                scanner_name="web", severity=Severity.MEDIUM,
                title="CSP eksik", description="x", target="https://test",
            ),
        ]
        md = exp.render(_sample_report(findings))
        # CSP rehberi açılır kart olmalı
        assert "Detaylı Onarım Rehberi" in md
        # Code block fence '```' olmalı
        assert "```" in md


class TestExport:
    def test_export_writes_md_file(self, tmp_path: Path) -> None:
        exp = MarkdownExporter()
        out = tmp_path / "report.md"
        written = exp.export(_sample_report(), out)
        assert out.exists()
        assert written == out
        content = out.read_text(encoding="utf-8")
        assert content.startswith("# 🛡️ Pentra")
