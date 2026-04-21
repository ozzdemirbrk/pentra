"""report_builder.py — Report + ReportSummary testleri."""

from __future__ import annotations

from datetime import datetime, timezone

from pentra.models import Finding, ScanDepth, Severity, Target, TargetType
from pentra.reporting.report_builder import Report, ReportBuilder, ReportSummary


def _make_finding(severity: Severity, title: str = "t") -> Finding:
    return Finding(
        scanner_name="test",
        severity=severity,
        title=title,
        description="d",
        target="127.0.0.1:80",
    )


class TestReportSummary:
    def test_empty_findings(self) -> None:
        s = ReportSummary.from_findings([])
        assert s.total == 0
        assert s.critical == s.high == s.medium == s.low == s.info == 0

    def test_counts_by_severity(self) -> None:
        findings = [
            _make_finding(Severity.CRITICAL),
            _make_finding(Severity.HIGH),
            _make_finding(Severity.HIGH),
            _make_finding(Severity.INFO),
            _make_finding(Severity.INFO),
            _make_finding(Severity.INFO),
        ]
        s = ReportSummary.from_findings(findings)
        assert s.total == 6
        assert s.critical == 1
        assert s.high == 2
        assert s.info == 3
        assert s.medium == 0


class TestReportBuilder:
    def test_sorted_by_severity(self) -> None:
        findings = [
            _make_finding(Severity.INFO, "i"),
            _make_finding(Severity.CRITICAL, "c"),
            _make_finding(Severity.LOW, "l"),
            _make_finding(Severity.HIGH, "h"),
        ]
        rb = ReportBuilder()
        target = Target(TargetType.LOCALHOST, "127.0.0.1")
        started = datetime(2026, 4, 21, 10, 0, tzinfo=timezone.utc)
        ended = datetime(2026, 4, 21, 10, 5, tzinfo=timezone.utc)

        report = rb.build(
            target=target,
            depth=ScanDepth.QUICK,
            findings=findings,
            started_at=started,
            ended_at=ended,
        )

        assert [f.severity for f in report.findings] == [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.LOW,
            Severity.INFO,
        ]
        assert report.duration_seconds == 300

    def test_default_ended_at_is_now(self) -> None:
        rb = ReportBuilder()
        target = Target(TargetType.LOCALHOST, "127.0.0.1")
        started = datetime.now(timezone.utc)
        report = rb.build(
            target=target,
            depth=ScanDepth.QUICK,
            findings=[],
            started_at=started,
        )
        assert report.ended_at is not None
        assert report.duration_seconds >= 0

    def test_duration_pretty_seconds_only(self) -> None:
        report = Report(
            target=Target(TargetType.LOCALHOST, "127.0.0.1"),
            depth=ScanDepth.QUICK,
            started_at=datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc),
            ended_at=datetime(2026, 1, 1, 10, 0, 45, tzinfo=timezone.utc),
            findings=[],
            summary=ReportSummary.from_findings([]),
        )
        assert report.duration_pretty == "45 sn"

    def test_duration_pretty_minutes(self) -> None:
        report = Report(
            target=Target(TargetType.LOCALHOST, "127.0.0.1"),
            depth=ScanDepth.QUICK,
            started_at=datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc),
            ended_at=datetime(2026, 1, 1, 10, 5, 30, tzinfo=timezone.utc),
            findings=[],
            summary=ReportSummary.from_findings([]),
        )
        assert report.duration_pretty == "5 dk 30 sn"

    def test_duration_pretty_hours(self) -> None:
        report = Report(
            target=Target(TargetType.LOCALHOST, "127.0.0.1"),
            depth=ScanDepth.DEEP,
            started_at=datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc),
            ended_at=datetime(2026, 1, 1, 12, 15, 5, tzinfo=timezone.utc),
            findings=[],
            summary=ReportSummary.from_findings([]),
        )
        assert report.duration_pretty == "2 saat 15 dk 5 sn"
