"""scan_history.py — SQLite scan-history tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from pentra.models import Finding, ScanDepth, Severity, Target, TargetType
from pentra.reporting.report_builder import ReportBuilder
from pentra.storage.scan_history import (
    ScanHistory,
)


@pytest.fixture
def history(tmp_path: Path) -> ScanHistory:
    """An isolated SQLite DB for tests."""
    return ScanHistory(tmp_path / "history.db")


def _build_report(
    target_value: str = "127.0.0.1",
    findings: list[Finding] | None = None,
    ended: datetime | None = None,
):
    """Helper — quickly build a Report for tests."""
    target = Target(TargetType.LOCALHOST, target_value)
    rb = ReportBuilder()
    return rb.build(
        target=target,
        depth=ScanDepth.QUICK,
        findings=findings or [],
        started_at=ended or datetime(2026, 4, 22, tzinfo=UTC),
        ended_at=ended or datetime(2026, 4, 22, tzinfo=UTC),
    )


def _finding(title: str, target: str = "127.0.0.1", sev: Severity = Severity.MEDIUM) -> Finding:
    return Finding(
        scanner_name="t",
        severity=sev,
        title=title,
        description="d",
        target=target,
    )


# =====================================================================
# Schema + record
# =====================================================================
class TestRecord:
    def test_db_file_created_on_init(self, tmp_path: Path) -> None:
        db = tmp_path / "nested" / "history.db"
        ScanHistory(db)
        assert db.exists()

    def test_record_returns_scan_id(self, history: ScanHistory) -> None:
        report = _build_report(findings=[_finding("a"), _finding("b")])
        scan_id = history.record(report)
        assert isinstance(scan_id, int)
        assert scan_id > 0

    def test_record_persists_findings(self, history: ScanHistory) -> None:
        report = _build_report(
            findings=[
                _finding("f1", target="127.0.0.1:80", sev=Severity.HIGH),
                _finding("f2", target="127.0.0.1:443", sev=Severity.LOW),
            ]
        )
        history.record(report)
        snap = history.find_previous(report.target)
        assert snap is not None
        assert len(snap.findings) == 2
        titles = {f.title for f in snap.findings}
        assert titles == {"f1", "f2"}

    def test_record_empty_findings(self, history: ScanHistory) -> None:
        report = _build_report(findings=[])
        scan_id = history.record(report)
        assert scan_id > 0
        snap = history.find_previous(report.target)
        assert snap is not None
        assert len(snap.findings) == 0


# =====================================================================
# find_previous
# =====================================================================
class TestFindPrevious:
    def test_no_history_returns_none(self, history: ScanHistory) -> None:
        target = Target(TargetType.LOCALHOST, "127.0.0.1")
        assert history.find_previous(target) is None

    def test_returns_most_recent_for_same_target(self, history: ScanHistory) -> None:
        # Same target on two different dates — newest should be returned
        old = _build_report(
            findings=[_finding("old_issue")],
            ended=datetime(2026, 4, 1, tzinfo=UTC),
        )
        new = _build_report(
            findings=[_finding("new_issue")],
            ended=datetime(2026, 4, 20, tzinfo=UTC),
        )
        history.record(old)
        history.record(new)

        snap = history.find_previous(new.target)
        assert snap is not None
        titles = {f.title for f in snap.findings}
        assert "new_issue" in titles
        assert "old_issue" not in titles

    def test_different_target_not_matched(self, history: ScanHistory) -> None:
        r1 = _build_report(target_value="127.0.0.1", findings=[_finding("x")])
        history.record(r1)
        # Should not match when querying a different target
        other_target = Target(TargetType.LOCALHOST, "192.168.1.1")
        assert history.find_previous(other_target) is None

    def test_target_type_matters(self, history: ScanHistory) -> None:
        """LOCALHOST vs IP_SINGLE produce different target_keys -> must not match."""
        localhost_tgt = Target(TargetType.LOCALHOST, "127.0.0.1")
        ip_tgt = Target(TargetType.IP_SINGLE, "127.0.0.1")

        rb = ReportBuilder()
        r1 = rb.build(
            target=localhost_tgt,
            depth=ScanDepth.QUICK,
            findings=[_finding("localhost_only")],
            started_at=datetime(2026, 4, 22, tzinfo=UTC),
        )
        history.record(r1)

        # An IP_SINGLE 127.0.0.1 lookup should not find the localhost record
        assert history.find_previous(ip_tgt) is None
        assert history.find_previous(localhost_tgt) is not None


# =====================================================================
# list_recent
# =====================================================================
class TestListRecent:
    def test_empty_history_returns_empty_list(self, history: ScanHistory) -> None:
        assert history.list_recent() == []

    def test_orders_by_ended_at_desc(self, history: ScanHistory) -> None:
        history.record(_build_report(target_value="a", ended=datetime(2026, 4, 1, tzinfo=UTC)))
        history.record(_build_report(target_value="b", ended=datetime(2026, 4, 10, tzinfo=UTC)))
        history.record(_build_report(target_value="c", ended=datetime(2026, 4, 20, tzinfo=UTC)))

        summaries = history.list_recent()
        assert [s.target_value for s in summaries] == ["c", "b", "a"]

    def test_limit_respected(self, history: ScanHistory) -> None:
        for i in range(5):
            history.record(_build_report(target_value=f"h{i}"))
        assert len(history.list_recent(limit=3)) == 3


# =====================================================================
# delete_all
# =====================================================================
class TestDelete:
    def test_delete_all_removes_scans_and_findings(self, history: ScanHistory) -> None:
        history.record(_build_report(findings=[_finding("x")]))
        history.record(_build_report(findings=[_finding("y")]))

        deleted = history.delete_all()
        assert deleted == 2
        assert history.list_recent() == []

    def test_delete_on_empty_returns_zero(self, history: ScanHistory) -> None:
        assert history.delete_all() == 0
