"""comparison.py — tests for the diff logic between two scans."""

from __future__ import annotations

from datetime import datetime, timezone

from pentra.models import Finding, Severity
from pentra.reporting.comparison import ScanComparison, compare
from pentra.storage.scan_history import FindingSnapshot, ReportSnapshot


def _snap(title: str, target: str = "127.0.0.1", sev: str = "medium") -> FindingSnapshot:
    return FindingSnapshot(severity=sev, title=title, target=target)


def _current(title: str, target: str = "127.0.0.1", sev: Severity = Severity.MEDIUM) -> Finding:
    return Finding(scanner_name="t", severity=sev, title=title, description="d", target=target)


def _prev_snapshot(findings: list[FindingSnapshot], risk: float = 5.0) -> ReportSnapshot:
    return ReportSnapshot(
        scan_id=1,
        target_key="localhost:127.0.0.1",
        target_value="127.0.0.1",
        depth="quick",
        ended_at=datetime(2026, 4, 1, tzinfo=timezone.utc),
        risk_score=risk,
        finding_count=len(findings),
        findings=tuple(findings),
    )


# =====================================================================
# New-finding detection
# =====================================================================
class TestNewFindings:
    def test_finding_only_in_current_is_new(self) -> None:
        previous = _prev_snapshot([_snap("A")])
        current = [_current("A"), _current("B")]
        cmp = compare(previous, current, current_risk_score=6.0)
        assert len(cmp.new_findings) == 1
        assert cmp.new_findings[0].title == "B"

    def test_identical_scans_no_new(self) -> None:
        previous = _prev_snapshot([_snap("A"), _snap("B")])
        current = [_current("A"), _current("B")]
        cmp = compare(previous, current, current_risk_score=5.0)
        assert cmp.new_findings == ()
        assert cmp.unchanged_count == 2


# =====================================================================
# Resolved-finding detection
# =====================================================================
class TestResolvedFindings:
    def test_finding_only_in_previous_is_resolved(self) -> None:
        previous = _prev_snapshot([_snap("A"), _snap("B")])
        current = [_current("A")]
        cmp = compare(previous, current, current_risk_score=4.0)
        assert len(cmp.resolved_findings) == 1
        assert cmp.resolved_findings[0].title == "B"

    def test_all_resolved(self) -> None:
        previous = _prev_snapshot([_snap("A"), _snap("B")])
        current: list[Finding] = []
        cmp = compare(previous, current, current_risk_score=0.0)
        assert cmp.resolved_count == 2
        assert cmp.new_count == 0


# =====================================================================
# Matching (by title + target)
# =====================================================================
class TestMatching:
    def test_same_title_different_target_treated_as_different(self) -> None:
        previous = _prev_snapshot([_snap("CSP eksik", target="https://a.com")])
        current = [_current("CSP eksik", target="https://b.com")]
        cmp = compare(previous, current, current_risk_score=5.0)
        # Different targets -> one is resolved, the other is new
        assert cmp.resolved_count == 1
        assert cmp.new_count == 1
        assert cmp.unchanged_count == 0

    def test_same_title_same_target_treated_as_unchanged(self) -> None:
        previous = _prev_snapshot([_snap("x", target="1.2.3.4")])
        current = [_current("x", target="1.2.3.4")]
        cmp = compare(previous, current, current_risk_score=5.0)
        assert cmp.unchanged_count == 1
        assert cmp.new_count == 0
        assert cmp.resolved_count == 0


# =====================================================================
# Risk trend
# =====================================================================
class TestRiskTrend:
    def test_improved_when_score_decreased(self) -> None:
        previous = _prev_snapshot([_snap("x")], risk=7.0)
        cmp = compare(previous, [], current_risk_score=2.0)
        assert cmp.risk_trend == "improved"
        assert cmp.risk_delta < 0

    def test_worsened_when_score_increased(self) -> None:
        previous = _prev_snapshot([], risk=2.0)
        cmp = compare(previous, [_current("x"), _current("y", sev=Severity.CRITICAL)], current_risk_score=9.5)
        assert cmp.risk_trend == "worsened"

    def test_stable_when_delta_small(self) -> None:
        previous = _prev_snapshot([_snap("x")], risk=5.0)
        cmp = compare(previous, [_current("x")], current_risk_score=5.1)
        assert cmp.risk_trend == "stable"


# =====================================================================
# has_changes
# =====================================================================
class TestHasChanges:
    def test_true_when_new(self) -> None:
        previous = _prev_snapshot([])
        cmp = compare(previous, [_current("new")], current_risk_score=3.0)
        assert cmp.has_changes

    def test_true_when_resolved(self) -> None:
        previous = _prev_snapshot([_snap("resolved")])
        cmp = compare(previous, [], current_risk_score=0.0)
        assert cmp.has_changes

    def test_false_when_identical(self) -> None:
        previous = _prev_snapshot([_snap("same")])
        cmp = compare(previous, [_current("same")], current_risk_score=5.0)
        assert not cmp.has_changes
