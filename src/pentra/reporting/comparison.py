"""Scan comparison — diffs the previous and current scans of the same target.

Findings are matched on a `(title, target)` key:
    - Existed before, missing now -> **resolved** (fix applied)
    - Exists now, missing before -> **new risk**
    - Present in both -> **unchanged**

Severity changes are not tracked for now — kept simple.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime
from typing import Iterable

from pentra.models import Finding
from pentra.storage.scan_history import FindingSnapshot, ReportSnapshot


@dataclasses.dataclass(frozen=True)
class ScanComparison:
    """Difference between two scans — shown in the report template."""

    previous_date: datetime
    previous_risk_score: float
    new_findings: tuple[FindingSnapshot, ...]  # in current, not in previous
    resolved_findings: tuple[FindingSnapshot, ...]  # in previous, not in current
    unchanged_count: int
    current_risk_score: float

    @property
    def has_changes(self) -> bool:
        return bool(self.new_findings) or bool(self.resolved_findings)

    @property
    def new_count(self) -> int:
        return len(self.new_findings)

    @property
    def resolved_count(self) -> int:
        return len(self.resolved_findings)

    @property
    def risk_delta(self) -> float:
        """Risk score change: positive = worsened, negative = improved."""
        return self.current_risk_score - self.previous_risk_score

    @property
    def risk_trend(self) -> str:
        """'improved' / 'worsened' / 'stable' — used to pick the UI icon."""
        delta = self.risk_delta
        if abs(delta) < 0.3:
            return "stable"
        return "worsened" if delta > 0 else "improved"


def _snapshot_from_finding(finding: Finding) -> FindingSnapshot:
    return FindingSnapshot(
        severity=finding.severity.value,
        title=finding.title,
        target=finding.target,
    )


def compare(
    previous: ReportSnapshot,
    current_findings: Iterable[Finding],
    current_risk_score: float,
) -> ScanComparison:
    """Compare a historical snapshot with the (not-yet-saved) current report.

    Args:
        previous: Previous scan fetched from the DB
        current_findings: Findings produced by the current scan
        current_risk_score: Current overall risk score

    Returns:
        ScanComparison — new/resolved/unchanged info
    """
    current_list = list(current_findings)

    # Build sets keyed by (title, target)
    prev_by_key: dict[tuple[str, str], FindingSnapshot] = {
        (f.title, f.target): f for f in previous.findings
    }
    curr_by_key: dict[tuple[str, str], FindingSnapshot] = {
        (f.title, f.target): _snapshot_from_finding(f) for f in current_list
    }

    # In previous, not in current -> resolved
    resolved = tuple(
        prev_by_key[k] for k in prev_by_key if k not in curr_by_key
    )
    # In current, not in previous -> new
    new_items = tuple(
        curr_by_key[k] for k in curr_by_key if k not in prev_by_key
    )
    # In both -> unchanged
    unchanged_count = sum(1 for k in prev_by_key if k in curr_by_key)

    return ScanComparison(
        previous_date=previous.ended_at,
        previous_risk_score=previous.risk_score,
        new_findings=new_items,
        resolved_findings=resolved,
        unchanged_count=unchanged_count,
        current_risk_score=current_risk_score,
    )
