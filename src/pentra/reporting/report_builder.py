"""Report data structure + helper that builds a report from a list of Findings.

Knows nothing about report formatting (HTML/PDF/MD); just prepares data.
Exporters convert the Report object they receive into their target format.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from pentra.models import Finding, ScanDepth, Severity, Target
from pentra.reporting.risk_score import RiskAssessment, assess_risk, top_actions

if TYPE_CHECKING:
    from pentra.reporting.comparison import ScanComparison


# ---------------------------------------------------------------------
# Report data model
# ---------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class ReportSummary:
    """Finding counters — used for the quick overview at the top of the report."""

    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> ReportSummary:
        counts = dict.fromkeys(Severity, 0)
        for f in findings:
            counts[f.severity] += 1
        return cls(
            total=len(findings),
            critical=counts[Severity.CRITICAL],
            high=counts[Severity.HIGH],
            medium=counts[Severity.MEDIUM],
            low=counts[Severity.LOW],
            info=counts[Severity.INFO],
        )


@dataclasses.dataclass(frozen=True)
class Report:
    """Full report ready for export."""

    target: Target
    depth: ScanDepth
    started_at: datetime
    ended_at: datetime
    findings: list[Finding]
    summary: ReportSummary
    #: Risk score (0–10) + Turkish label + summary sentence
    risk: RiskAssessment
    #: Top N priority actions shown at the top of the report
    top_actions: list[Finding] = dataclasses.field(default_factory=list)
    #: Comparison with the previous scan (if any); None on first scan
    comparison: ScanComparison | None = None

    @property
    def duration_seconds(self) -> float:
        return (self.ended_at - self.started_at).total_seconds()

    @property
    def duration_pretty(self) -> str:
        """Format the duration in Turkish (e.g. '3 dk 12 sn')."""
        total = int(self.duration_seconds)
        minutes, seconds = divmod(total, 60)
        hours, minutes = divmod(minutes, 60)
        if hours:
            return f"{hours} saat {minutes} dk {seconds} sn"
        if minutes:
            return f"{minutes} dk {seconds} sn"
        return f"{seconds} sn"


# ---------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------
class ReportBuilder:
    """Builds a `Report` object from a scan result."""

    def build(
        self,
        *,
        target: Target,
        depth: ScanDepth,
        findings: list[Finding],
        started_at: datetime,
        ended_at: datetime | None = None,
        comparison: ScanComparison | None = None,
    ) -> Report:
        if ended_at is None:
            ended_at = datetime.now(UTC)

        # Sort by severity (critical -> info) so critical items appear first
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        sorted_findings = sorted(
            findings,
            key=lambda f: (severity_order[f.severity], f.title),
        )

        summary = ReportSummary.from_findings(sorted_findings)
        risk = assess_risk(sorted_findings)
        actions = top_actions(sorted_findings, max_count=3)

        return Report(
            target=target,
            depth=depth,
            started_at=started_at,
            ended_at=ended_at,
            findings=sorted_findings,
            summary=summary,
            risk=risk,
            top_actions=actions,
            comparison=comparison,
        )
