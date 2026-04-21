"""Rapor veri yapısı + Finding listesinden rapor oluşturan yardımcı.

Rapor formatlamasını (HTML/PDF/MD) bilmez; sadece veri hazırlar.
Exporter'lar aldıkları Report nesnesiyle ilgili formata çevirir.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone

from pentra.models import Finding, ScanDepth, Severity, Target


# ---------------------------------------------------------------------
# Rapor veri modeli
# ---------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class ReportSummary:
    """Bulgu sayaçları — rapor başında hızlı özet için."""

    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> "ReportSummary":
        counts = {sev: 0 for sev in Severity}
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
    """Dışa aktarıma hazır tam rapor."""

    target: Target
    depth: ScanDepth
    started_at: datetime
    ended_at: datetime
    findings: list[Finding]
    summary: ReportSummary

    @property
    def duration_seconds(self) -> float:
        return (self.ended_at - self.started_at).total_seconds()

    @property
    def duration_pretty(self) -> str:
        """Süreyi Türkçe olarak biçimlendirir (ör. '3 dk 12 sn')."""
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
    """Tarama sonucundan `Report` nesnesi üretir."""

    def build(
        self,
        *,
        target: Target,
        depth: ScanDepth,
        findings: list[Finding],
        started_at: datetime,
        ended_at: datetime | None = None,
    ) -> Report:
        if ended_at is None:
            ended_at = datetime.now(timezone.utc)

        # Severity sırasına göre (kritik → info) sırala — raporda üstte kritikler
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

        return Report(
            target=target,
            depth=depth,
            started_at=started_at,
            ended_at=ended_at,
            findings=sorted_findings,
            summary=summary,
        )
