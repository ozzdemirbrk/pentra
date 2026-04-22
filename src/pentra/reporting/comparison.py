"""Tarama karşılaştırması — aynı hedefin önceki ve mevcut taramasını diff'ler.

Bulgular `(title, target)` anahtarıyla eşleştirilir:
    - Önceki tarama içinde olup şimdi olmayan → **çözülmüş** (fix uygulanmış)
    - Şimdi olup öncekinde olmayan → **yeni risk**
    - Her ikisinde var → **değişmemiş**

Severity değişiklikleri şimdilik takip edilmiyor — basit tutuluyor.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime
from typing import Iterable

from pentra.models import Finding
from pentra.storage.scan_history import FindingSnapshot, ReportSnapshot


@dataclasses.dataclass(frozen=True)
class ScanComparison:
    """İki tarama arasındaki fark — rapor şablonunda gösterilir."""

    previous_date: datetime
    previous_risk_score: float
    new_findings: tuple[FindingSnapshot, ...]  # mevcut'ta var, önceki'de yoktu
    resolved_findings: tuple[FindingSnapshot, ...]  # önceki'de vardı, mevcut'ta yok
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
        """Risk skoru değişimi: pozitif = arttı (kötü), negatif = azaldı (iyi)."""
        return self.current_risk_score - self.previous_risk_score

    @property
    def risk_trend(self) -> str:
        """'improved' / 'worsened' / 'stable' — UI için ikon seçimi."""
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
    """Geçmiş bir snapshot ile mevcut (henüz kaydedilmemiş) raporu karşılaştır.

    Args:
        previous: DB'den çekilen önceki tarama
        current_findings: Mevcut taramada üretilen bulgular
        current_risk_score: Mevcut genel risk skoru

    Returns:
        ScanComparison — new/resolved/unchanged bilgisi
    """
    current_list = list(current_findings)

    # (title, target) anahtarıyla set'ler oluştur
    prev_by_key: dict[tuple[str, str], FindingSnapshot] = {
        (f.title, f.target): f for f in previous.findings
    }
    curr_by_key: dict[tuple[str, str], FindingSnapshot] = {
        (f.title, f.target): _snapshot_from_finding(f) for f in current_list
    }

    # Önceki'de vardı, mevcut'ta yok → çözülmüş
    resolved = tuple(
        prev_by_key[k] for k in prev_by_key if k not in curr_by_key
    )
    # Mevcut'ta var, önceki'de yoktu → yeni
    new_items = tuple(
        curr_by_key[k] for k in curr_by_key if k not in prev_by_key
    )
    # Her ikisinde var → değişmemiş
    unchanged_count = sum(1 for k in prev_by_key if k in curr_by_key)

    return ScanComparison(
        previous_date=previous.ended_at,
        previous_risk_score=previous.risk_score,
        new_findings=new_items,
        resolved_findings=resolved,
        unchanged_count=unchanged_count,
        current_risk_score=current_risk_score,
    )
