"""Genel risk skoru hesabı — finding listesinden 0.0-10.0 arası puan.

Skor mantığı:
    - En yüksek severity'li bulgu skora ana katkıyı yapar (anchor)
    - Bulgu sayısı az bir kademe bonus verir (diminishing)
    - CVE'li bulgularda CVSS skoru severity ağırlığından öncelikli

Etiket aralıkları (i18n):
    0.0       → Clean / Temiz
    0.0 – 3.9 → Low / Düşük (yeşil)
    4.0 – 6.9 → Medium / Orta (sarı)
    7.0 – 8.9 → High / Yüksek (turuncu)
    9.0 – 10.0 → Critical / Kritik (kırmızı)
"""

from __future__ import annotations

import dataclasses
import math
from collections.abc import Iterable

from pentra.i18n import t
from pentra.models import Finding, Severity

# Severity ağırlıkları — CVE yoksa bu kullanılır
_SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.5,
    Severity.INFO: 0.5,
}


@dataclasses.dataclass(frozen=True)
class RiskAssessment:
    """Bir rapor için genel risk değerlendirmesi."""

    score: float  # 0.0 – 10.0
    label: str  # Aktif dile çevrilmiş etiket
    color: str  # Hex — etiket rengi
    summary_tr: str  # 1-2 cümlelik özet (aktif dile göre üretilmiş)

    @property
    def score_display(self) -> str:
        return f"{self.score:.1f}"


def _finding_raw_score(finding: Finding) -> float:
    """CVE'li ise max CVSS, değilse severity ağırlığı."""
    cves = finding.evidence.get("cves") if finding.evidence else None
    if cves:
        cvss_values = [
            float(c.get("cvss") or 0) for c in cves if c.get("cvss")
        ]
        if cvss_values:
            return max(cvss_values)
    return _SEVERITY_WEIGHT.get(finding.severity, 0.5)


def compute_risk_score(findings: Iterable[Finding]) -> float:
    """0.0–10.0 arası skor döner."""
    findings_list = list(findings)
    if not findings_list:
        return 0.0

    max_single = max(_finding_raw_score(f) for f in findings_list)

    significant = [
        f for f in findings_list
        if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
    ]
    count_bonus = min(1.0, 0.35 * math.log(len(significant) + 1))

    score = min(10.0, max_single + count_bonus)
    return round(score, 1)


def risk_label_and_color(score: float) -> tuple[str, str]:
    """Skora göre aktif dile çevrilmiş etiket + renk (hex)."""
    if score <= 0.0:
        return t("risk.label.clean"), "#388e3c"
    if score < 4.0:
        return t("risk.label.low"), "#689f38"
    if score < 7.0:
        return t("risk.label.medium"), "#ef6c00"
    if score < 9.0:
        return t("risk.label.high"), "#d32f2f"
    return t("risk.label.critical"), "#8b0000"


#: Risk etiketi kategorisi → aksiyon tonu anahtarı
def _tone_key(score: float) -> str:
    if score >= 7.0:
        return "risk.summary.tone_urgent"
    if score >= 4.0:
        return "risk.summary.tone_moderate"
    return "risk.summary.tone_low"


def _build_summary_text(
    score: float, label: str, findings: list[Finding],
) -> str:
    """1-2 cümlelik aktif-dil özet metni."""
    if not findings:
        return t("risk.summary.empty")

    # Severity başına sayım
    counts = {sev: 0 for sev in Severity}
    for f in findings:
        counts[f.severity] += 1

    parts: list[str] = []
    for sev, word_key in (
        (Severity.CRITICAL, "risk.summary.word_critical"),
        (Severity.HIGH, "risk.summary.word_high"),
        (Severity.MEDIUM, "risk.summary.word_medium"),
        (Severity.LOW, "risk.summary.word_low"),
    ):
        if counts[sev]:
            parts.append(
                t(
                    "risk.summary.level_template",
                    count=counts[sev], label=t(word_key),
                ),
            )
    if counts[Severity.INFO]:
        parts.append(
            t("risk.summary.info_template", count=counts[Severity.INFO]),
        )

    parts_text = ", ".join(parts) if parts else "-"
    tone = t(_tone_key(score))

    return t(
        "risk.summary.sentence",
        parts=parts_text,
        count=len(findings),
        label=label,
        score=f"{score:.1f}",
        tone=tone,
    )


def assess_risk(findings: Iterable[Finding]) -> RiskAssessment:
    """Tam değerlendirme — skor + etiket + renk + özet cümle."""
    findings_list = list(findings)
    score = compute_risk_score(findings_list)
    label, color = risk_label_and_color(score)
    summary = _build_summary_text(score, label, findings_list)
    return RiskAssessment(
        score=score, label=label, color=color, summary_tr=summary,
    )


def top_actions(findings: Iterable[Finding], max_count: int = 3) -> list[Finding]:
    """En kritik N bulguyu aksiyon listesi için döner."""
    severity_rank = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    sorted_findings = sorted(
        findings,
        key=lambda f: (severity_rank.get(f.severity, 5), -_finding_raw_score(f)),
    )
    return sorted_findings[:max_count]
