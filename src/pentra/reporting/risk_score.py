"""Overall risk score calculation — a 0.0-10.0 score from a list of findings.

Score logic:
    - The highest-severity finding is the anchor contributing the base score
    - Finding count gives a small bonus tier (diminishing)
    - For findings with CVEs, the CVSS score takes priority over severity weight

Label ranges (i18n):
    0.0       -> Clean
    0.0 – 3.9 -> Low (green)
    4.0 – 6.9 -> Medium (yellow)
    7.0 – 8.9 -> High (orange)
    9.0 – 10.0 -> Critical (red)
"""

from __future__ import annotations

import dataclasses
import math
from collections.abc import Iterable

from pentra.i18n import t
from pentra.models import Finding, Severity

# Severity weights — used when no CVE data is available
_SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.5,
    Severity.INFO: 0.5,
}


@dataclasses.dataclass(frozen=True)
class RiskAssessment:
    """Overall risk assessment for a report."""

    score: float  # 0.0 – 10.0
    label: str  # Label translated into the active language
    color: str  # Hex — label color
    summary_tr: str  # 1-2 sentence summary (built in the active language)

    @property
    def score_display(self) -> str:
        return f"{self.score:.1f}"


def _finding_raw_score(finding: Finding) -> float:
    """Return max CVSS when CVEs are present, otherwise the severity weight."""
    cves = finding.evidence.get("cves") if finding.evidence else None
    if cves:
        cvss_values = [
            float(c.get("cvss") or 0) for c in cves if c.get("cvss")
        ]
        if cvss_values:
            return max(cvss_values)
    return _SEVERITY_WEIGHT.get(finding.severity, 0.5)


def compute_risk_score(findings: Iterable[Finding]) -> float:
    """Return a score in the 0.0–10.0 range."""
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
    """Return the label (in the active language) + color (hex) for a score."""
    if score <= 0.0:
        return t("risk.label.clean"), "#388e3c"
    if score < 4.0:
        return t("risk.label.low"), "#689f38"
    if score < 7.0:
        return t("risk.label.medium"), "#ef6c00"
    if score < 9.0:
        return t("risk.label.high"), "#d32f2f"
    return t("risk.label.critical"), "#8b0000"


#: Risk label category -> action tone key
def _tone_key(score: float) -> str:
    if score >= 7.0:
        return "risk.summary.tone_urgent"
    if score >= 4.0:
        return "risk.summary.tone_moderate"
    return "risk.summary.tone_low"


def _build_summary_text(
    score: float, label: str, findings: list[Finding],
) -> str:
    """1-2 sentence summary in the active language."""
    if not findings:
        return t("risk.summary.empty")

    # Count per severity
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
    """Full assessment — score + label + color + summary sentence."""
    findings_list = list(findings)
    score = compute_risk_score(findings_list)
    label, color = risk_label_and_color(score)
    summary = _build_summary_text(score, label, findings_list)
    return RiskAssessment(
        score=score, label=label, color=color, summary_tr=summary,
    )


def top_actions(findings: Iterable[Finding], max_count: int = 3) -> list[Finding]:
    """Return the N most critical findings for the action list."""
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
