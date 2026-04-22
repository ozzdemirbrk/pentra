"""Genel risk skoru hesabı — finding listesinden 0.0-10.0 arası puan.

Skor mantığı:
    - En yüksek severity'li bulgu skora ana katkıyı yapar (anchor)
    - Bulgu sayısı az bir kademe bonus verir (diminishing)
    - CVE'li bulgularda CVSS skoru severity ağırlığından öncelikli

Etiket aralıkları (tr):
    0.0 – 3.9 → Düşük (yeşil)
    4.0 – 6.9 → Orta (sarı)
    7.0 – 8.9 → Yüksek (turuncu)
    9.0 – 10.0 → Kritik (kırmızı)
"""

from __future__ import annotations

import dataclasses
import math
from collections.abc import Iterable

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
    label: str  # "Temiz" / "Düşük" / "Orta" / "Yüksek" / "Kritik"
    color: str  # Hex — etiket rengi
    summary_tr: str  # 1-2 cümlelik Türkçe özet

    @property
    def score_display(self) -> str:
        """Sayısal skoru 1 ondalıklı olarak yazdırır."""
        return f"{self.score:.1f}"


def _finding_raw_score(finding: Finding) -> float:
    """Tek bir bulgu için ham skor:
    CVE'li ise maksimum CVSS, değilse severity ağırlığı.
    """
    cves = finding.evidence.get("cves") if finding.evidence else None
    if cves:
        cvss_values = [
            float(c.get("cvss") or 0) for c in cves if c.get("cvss")
        ]
        if cvss_values:
            return max(cvss_values)
    return _SEVERITY_WEIGHT.get(finding.severity, 0.5)


def compute_risk_score(findings: Iterable[Finding]) -> float:
    """0.0–10.0 arası skor döner.

    Anchor: en yüksek bulgu skoru.
    Bonus: aynı tip riskin çok olması (diminishing — log).
    """
    findings_list = list(findings)
    if not findings_list:
        return 0.0

    max_single = max(_finding_raw_score(f) for f in findings_list)

    # Kaç tane "önemli" bulgu var (INFO hariç) — skor çoğulluğu biraz artırır
    significant = [
        f for f in findings_list
        if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
    ]
    count_bonus = min(1.0, 0.35 * math.log(len(significant) + 1))

    score = min(10.0, max_single + count_bonus)
    return round(score, 1)


def risk_label_and_color(score: float) -> tuple[str, str]:
    """Skora göre Türkçe etiket + renk (hex)."""
    if score <= 0.0:
        return "Temiz", "#388e3c"
    if score < 4.0:
        return "Düşük", "#689f38"
    if score < 7.0:
        return "Orta", "#ef6c00"
    if score < 9.0:
        return "Yüksek", "#d32f2f"
    return "Kritik", "#8b0000"


def _build_summary_text(
    score: float, label: str, findings: list[Finding],
) -> str:
    """Yönetici için 1-2 cümlelik Türkçe özet."""
    if not findings:
        return (
            "Seçtiğiniz tarama derinliğinde güvenlik sorunu tespit edilmedi. "
            "Sisteminiz bu tarama kapsamında temiz görünüyor — tebrikler. "
            "Daha kapsamlı bir tarama için Standart/Derin seçeneğini deneyebilirsiniz."
        )

    # Severity başına sayım
    counts = {sev: 0 for sev in Severity}
    for f in findings:
        counts[f.severity] += 1

    parts: list[str] = []
    for sev, ad in (
        (Severity.CRITICAL, "kritik"),
        (Severity.HIGH, "yüksek"),
        (Severity.MEDIUM, "orta"),
        (Severity.LOW, "düşük"),
    ):
        if counts[sev]:
            parts.append(f"<b>{counts[sev]} {ad}</b>")
    if counts[Severity.INFO]:
        parts.append(f"{counts[Severity.INFO]} bilgi")

    parts_text = ", ".join(parts) if parts else "birkaç"

    # Risk seviyesine göre aksiyon tonu
    if label in ("Kritik", "Yüksek"):
        tone = (
            "Acil aksiyon gerekiyor — bazı bulgular saldırganın sisteminize "
            "zarar vermesine yol açabilir."
        )
    elif label == "Orta":
        tone = (
            "Sisteminiz genel olarak tehlikeli durumda değil ama bazı "
            "yapılandırma iyileştirmeleri önemli."
        )
    else:
        tone = (
            "Düşük öncelikli iyileştirmeler — acil bir risk yok ama en iyi "
            "pratikler için uygulanması tavsiye edilir."
        )

    return (
        f"Sisteminizde {parts_text} seviyeli toplam {len(findings)} bulgu "
        f"tespit edildi. Risk seviyesi: <b>{label}</b> ({score:.1f}/10). {tone}"
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
