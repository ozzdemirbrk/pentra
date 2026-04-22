"""risk_score.py — skor hesaplama + etiket + özet testleri."""

from __future__ import annotations

import pytest

from pentra.models import Finding, Severity
from pentra.reporting.risk_score import (
    assess_risk,
    compute_risk_score,
    risk_label_and_color,
    top_actions,
)


def _finding(severity: Severity, title: str = "t", cvss: float | None = None) -> Finding:
    evidence = {}
    if cvss is not None:
        evidence = {"cves": [{"id": "CVE-X", "cvss": cvss, "severity": "X", "description": "", "url": ""}]}
    return Finding(
        scanner_name="test",
        severity=severity,
        title=title,
        description="d",
        target="127.0.0.1",
        evidence=evidence,
    )


class TestComputeScore:
    def test_no_findings_zero(self) -> None:
        assert compute_risk_score([]) == 0.0

    def test_single_critical(self) -> None:
        score = compute_risk_score([_finding(Severity.CRITICAL)])
        assert score >= 9.0  # Critical anchor

    def test_single_high(self) -> None:
        score = compute_risk_score([_finding(Severity.HIGH)])
        assert 7.0 <= score < 9.0

    def test_single_medium(self) -> None:
        score = compute_risk_score([_finding(Severity.MEDIUM)])
        assert 4.0 <= score < 7.0

    def test_single_low(self) -> None:
        score = compute_risk_score([_finding(Severity.LOW)])
        assert 2.0 <= score < 4.0

    def test_single_info(self) -> None:
        score = compute_risk_score([_finding(Severity.INFO)])
        assert score < 1.0

    def test_cvss_overrides_severity(self) -> None:
        """CVSS 10.0 içeren finding severity LOW olsa bile skor yüksek olmalı."""
        score = compute_risk_score([_finding(Severity.LOW, cvss=10.0)])
        assert score >= 9.0

    def test_multiple_findings_bonus(self) -> None:
        """Çok sayıda önemli bulgu skoru biraz artırır (diminishing)."""
        single_high = compute_risk_score([_finding(Severity.HIGH)])
        many_highs = compute_risk_score([_finding(Severity.HIGH) for _ in range(10)])
        assert many_highs > single_high
        assert many_highs <= 10.0  # cap

    def test_score_capped_at_10(self) -> None:
        findings = [_finding(Severity.CRITICAL, cvss=10.0) for _ in range(50)]
        assert compute_risk_score(findings) <= 10.0


class TestLabelAndColor:
    @pytest.mark.parametrize("score,expected_label", [
        (0.0, "Temiz"),
        (2.5, "Düşük"),
        (5.0, "Orta"),
        (7.5, "Yüksek"),
        (9.5, "Kritik"),
        (10.0, "Kritik"),
    ])
    def test_label_brackets(self, score: float, expected_label: str) -> None:
        label, color = risk_label_and_color(score)
        assert label == expected_label
        assert color.startswith("#")


class TestAssessRisk:
    def test_no_findings_returns_clean(self) -> None:
        r = assess_risk([])
        assert r.score == 0.0
        assert r.label == "Temiz"
        assert "tespit edilmedi" in r.summary_tr or "temiz" in r.summary_tr.lower()

    def test_critical_finding_yields_high_risk(self) -> None:
        r = assess_risk([_finding(Severity.CRITICAL, "Redis açık")])
        assert r.score >= 9.0
        assert r.label in ("Yüksek", "Kritik")
        assert "<b>" in r.summary_tr  # HTML formatlama (kritik sayısı bold)

    def test_summary_counts_severities(self) -> None:
        findings = [
            _finding(Severity.CRITICAL),
            _finding(Severity.HIGH),
            _finding(Severity.HIGH),
            _finding(Severity.MEDIUM),
        ]
        r = assess_risk(findings)
        assert "1 kritik" in r.summary_tr.lower()
        assert "2 yüksek" in r.summary_tr.lower()
        assert "1 orta" in r.summary_tr.lower()


class TestTopActions:
    def test_returns_most_critical_first(self) -> None:
        findings = [
            _finding(Severity.LOW, "low1"),
            _finding(Severity.CRITICAL, "crit1"),
            _finding(Severity.MEDIUM, "med1"),
            _finding(Severity.HIGH, "high1"),
        ]
        top = top_actions(findings, max_count=3)
        assert len(top) == 3
        titles = [f.title for f in top]
        assert titles[0] == "crit1"
        assert "high1" in titles
        assert "low1" not in titles  # 3 en kritik arasında olmamalı

    def test_cvss_weights_within_same_severity(self) -> None:
        """Aynı severity içinde CVSS'i yüksek olan önce gelsin."""
        low_cvss = _finding(Severity.HIGH, "low_cvss", cvss=7.0)
        high_cvss = _finding(Severity.HIGH, "high_cvss", cvss=9.8)
        top = top_actions([low_cvss, high_cvss], max_count=2)
        assert top[0].title == "high_cvss"

    def test_empty_returns_empty(self) -> None:
        assert top_actions([]) == []
