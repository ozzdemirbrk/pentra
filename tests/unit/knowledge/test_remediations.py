"""remediations_tr.py — guide lookup testleri."""

from __future__ import annotations

import pytest

from pentra.knowledge.remediations_tr import (
    FixStep,
    RemediationGuide,
    get_guide,
    get_guide_by_key,
)
from pentra.models import Finding, Severity


def _finding_with_title(title: str) -> Finding:
    return Finding(
        scanner_name="test",
        severity=Severity.LOW,
        title=title,
        description="d",
        target="x",
    )


class TestGuideStructure:
    @pytest.mark.parametrize("key", [
        "csp_missing",
        "hsts_missing",
        "xfo_missing",
        "xcto_missing",
        "referrer_missing",
        "server_leak",
        "http_only",
        "security_txt",
        "redis_open",
        "mongodb_open",
        "elasticsearch_open",
        "mysql_default",
        "ssh_default",
        "env_exposed",
    ])
    def test_every_known_key_returns_guide(self, key: str) -> None:
        guide = get_guide_by_key(key)
        assert guide is not None
        assert isinstance(guide, RemediationGuide)

    def test_unknown_key_returns_none(self) -> None:
        assert get_guide_by_key("nonexistent_key_xyz") is None

    def test_guide_has_all_sections(self) -> None:
        """Her rehber 5 bölümü doldurmuş olmalı."""
        guide = get_guide_by_key("csp_missing")
        assert guide is not None
        assert guide.problem_summary
        assert guide.why_important
        assert len(guide.fix_steps) >= 1
        assert guide.verification
        assert len(guide.references) >= 1

    def test_fix_steps_are_valid(self) -> None:
        guide = get_guide_by_key("hsts_missing")
        assert guide is not None
        for step in guide.fix_steps:
            assert isinstance(step, FixStep)
            assert step.platform  # boş olmamalı


class TestTitleMatching:
    @pytest.mark.parametrize("title,expected_key_present", [
        ("CSP eksik", True),
        ("HSTS eksik", True),
        ("X-Frame-Options eksik (clickjacking koruması)", True),
        ("X-Content-Type-Options eksik (MIME sniffing)", True),
        ("Referrer-Policy eksik", True),
        ("Versiyon sızıntısı: Server", True),
        ("Versiyon sızıntısı: Server — 5 bilinen CVE", True),
        ("HTTP üzerinden sunuluyor (şifresiz)", True),
        ("security.txt yok", True),
        ("Redis parolasız erişilebilir — port 6379", True),
        ("MongoDB parolasız erişilebilir — port 27017", True),
        ("Elasticsearch parolasız erişilebilir — port 9200", True),
        ("MySQL varsayılan parola kabul ediliyor — root@3306", True),
        ("SSH varsayılan parola kabul ediliyor — root@22", True),
        (".env dosyası public erişilebilir", True),
    ])
    def test_known_findings_get_guide(self, title: str, expected_key_present: bool) -> None:
        finding = _finding_with_title(title)
        guide = get_guide(finding)
        if expected_key_present:
            assert guide is not None, f"'{title}' için rehber bulunamadı"

    def test_unknown_title_returns_none(self) -> None:
        finding = _finding_with_title("Rastgele tanımsız bulgu")
        assert get_guide(finding) is None


class TestGuideContent:
    def test_csp_guide_has_platform_variants(self) -> None:
        guide = get_guide_by_key("csp_missing")
        assert guide is not None
        platforms = {step.platform for step in guide.fix_steps}
        assert "Nginx" in platforms
        assert "Apache" in platforms
        # IIS ve Cloudflare varyantları da olmalı
        assert any("IIS" in p for p in platforms)

    def test_redis_guide_mentions_requirepass(self) -> None:
        """Redis rehberinde 'requirepass' yönergesi geçmeli."""
        guide = get_guide_by_key("redis_open")
        assert guide is not None
        combined = "\n".join(step.code for step in guide.fix_steps)
        assert "requirepass" in combined

    def test_ssh_guide_mentions_key_auth(self) -> None:
        """SSH rehberi parola yerine key authentication önermeli."""
        guide = get_guide_by_key("ssh_default")
        assert guide is not None
        combined = "\n".join(step.code for step in guide.fix_steps)
        assert "PasswordAuthentication no" in combined

    def test_http_only_guide_mentions_lets_encrypt(self) -> None:
        guide = get_guide_by_key("http_only")
        assert guide is not None
        combined = guide.why_important + "\n".join(
            step.instructions + step.code for step in guide.fix_steps
        )
        assert "certbot" in combined.lower() or "let's encrypt" in combined.lower()
