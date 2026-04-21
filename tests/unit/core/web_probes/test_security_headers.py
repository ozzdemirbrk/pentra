"""security_headers.py probe testleri — mocked HTTP yanıtlarıyla."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from pentra.core.web_probes.security_headers import SecurityHeadersProbe
from pentra.models import Severity


def _mock_session(status_code: int, headers: dict[str, str]) -> MagicMock:
    """Fake session — get() çağrısı sabit response döndürür."""
    response = MagicMock()
    response.status_code = status_code
    response.headers = headers

    session = MagicMock(spec=requests.Session)
    session.get.return_value = response
    return session


class TestHttpsRequired:
    def test_http_url_flagged_as_high(self) -> None:
        probe = SecurityHeadersProbe()
        session = _mock_session(200, {})
        findings = probe.probe("http://example.com", session)

        titles = [f.title for f in findings]
        assert any("HTTP üzerinden" in t for t in titles)

        http_finding = next(f for f in findings if "HTTP üzerinden" in f.title)
        assert http_finding.severity == Severity.HIGH

    def test_https_url_not_flagged_for_http_risk(self) -> None:
        probe = SecurityHeadersProbe()
        session = _mock_session(200, {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        })
        findings = probe.probe("https://example.com", session)
        assert not any("HTTP üzerinden" in f.title for f in findings)


class TestMissingHeaders:
    def test_all_security_headers_missing_generates_findings(self) -> None:
        probe = SecurityHeadersProbe()
        session = _mock_session(200, {})
        findings = probe.probe("https://example.com", session)

        titles = {f.title for f in findings}
        assert "HSTS eksik" in titles
        assert "CSP eksik" in titles
        assert any("X-Frame-Options eksik" in t for t in titles)
        assert any("X-Content-Type-Options eksik" in t for t in titles)
        assert "Referrer-Policy eksik" in titles

    def test_all_headers_present_no_missing_findings(self) -> None:
        probe = SecurityHeadersProbe()
        session = _mock_session(200, {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        })
        findings = probe.probe("https://example.com", session)

        missing_titles = {f.title for f in findings if "eksik" in f.title}
        assert missing_titles == set()

    def test_http_url_skips_hsts_check(self) -> None:
        """HSTS sadece HTTPS'te anlamlıdır — HTTP sitesinde HSTS eksikliği raporlanmamalı."""
        probe = SecurityHeadersProbe()
        session = _mock_session(200, {})
        findings = probe.probe("http://example.com", session)

        titles = [f.title for f in findings]
        assert "HSTS eksik" not in titles


class TestLeakyHeaders:
    def test_server_header_generates_info_finding(self) -> None:
        probe = SecurityHeadersProbe()
        session = _mock_session(200, {
            "Server": "Apache/2.4.41 (Ubuntu)",
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        })
        findings = probe.probe("https://example.com", session)

        leak_findings = [f for f in findings if "Versiyon sızıntısı" in f.title]
        assert len(leak_findings) == 1
        assert leak_findings[0].severity == Severity.INFO
        assert "Apache/2.4.41" in leak_findings[0].evidence["why_vulnerable"]

    def test_x_powered_by_generates_finding(self) -> None:
        probe = SecurityHeadersProbe()
        session = _mock_session(200, {
            "X-Powered-By": "PHP/7.4.3",
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        })
        findings = probe.probe("https://example.com", session)

        assert any("X-Powered-By" in f.title for f in findings)


class TestNetworkFailure:
    def test_connection_error_produces_info_finding(self) -> None:
        probe = SecurityHeadersProbe()
        session = MagicMock(spec=requests.Session)
        session.get.side_effect = requests.ConnectionError("host unreachable")

        findings = probe.probe("https://nonexistent.example", session)

        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "başarısız" in findings[0].title.lower()


class TestEvidence:
    def test_findings_include_evidence(self) -> None:
        probe = SecurityHeadersProbe()
        session = _mock_session(200, {})
        findings = probe.probe("https://example.com", session)

        for f in findings:
            if "eksik" in f.title or "HTTP" in f.title:
                assert "probe_name" in f.evidence
                assert f.evidence["probe_name"] == "security_headers"
                assert "request" in f.evidence
                assert "response_status" in f.evidence
