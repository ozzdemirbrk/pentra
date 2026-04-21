"""xss.py — reflected XSS probe testleri."""

from __future__ import annotations

from unittest.mock import MagicMock

import requests

from pentra.core.web_probes.xss import XssProbe
from pentra.models import Severity


def _resp(text: str) -> MagicMock:
    r = MagicMock()
    r.status_code = 200
    r.text = text
    return r


class TestReflectionDetection:
    def test_unescaped_reflection_detected(self) -> None:
        probe = XssProbe()
        session = MagicMock(spec=requests.Session)

        def fake_get(url, **_kwargs):
            # Query string'i response'a yansıt (kaçış yok)
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(url).query)
            value = next(iter(qs.values()))[0] if qs else ""
            return _resp(f"<html><body>Aradığınız: {value}</body></html>")

        session.get.side_effect = fake_get

        findings = probe.probe("https://example.com/search", session)
        assert any("Reflected XSS" in f.title for f in findings)
        first = next(f for f in findings if "Reflected XSS" in f.title)
        assert first.severity == Severity.HIGH

    def test_escaped_reflection_no_finding(self) -> None:
        probe = XssProbe()
        session = MagicMock(spec=requests.Session)

        def fake_get(url, **_kwargs):
            # Güvenli sunucu: HTML escape uygular
            from urllib.parse import urlparse, parse_qs
            from html import escape
            qs = parse_qs(urlparse(url).query)
            value = next(iter(qs.values()))[0] if qs else ""
            return _resp(f"<html><body>Aradığınız: {escape(value)}</body></html>")

        session.get.side_effect = fake_get

        findings = probe.probe("https://example.com/search", session)
        assert findings == []

    def test_no_reflection_no_finding(self) -> None:
        """Parametre yanıta hiç yansımıyorsa → test uygulanamıyor, bulgu yok."""
        probe = XssProbe()
        session = MagicMock(spec=requests.Session)
        session.get.return_value = _resp("<html><body>Sabit sayfa</body></html>")

        findings = probe.probe("https://example.com/search", session)
        assert findings == []


class TestCanaryUniqueness:
    def test_canary_varies_between_requests(self) -> None:
        """Her istek için farklı canary üretilmeli."""
        probe = XssProbe()
        session = MagicMock(spec=requests.Session)
        urls_called: list[str] = []

        def fake_get(url, **_kwargs):
            urls_called.append(url)
            return _resp("")

        session.get.side_effect = fake_get

        probe.probe("https://example.com", session)

        # En azından bazı farklı canary'ler üretilmiş olmalı
        # (her param için farklı canary)
        canaries = [u.split("=")[-1] for u in urls_called]
        unique_canaries = {c for c in canaries if "pentra" in c}
        # En az 3 farklı canary beklenir
        assert len(unique_canaries) >= 3


class TestParamDedup:
    def test_one_finding_per_param(self) -> None:
        probe = XssProbe()
        session = MagicMock(spec=requests.Session)

        def fake_get(url, **_kwargs):
            # Query'yi olduğu gibi yansıt (kaçışsız)
            from urllib.parse import urlparse
            return _resp(f"echo: {urlparse(url).query}")

        session.get.side_effect = fake_get

        findings = probe.probe("https://example.com", session)

        titles = [f.title for f in findings]
        assert len(titles) == len(set(titles))
