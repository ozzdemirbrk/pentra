"""xss.py — reflected XSS probe testleri (echo-fallback tespiti dahil)."""

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


# Echo-fallback tespit edilmeyecek sunucu: SADECE bilinen param'ları yansıtır
# (q, search gibi) — rastgele `pentraXXX` param'ı yansımaz.
_KNOWN_PARAMS: set[str] = {
    "q", "query", "search", "s", "keyword", "term", "name",
}


def _selective_reflection_server() -> MagicMock:
    """Tipik bir gerçek sunucu: sadece bilinen search/form param'larını yansıtır."""
    from urllib.parse import urlparse, parse_qs

    session = MagicMock(spec=requests.Session)

    def fake_get(url, **_kwargs):
        qs = parse_qs(urlparse(url).query)
        if not qs:
            return _resp("<html><body>Anasayfa</body></html>")

        param_name = next(iter(qs.keys()))
        value = qs[param_name][0]

        # Sadece bilinen param'lar yansıtılır
        if param_name in _KNOWN_PARAMS:
            return _resp(f"<html><body>Aradığınız: {value}</body></html>")
        return _resp("<html><body>Anasayfa</body></html>")

    session.get.side_effect = fake_get
    return session


def _echo_everything_server() -> MagicMock:
    """Echo-fallback sunucu: HER param'ı (decoded) yansıtır (SPA, dev server, debug)."""
    from urllib.parse import urlparse, parse_qs

    session = MagicMock(spec=requests.Session)

    def fake_get(url, **_kwargs):
        qs = parse_qs(urlparse(url).query)
        if not qs:
            return _resp("home")
        # Tüm decoded değerleri yanıta yansıt
        values = [v[0] for v in qs.values()]
        return _resp(f"<html><body>echo: {' '.join(values)}</body></html>")

    session.get.side_effect = fake_get
    return session


# =====================================================================
# Echo-fallback tespiti (yeni)
# =====================================================================
class TestEchoFallback:
    def test_echo_everything_server_yields_info_only(self) -> None:
        """Site rastgele param'ı bile yansıtıyorsa tek bir INFO bulgu döner."""
        probe = XssProbe()
        session = _echo_everything_server()

        findings = probe.probe("https://spa.example", session)

        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "atland" in findings[0].title.lower()  # "XSS testi atlandı"

    def test_echo_fallback_blocks_false_positives(self) -> None:
        """Eskiden 20+ HIGH bulgu üretirdi — şimdi sadece 1 INFO."""
        probe = XssProbe()
        session = _echo_everything_server()
        findings = probe.probe("https://spa.example", session)

        # HIGH severity XSS bulgusu OLMAMALI
        assert not any(f.severity == Severity.HIGH for f in findings)


# =====================================================================
# Gerçek XSS tespiti (spesifik param'da reflection)
# =====================================================================
class TestRealXssDetection:
    def test_real_xss_on_q_parameter(self) -> None:
        """q= gibi bilinen param yansıtılıyor, diğerleri yansıtılmıyor → gerçek XSS."""
        probe = XssProbe()
        session = _selective_reflection_server()

        findings = probe.probe("https://realsite.example", session)

        # En az bir HIGH XSS bulgusu olmalı (q param'ı yansıtılıyor)
        high_findings = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high_findings) >= 1
        assert any("q" in f.title or "query" in f.title for f in high_findings)

    def test_escaped_reflection_no_finding(self) -> None:
        """Site HTML escape uyguluyor → XSS yok."""
        from html import escape
        from urllib.parse import urlparse, parse_qs

        probe = XssProbe()
        session = MagicMock(spec=requests.Session)

        def fake_get(url, **_kwargs):
            qs = parse_qs(urlparse(url).query)
            if not qs:
                return _resp("<html>Home</html>")
            param_name = next(iter(qs.keys()))
            value = qs[param_name][0]
            # HTML escape uygulanıyor
            if param_name in _KNOWN_PARAMS:
                return _resp(f"<html>Aradığınız: {escape(value)}</html>")
            return _resp("<html>Home</html>")

        session.get.side_effect = fake_get
        findings = probe.probe("https://safesite.example", session)

        # Ne echo-fallback INFO ne de HIGH XSS
        assert findings == []

    def test_no_reflection_no_finding(self) -> None:
        """Hiçbir param yansımıyor → bulgu yok."""
        probe = XssProbe()
        session = MagicMock(spec=requests.Session)
        session.get.return_value = _resp("<html>Sabit sayfa</html>")

        findings = probe.probe("https://static.example", session)
        assert findings == []


# =====================================================================
# Canary davranışı
# =====================================================================
class TestCanaryUniqueness:
    def test_canary_varies_between_requests(self) -> None:
        probe = XssProbe()
        urls_called: list[str] = []
        session = MagicMock(spec=requests.Session)

        def fake_get(url, **_kwargs):
            urls_called.append(url)
            return _resp("")

        session.get.side_effect = fake_get
        probe.probe("https://example.com", session)

        canaries = {u for u in urls_called if "pentra" in u}
        assert len(canaries) >= 3


class TestParamDedup:
    def test_one_finding_per_param_on_real_xss(self) -> None:
        """Gerçek XSS ortamında her param max 1 bulgu."""
        probe = XssProbe()
        session = _selective_reflection_server()

        findings = probe.probe("https://realsite.example", session)
        xss_findings = [f for f in findings if f.severity == Severity.HIGH]

        titles = [f.title for f in xss_findings]
        assert len(titles) == len(set(titles))
