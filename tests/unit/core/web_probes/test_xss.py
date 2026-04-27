"""xss.py — reflected XSS probe tests (including echo-fallback detection)."""

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


# A server where echo-fallback would NOT trigger: only reflects known params
# (q, search etc.) — a random `pentraXXX` param is not reflected.
_KNOWN_PARAMS: set[str] = {
    "q", "query", "search", "s", "keyword", "term", "name",
}


def _selective_reflection_server() -> MagicMock:
    """A typical real server: reflects only well-known search/form parameters."""
    from urllib.parse import urlparse, parse_qs

    session = MagicMock(spec=requests.Session)

    def fake_get(url, **_kwargs):
        qs = parse_qs(urlparse(url).query)
        if not qs:
            return _resp("<html><body>Anasayfa</body></html>")

        param_name = next(iter(qs.keys()))
        value = qs[param_name][0]

        # Only well-known params are reflected
        if param_name in _KNOWN_PARAMS:
            return _resp(f"<html><body>Aradığınız: {value}</body></html>")
        return _resp("<html><body>Anasayfa</body></html>")

    session.get.side_effect = fake_get
    return session


def _echo_everything_server() -> MagicMock:
    """Echo-fallback server: reflects EVERY param (decoded) (SPA, dev server, debug)."""
    from urllib.parse import urlparse, parse_qs

    session = MagicMock(spec=requests.Session)

    def fake_get(url, **_kwargs):
        qs = parse_qs(urlparse(url).query)
        if not qs:
            return _resp("home")
        # Reflect all decoded values back into the response
        values = [v[0] for v in qs.values()]
        return _resp(f"<html><body>echo: {' '.join(values)}</body></html>")

    session.get.side_effect = fake_get
    return session


# =====================================================================
# Echo-fallback detection (new)
# =====================================================================
class TestEchoFallback:
    def test_echo_everything_server_yields_info_only(self) -> None:
        """If the site reflects even random params, a single INFO finding is returned."""
        probe = XssProbe()
        session = _echo_everything_server()

        findings = probe.probe("https://spa.example", session)

        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "atland" in findings[0].title.lower()  # "XSS test skipped"

    def test_echo_fallback_blocks_false_positives(self) -> None:
        """Used to produce 20+ HIGH findings — now just 1 INFO."""
        probe = XssProbe()
        session = _echo_everything_server()
        findings = probe.probe("https://spa.example", session)

        # No HIGH severity XSS finding should appear
        assert not any(f.severity == Severity.HIGH for f in findings)


# =====================================================================
# Real XSS detection (reflection on a specific param)
# =====================================================================
class TestRealXssDetection:
    def test_real_xss_on_q_parameter(self) -> None:
        """A known param like q= is reflected, others are not → real XSS."""
        probe = XssProbe()
        session = _selective_reflection_server()

        findings = probe.probe("https://realsite.example", session)

        # At least one HIGH XSS finding (q is reflected)
        high_findings = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high_findings) >= 1
        assert any("q" in f.title or "query" in f.title for f in high_findings)

    def test_escaped_reflection_no_finding(self) -> None:
        """Site HTML-escapes input → no XSS."""
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
            # HTML escape applied
            if param_name in _KNOWN_PARAMS:
                return _resp(f"<html>Aradığınız: {escape(value)}</html>")
            return _resp("<html>Home</html>")

        session.get.side_effect = fake_get
        findings = probe.probe("https://safesite.example", session)

        # Neither echo-fallback INFO nor HIGH XSS
        assert findings == []

    def test_no_reflection_no_finding(self) -> None:
        """No param is reflected → no finding."""
        probe = XssProbe()
        session = MagicMock(spec=requests.Session)
        session.get.return_value = _resp("<html>Sabit sayfa</html>")

        findings = probe.probe("https://static.example", session)
        assert findings == []


# =====================================================================
# Canary behavior
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
        """In a real XSS scenario, at most 1 finding per param."""
        probe = XssProbe()
        session = _selective_reflection_server()

        findings = probe.probe("https://realsite.example", session)
        xss_findings = [f for f in findings if f.severity == Severity.HIGH]

        titles = [f.title for f in xss_findings]
        assert len(titles) == len(set(titles))
