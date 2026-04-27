"""path_traversal.py — probe tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import requests

from pentra.core.web_probes.path_traversal import PathTraversalProbe
from pentra.models import Severity


def _response(status: int, text: str = "") -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.text = text
    return r


class TestLeakDetection:
    def test_linux_passwd_leak_detected(self) -> None:
        probe = PathTraversalProbe()
        session = MagicMock(spec=requests.Session)

        # Pretend every response contains /etc/passwd content
        session.get.return_value = _response(
            200,
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin/nologin",
        )

        findings = probe.probe("https://example.com", session)

        assert any("Path traversal" in f.title for f in findings)
        first = next(f for f in findings if "Path traversal" in f.title)
        assert first.severity == Severity.CRITICAL
        assert "root:x:0:0" in first.evidence["response_snippet"]

    def test_windows_leak_detected(self) -> None:
        probe = PathTraversalProbe()
        session = MagicMock(spec=requests.Session)
        session.get.return_value = _response(
            200,
            "; for 16-bit app support\n[fonts]\n[mci extensions]",
        )
        findings = probe.probe("https://example.com", session)
        assert any("Path traversal" in f.title for f in findings)

    def test_no_leak_no_finding(self) -> None:
        probe = PathTraversalProbe()
        session = MagicMock(spec=requests.Session)
        # Normal HTML on every request
        session.get.return_value = _response(200, "<html><h1>Hoş geldiniz</h1></html>")
        findings = probe.probe("https://example.com", session)
        assert findings == []

    def test_404_responses_no_finding(self) -> None:
        probe = PathTraversalProbe()
        session = MagicMock(spec=requests.Session)
        session.get.return_value = _response(404, "Not Found")
        findings = probe.probe("https://example.com", session)
        assert findings == []


class TestParameterDedup:
    def test_only_one_finding_per_vulnerable_param(self) -> None:
        """Once the first payload proves a parameter, others should be skipped."""
        probe = PathTraversalProbe()
        session = MagicMock(spec=requests.Session)
        session.get.return_value = _response(200, "root:x:0:0:root:/root:/bin/bash")

        findings = probe.probe("https://example.com", session)

        # At most 1 finding per parameter — no duplicate test
        param_titles = [f.title for f in findings if "Path traversal" in f.title]
        # 10 parameters, identical response → 10 findings (each from a different parameter)
        assert len(param_titles) == len(set(param_titles))


class TestUrlBuilding:
    def test_query_separator_correct(self) -> None:
        probe = PathTraversalProbe()
        urls_called: list[str] = []

        session = MagicMock(spec=requests.Session)

        def fake_get(url, **_kwargs):
            urls_called.append(url)
            return _response(404)

        session.get.side_effect = fake_get

        probe.probe("https://example.com/page", session)
        # When there is no ?, the first parameter is appended with ?
        assert any("?file=" in u for u in urls_called)

    def test_existing_query_uses_ampersand(self) -> None:
        probe = PathTraversalProbe()
        urls_called: list[str] = []
        session = MagicMock(spec=requests.Session)

        def fake_get(url, **_kwargs):
            urls_called.append(url)
            return _response(404)

        session.get.side_effect = fake_get

        probe.probe("https://example.com/page?id=1", session)
        assert any("?id=1&" in u for u in urls_called)
