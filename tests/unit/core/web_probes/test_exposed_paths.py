"""exposed_paths.py — probe testleri."""

from __future__ import annotations

from unittest.mock import MagicMock

import requests

from pentra.core.web_probes.exposed_paths import ExposedPathsProbe
from pentra.models import Severity


def _response(status_code: int, text: str = "") -> MagicMock:
    r = MagicMock()
    r.status_code = status_code
    r.text = text
    r.content = text.encode() if text else b""
    return r


def _session_returning(response_map: dict[str, MagicMock]) -> MagicMock:
    """URL → response eşlemesi; varsayılan 404."""
    session = MagicMock(spec=requests.Session)

    def fake_get(url, **_kwargs):
        for key, resp in response_map.items():
            if key in url:
                return resp
        return _response(404)

    session.get.side_effect = fake_get
    return session


class TestEnvFileExposed:
    def test_env_with_signature_flagged_critical(self) -> None:
        probe = ExposedPathsProbe()
        session = _session_returning({
            "/.env": _response(200, "DB_PASSWORD=secret123\nAPI_KEY=xyz"),
        })
        findings = probe.probe("https://example.com", session)

        env_findings = [f for f in findings if ".env dosyası" in f.title]
        assert len(env_findings) == 1
        assert env_findings[0].severity == Severity.CRITICAL

    def test_env_without_signature_not_flagged(self) -> None:
        """200 yanıt ama içerik `=` içermiyor → .env değil (SPA catch-all olabilir)."""
        probe = ExposedPathsProbe()
        session = _session_returning({
            "/.env": _response(200, "<html>SPA fallback</html>"),
        })
        findings = probe.probe("https://example.com", session)
        assert not any(".env dosyası" in f.title for f in findings)

    def test_env_404_not_flagged(self) -> None:
        probe = ExposedPathsProbe()
        session = _session_returning({})  # her şey 404
        findings = probe.probe("https://example.com", session)
        assert not any(".env dosyası" in f.title for f in findings)


class TestGitConfigExposed:
    def test_git_config_with_core_section_flagged(self) -> None:
        probe = ExposedPathsProbe()
        session = _session_returning({
            "/.git/config": _response(200, "[core]\n\trepositoryformatversion = 0\n"),
        })
        findings = probe.probe("https://example.com", session)

        git_findings = [f for f in findings if ".git deposu" in f.title]
        assert len(git_findings) == 1
        assert git_findings[0].severity == Severity.HIGH


class TestBackupFiles:
    def test_wp_config_bak_flagged_critical(self) -> None:
        probe = ExposedPathsProbe()
        session = _session_returning({
            "/wp-config.php.bak": _response(200, "<?php $password='secret'; ?>"),
        })
        findings = probe.probe("https://example.com", session)

        assert any("wp-config.php.bak" in f.target for f in findings)
        bak = next(f for f in findings if "wp-config.php.bak" in f.target)
        assert bak.severity == Severity.CRITICAL


class TestSecurityTxt:
    def test_missing_security_txt_produces_info(self) -> None:
        probe = ExposedPathsProbe()
        session = _session_returning({})  # hepsi 404
        findings = probe.probe("https://example.com", session)

        sec_findings = [f for f in findings if "security.txt yok" in f.title]
        assert len(sec_findings) == 1
        assert sec_findings[0].severity == Severity.INFO

    def test_present_security_txt_no_finding(self) -> None:
        probe = ExposedPathsProbe()
        session = _session_returning({
            "/.well-known/security.txt": _response(200, "Contact: mailto:a@b.com"),
        })
        findings = probe.probe("https://example.com", session)
        assert not any("security.txt yok" in f.title for f in findings)


class TestBaseUrlJoining:
    def test_url_with_trailing_slash_handled(self) -> None:
        probe = ExposedPathsProbe()
        calls: list[str] = []

        session = MagicMock(spec=requests.Session)

        def fake_get(url, **_kwargs):
            calls.append(url)
            return _response(404)

        session.get.side_effect = fake_get

        probe.probe("https://example.com/", session)

        # /.env URL'i /example.com/.env olmalı, çift slash yok
        env_calls = [c for c in calls if "/.env" in c and "well-known" not in c]
        assert len(env_calls) == 1
        assert "//.env" not in env_calls[0]
