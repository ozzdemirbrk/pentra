"""exposed_paths.py — probe tests (after soft-404 + content validator)."""

from __future__ import annotations

from unittest.mock import MagicMock

import requests

from pentra.core.web_probes.exposed_paths import ExposedPathsProbe
from pentra.models import Severity


def _response(
    status_code: int,
    text: str = "",
    content_type: str = "text/html",
    content: bytes | None = None,
) -> MagicMock:
    r = MagicMock()
    r.status_code = status_code
    r.text = text
    r.content = content if content is not None else text.encode("utf-8", errors="replace")
    r.headers = {"Content-Type": content_type}
    return r


def _session_with_map(response_map: dict[str, MagicMock], default: MagicMock) -> MagicMock:
    """Returns the response whose URL fragment matches, otherwise `default`."""
    session = MagicMock(spec=requests.Session)

    def fake_get(url, **_kwargs):
        for key, resp in response_map.items():
            if key in url:
                return resp
        return default

    session.get.side_effect = fake_get
    return session


# Common 404 default
_NOT_FOUND = _response(404, "", content_type="text/plain")


# =====================================================================
# .env validator
# =====================================================================
class TestEnvValidator:
    def test_real_env_file_flagged_critical(self) -> None:
        probe = ExposedPathsProbe()
        env_body = "DB_PASSWORD=secret123\nAPI_KEY=xyz\nDEBUG=true\n"
        session = _session_with_map(
            {"/.env": _response(200, env_body, content_type="text/plain")},
            default=_NOT_FOUND,
        )
        findings = probe.probe("https://example.com", session)

        env = [f for f in findings if ".env file" in f.title]
        assert len(env) == 1
        assert env[0].severity == Severity.CRITICAL

    def test_html_response_at_env_path_not_flagged(self) -> None:
        """Soft 404: if server returns HTML home page for .env → false positive MUST be prevented."""
        probe = ExposedPathsProbe()
        html = "<html><body>Hoş geldiniz! name=value etc.</body></html>"
        session = _session_with_map(
            {"/.env": _response(200, html, content_type="text/html")},
            default=_NOT_FOUND,
        )
        findings = probe.probe("https://example.com", session)
        assert not any(".env file" in f.title for f in findings)

    def test_plaintext_but_no_env_pattern_not_flagged(self) -> None:
        probe = ExposedPathsProbe()
        # Content-Type plain but content is not .env
        session = _session_with_map(
            {"/.env": _response(200, "merhaba dünya", content_type="text/plain")},
            default=_NOT_FOUND,
        )
        findings = probe.probe("https://example.com", session)
        assert not any(".env file" in f.title for f in findings)


# =====================================================================
# Git config validator
# =====================================================================
class TestGitConfigValidator:
    def test_real_git_config_flagged(self) -> None:
        probe = ExposedPathsProbe()
        git_body = '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n'
        session = _session_with_map(
            {"/.git/config": _response(200, git_body, content_type="text/plain")},
            default=_NOT_FOUND,
        )
        findings = probe.probe("https://example.com", session)
        assert any(".git repository" in f.title for f in findings)

    def test_html_at_git_config_not_flagged(self) -> None:
        probe = ExposedPathsProbe()
        session = _session_with_map(
            {"/.git/config": _response(200, "<html>[core] string içinde</html>")},
            default=_NOT_FOUND,
        )
        findings = probe.probe("https://example.com", session)
        assert not any(".git repository" in f.title for f in findings)


# =====================================================================
# SQL dump validator
# =====================================================================
class TestSqlDumpValidator:
    def test_real_sql_dump_flagged(self) -> None:
        probe = ExposedPathsProbe()
        sql_body = "-- MySQL dump\nCREATE TABLE users (id INT);\nINSERT INTO users VALUES (1);\n"
        session = _session_with_map(
            {"/database.sql": _response(200, sql_body, content_type="application/sql")},
            default=_NOT_FOUND,
        )
        findings = probe.probe("https://example.com", session)
        assert any("database.sql" in f.target for f in findings)

    def test_html_at_sql_path_not_flagged(self) -> None:
        """Soft-404 scenario."""
        probe = ExposedPathsProbe()
        html = "<html>CREATE TABLE mentioned in blog post</html>"
        session = _session_with_map(
            {"/database.sql": _response(200, html, content_type="text/html")},
            default=_NOT_FOUND,
        )
        findings = probe.probe("https://example.com", session)
        assert not any("database.sql" in f.target for f in findings)


# =====================================================================
# Soft-404 baseline
# =====================================================================
class TestSoftFourOhFour:
    def test_catchall_site_no_false_positives(self) -> None:
        """Server returns the same HTML for every path — there should be no findings (except sec_txt)."""
        probe = ExposedPathsProbe()
        catchall_html = "<html><body>Anasayfa</body></html>"
        catchall_response = _response(200, catchall_html, content_type="text/html")

        session = MagicMock(spec=requests.Session)
        session.get.return_value = catchall_response

        findings = probe.probe("https://example.com", session)

        # Soft-404 baseline must have been triggered — there must be no "exposed" findings
        exposed = [f for f in findings if f.severity != Severity.INFO]
        assert exposed == []

    def test_different_sized_response_not_filtered(self) -> None:
        """Responses with size very different from baseline aren't treated as soft-404."""
        probe = ExposedPathsProbe()

        small_404 = _response(404, "Not Found", content_type="text/plain")
        real_env = _response(
            200,
            "DB_PASSWORD=x\nAPI_KEY=y\n",
            content_type="text/plain",
        )

        def fake_get(url, **_kwargs):
            if "pentra-nonexistent" in url:
                return small_404
            if "/.env" in url:
                return real_env
            return small_404

        session = MagicMock(spec=requests.Session)
        session.get.side_effect = fake_get

        findings = probe.probe("https://example.com", session)
        assert any(".env file" in f.title for f in findings)


# =====================================================================
# security.txt inverse logic
# =====================================================================
class TestSecurityTxt:
    def test_missing_security_txt_info_finding(self) -> None:
        probe = ExposedPathsProbe()
        session = MagicMock(spec=requests.Session)
        session.get.return_value = _response(404, "", content_type="text/plain")

        findings = probe.probe("https://example.com", session)
        assert any("security.txt missing" in f.title for f in findings)

    def test_present_security_txt_no_info_finding(self) -> None:
        probe = ExposedPathsProbe()
        sec_response = _response(200, "Contact: a@b.com", content_type="text/plain")
        session = _session_with_map(
            {"/.well-known/security.txt": sec_response},
            default=_response(404, "", content_type="text/plain"),
        )
        findings = probe.probe("https://example.com", session)
        assert not any("security.txt missing" in f.title for f in findings)

    def test_soft_404_on_security_txt_reports_missing(self) -> None:
        """A security.txt response identical to the soft-404 baseline → file considered missing."""
        probe = ExposedPathsProbe()
        catchall = _response(200, "<html>anasayfa</html>", content_type="text/html")
        session = MagicMock(spec=requests.Session)
        session.get.return_value = catchall
        findings = probe.probe("https://example.com", session)
        assert any("security.txt missing" in f.title for f in findings)


# =====================================================================
# Admin / phpMyAdmin validator
# =====================================================================
class TestAdminValidator:
    def test_real_admin_panel_with_login_form_flagged(self) -> None:
        probe = ExposedPathsProbe()
        admin_html = (
            "<html><head><title>Admin Login</title></head><body>"
            "<form action='/admin/login' method='post'>"
            "<input name='username'><input name='password' type='password'></form></body></html>"
        )
        session = _session_with_map(
            {"/admin": _response(200, admin_html)},
            default=_response(404, "", content_type="text/plain"),
        )
        findings = probe.probe("https://example.com", session)
        assert any(f.target.endswith("/admin") for f in findings)

    def test_fake_admin_from_soft_404_not_flagged(self) -> None:
        probe = ExposedPathsProbe()
        catchall = _response(200, "<html>Anasayfa</html>")
        session = MagicMock(spec=requests.Session)
        session.get.return_value = catchall
        findings = probe.probe("https://example.com", session)
        # No finding for /admin (matches the soft-404 baseline)
        assert not any(f.target.endswith("/admin") for f in findings)


class TestPhpMyAdminValidator:
    def test_real_phpmyadmin_flagged(self) -> None:
        probe = ExposedPathsProbe()
        pma_html = "<html><title>phpMyAdmin</title><form name='pma_username'></form></html>"
        session = _session_with_map(
            {"/phpmyadmin": _response(200, pma_html)},
            default=_response(404, "", content_type="text/plain"),
        )
        findings = probe.probe("https://example.com", session)
        assert any("phpMyAdmin public" in f.title for f in findings)
