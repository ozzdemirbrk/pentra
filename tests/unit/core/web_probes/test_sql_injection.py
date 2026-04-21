"""sql_injection.py — error-based probe testleri."""

from __future__ import annotations

from unittest.mock import MagicMock

import requests

from pentra.core.web_probes.sql_injection import SqlInjectionProbe
from pentra.models import Severity


def _resp(status: int, text: str = "") -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.text = text
    return r


class TestErrorDetection:
    def test_mysql_syntax_error_detected(self) -> None:
        probe = SqlInjectionProbe()
        session = MagicMock(spec=requests.Session)
        session.get.return_value = _resp(
            200,
            "<p>Error: You have an error in your SQL syntax; check the manual "
            "that corresponds to your MariaDB version</p>",
        )
        findings = probe.probe("https://example.com/page", session)

        assert any("SQL Injection" in f.title for f in findings)
        first = next(f for f in findings if "SQL Injection" in f.title)
        assert first.severity == Severity.CRITICAL
        assert first.evidence["dbms"] == "MySQL"

    def test_postgresql_error_detected(self) -> None:
        probe = SqlInjectionProbe()
        session = MagicMock(spec=requests.Session)
        session.get.return_value = _resp(
            500, "PostgreSQL ERROR: syntax error at or near \"'\"",
        )
        findings = probe.probe("https://example.com/page", session)

        assert any("PostgreSQL" in f.title for f in findings)

    def test_mssql_error_detected(self) -> None:
        probe = SqlInjectionProbe()
        session = MagicMock(spec=requests.Session)
        session.get.return_value = _resp(
            500,
            "Microsoft OLE DB Provider for SQL Server: Unclosed quotation mark "
            "after the character string",
        )
        findings = probe.probe("https://example.com/page", session)

        assert any("MSSQL" in f.title for f in findings)

    def test_oracle_error_detected(self) -> None:
        probe = SqlInjectionProbe()
        session = MagicMock(spec=requests.Session)
        session.get.return_value = _resp(
            500, "ORA-00933: SQL command not properly ended",
        )
        findings = probe.probe("https://example.com/page", session)

        assert any("Oracle" in f.title for f in findings)

    def test_generic_sqlstate_detected(self) -> None:
        probe = SqlInjectionProbe()
        session = MagicMock(spec=requests.Session)
        session.get.return_value = _resp(500, "SQLSTATE[42000]: Syntax error")
        findings = probe.probe("https://example.com/page", session)

        assert any("SQL Injection" in f.title for f in findings)


class TestNoFalsePositive:
    def test_normal_response_no_finding(self) -> None:
        probe = SqlInjectionProbe()
        session = MagicMock(spec=requests.Session)
        session.get.return_value = _resp(200, "<html><body>Normal sayfa</body></html>")

        findings = probe.probe("https://example.com/page", session)
        assert findings == []

    def test_404_no_finding(self) -> None:
        probe = SqlInjectionProbe()
        session = MagicMock(spec=requests.Session)
        session.get.return_value = _resp(404, "Not found")

        findings = probe.probe("https://example.com/page", session)
        assert findings == []


class TestParamDedup:
    def test_one_finding_per_param(self) -> None:
        probe = SqlInjectionProbe()
        session = MagicMock(spec=requests.Session)
        session.get.return_value = _resp(500, "You have an error in your SQL syntax")

        findings = probe.probe("https://example.com/page", session)

        # Her parametre en fazla 1 finding
        titles = [f.title for f in findings]
        assert len(titles) == len(set(titles))


class TestEvidence:
    def test_evidence_contains_payload_and_dbms(self) -> None:
        probe = SqlInjectionProbe()
        session = MagicMock(spec=requests.Session)
        session.get.return_value = _resp(
            500, "You have an error in your SQL syntax near ''",
        )

        findings = probe.probe("https://example.com/page", session)
        first = findings[0]

        assert "payload" in first.evidence
        assert "dbms" in first.evidence
        assert "param" in first.evidence
