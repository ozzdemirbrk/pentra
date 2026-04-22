"""postgresql_probe.py testleri — mocked psycopg2."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from pentra.core.service_probes.postgresql_probe import PostgresDefaultCredsProbe
from pentra.models import Severity


@pytest.fixture
def psycopg2_stub():
    operational_error = type("OperationalError", (Exception,), {})

    fake_psycopg2 = MagicMock()
    fake_psycopg2.OperationalError = operational_error
    fake_psycopg2.connect = MagicMock()

    with patch.dict("sys.modules", {"psycopg2": fake_psycopg2}):
        yield {
            "psycopg2": fake_psycopg2,
            "OperationalError": operational_error,
        }


def _mock_pg_conn(version: str = "PostgreSQL 15.3 on x86_64-linux") -> MagicMock:
    cursor = MagicMock()
    cursor.fetchone.return_value = (version,)
    cursor.__enter__ = MagicMock(return_value=cursor)
    cursor.__exit__ = MagicMock(return_value=False)

    conn = MagicMock()
    conn.cursor.return_value = cursor
    return conn


class TestPostgresDefaultOpen:
    def test_postgres_postgres_yields_critical(self, psycopg2_stub) -> None:
        psycopg2_stub["psycopg2"].connect.return_value = _mock_pg_conn()

        probe = PostgresDefaultCredsProbe()
        findings = probe.probe("10.0.0.5", 5432)

        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "varsayılan parola" in findings[0].title.lower()
        assert "PostgreSQL 15.3" in findings[0].evidence["postgres_version"]


class TestPostgresProtected:
    def test_auth_failed_no_finding(self, psycopg2_stub) -> None:
        op_fail = psycopg2_stub["OperationalError"]
        psycopg2_stub["psycopg2"].connect.side_effect = op_fail(
            "FATAL: password authentication failed",
        )

        probe = PostgresDefaultCredsProbe()
        findings = probe.probe("10.0.0.5", 5432)
        assert findings == []

    def test_max_2_attempts(self, psycopg2_stub) -> None:
        op_fail = psycopg2_stub["OperationalError"]
        psycopg2_stub["psycopg2"].connect.side_effect = op_fail("auth fail")

        probe = PostgresDefaultCredsProbe()
        probe.probe("10.0.0.5", 5432)
        assert psycopg2_stub["psycopg2"].connect.call_count == 2


class TestPostgresMissingDep:
    def test_psycopg2_not_installed(self) -> None:
        import sys
        probe = PostgresDefaultCredsProbe()
        with patch.dict(sys.modules, {"psycopg2": None}):
            findings = probe.probe("10.0.0.5", 5432)
        assert findings == []
