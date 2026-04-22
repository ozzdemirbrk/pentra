"""mysql_probe.py testleri — mocked pymysql."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from pentra.core.service_probes.mysql_probe import MysqlDefaultCredsProbe
from pentra.models import Severity


@pytest.fixture
def pymysql_stub():
    """pymysql modülünü sahte bir connect + OperationalError ile mock'la."""
    operational_error = type("OperationalError", (Exception,), {})
    fake_err = MagicMock()
    fake_err.OperationalError = operational_error

    fake_pymysql = MagicMock()
    fake_pymysql.err = fake_err
    fake_pymysql.connect = MagicMock()

    with patch.dict(
        "sys.modules",
        {"pymysql": fake_pymysql, "pymysql.err": fake_err},
    ):
        yield {
            "pymysql": fake_pymysql,
            "OperationalError": operational_error,
        }


def _mock_mysql_conn(version: str = "8.0.32") -> MagicMock:
    """Başarılı bir MySQL bağlantısını taklit eder."""
    cursor = MagicMock()
    cursor.fetchone.return_value = (version,)
    cursor.__enter__ = MagicMock(return_value=cursor)
    cursor.__exit__ = MagicMock(return_value=False)

    conn = MagicMock()
    conn.cursor.return_value = cursor
    return conn


class TestMysqlDefaultOpen:
    def test_root_empty_password_yields_critical(self, pymysql_stub) -> None:
        pymysql_stub["pymysql"].connect.return_value = _mock_mysql_conn("8.0.32-mysql")

        probe = MysqlDefaultCredsProbe()
        findings = probe.probe("10.0.0.5", 3306)

        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "varsayılan parola" in findings[0].title.lower()
        assert "8.0.32" in findings[0].evidence["mysql_version"]


class TestMysqlProtected:
    def test_access_denied_all_creds_no_finding(self, pymysql_stub) -> None:
        # Tüm bağlantı denemelerinde OperationalError fırlat
        op_fail = pymysql_stub["OperationalError"]
        pymysql_stub["pymysql"].connect.side_effect = op_fail("Access denied (1045)")

        probe = MysqlDefaultCredsProbe()
        findings = probe.probe("10.0.0.5", 3306)
        assert findings == []

    def test_max_2_attempts(self, pymysql_stub) -> None:
        """Probe en fazla 2 credentials denemeli."""
        op_fail = pymysql_stub["OperationalError"]
        pymysql_stub["pymysql"].connect.side_effect = op_fail("Access denied")

        probe = MysqlDefaultCredsProbe()
        probe.probe("10.0.0.5", 3306)

        # Connect 2 kez çağrıldı (root:'', root:root)
        assert pymysql_stub["pymysql"].connect.call_count == 2


class TestMysqlMissingDep:
    def test_pymysql_not_installed_returns_empty(self) -> None:
        import sys
        probe = MysqlDefaultCredsProbe()
        with patch.dict(sys.modules, {"pymysql": None}):
            findings = probe.probe("10.0.0.5", 3306)
        assert findings == []
