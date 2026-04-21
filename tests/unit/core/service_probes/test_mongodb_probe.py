"""mongodb_probe.py testleri — mocked pymongo."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from pentra.core.service_probes.mongodb_probe import MongoDbAuthProbe
from pentra.models import Severity


@pytest.fixture
def pymongo_stub():
    """pymongo modülünü sahte bir MongoClient ile mock'la."""
    mongo_client = MagicMock()
    operation_failure = type("OperationFailure", (Exception,), {})
    connection_failure = type("ConnectionFailure", (Exception,), {})
    server_timeout = type("ServerSelectionTimeoutError", (Exception,), {})

    fake_errors = MagicMock()
    fake_errors.OperationFailure = operation_failure
    fake_errors.ConnectionFailure = connection_failure
    fake_errors.ServerSelectionTimeoutError = server_timeout

    fake_pymongo = MagicMock()
    fake_pymongo.MongoClient = mongo_client
    fake_pymongo.errors = fake_errors

    with patch.dict(
        "sys.modules",
        {"pymongo": fake_pymongo, "pymongo.errors": fake_errors},
    ):
        yield {
            "client_factory": mongo_client,
            "OperationFailure": operation_failure,
            "ConnectionFailure": connection_failure,
            "ServerSelectionTimeoutError": server_timeout,
        }


class TestMongoDbOpen:
    def test_anonymous_list_dbs_success_yields_critical(self, pymongo_stub) -> None:
        # client.list_database_names() başarılı → auth yok
        fake_client = MagicMock()
        fake_client.list_database_names.return_value = ["admin", "local", "config", "userdata"]
        pymongo_stub["client_factory"].return_value = fake_client

        probe = MongoDbAuthProbe()
        findings = probe.probe("10.0.0.5", 27017)

        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "parolasız" in findings[0].title.lower()


class TestMongoDbProtected:
    def test_auth_required_error_no_finding(self, pymongo_stub) -> None:
        fake_client = MagicMock()
        op_failure_cls = pymongo_stub["OperationFailure"]
        fake_client.list_database_names.side_effect = op_failure_cls(
            "Command listDatabases requires authentication",
        )
        pymongo_stub["client_factory"].return_value = fake_client

        probe = MongoDbAuthProbe()
        findings = probe.probe("10.0.0.5", 27017)
        assert findings == []

    def test_connection_failure_no_finding(self, pymongo_stub) -> None:
        conn_fail_cls = pymongo_stub["ConnectionFailure"]
        pymongo_stub["client_factory"].side_effect = conn_fail_cls("can't connect")

        probe = MongoDbAuthProbe()
        findings = probe.probe("10.0.0.5", 27017)
        assert findings == []

    def test_server_timeout_no_finding(self, pymongo_stub) -> None:
        timeout_cls = pymongo_stub["ServerSelectionTimeoutError"]
        fake_client = MagicMock()
        fake_client.list_database_names.side_effect = timeout_cls("timeout")
        pymongo_stub["client_factory"].return_value = fake_client

        probe = MongoDbAuthProbe()
        findings = probe.probe("10.0.0.5", 27017)
        assert findings == []


class TestMongoDbMissingDep:
    def test_pymongo_not_installed_returns_empty(self) -> None:
        """pymongo ImportError → probe sessizce boş döner."""
        import sys
        probe = MongoDbAuthProbe()
        # pymongo mock'u kaldır; import başarısız olsun
        with patch.dict(sys.modules, {"pymongo": None}):
            findings = probe.probe("10.0.0.5", 27017)
        assert findings == []
