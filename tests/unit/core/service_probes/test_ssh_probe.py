"""ssh_probe.py testleri — mocked paramiko."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from pentra.core.service_probes.ssh_probe import SshDefaultCredsProbe
from pentra.models import Severity


@pytest.fixture
def paramiko_stub():
    auth_exc = type("AuthenticationException", (Exception,), {})
    ssh_exc = type("SSHException", (Exception,), {})
    no_conn = type("NoValidConnectionsError", (OSError,), {})

    fake_ssh_client_instance = MagicMock()
    fake_client_factory = MagicMock(return_value=fake_ssh_client_instance)
    fake_auto_policy = MagicMock()

    fake_paramiko = MagicMock()
    fake_paramiko.SSHClient = fake_client_factory
    fake_paramiko.AutoAddPolicy = fake_auto_policy

    fake_exceptions = MagicMock()
    fake_exceptions.AuthenticationException = auth_exc
    fake_exceptions.SSHException = ssh_exc
    fake_exceptions.NoValidConnectionsError = no_conn

    with patch.dict("sys.modules", {
        "paramiko": fake_paramiko,
        "paramiko.ssh_exception": fake_exceptions,
    }):
        yield {
            "paramiko": fake_paramiko,
            "client_instance": fake_ssh_client_instance,
            "AuthenticationException": auth_exc,
            "SSHException": ssh_exc,
            "NoValidConnectionsError": no_conn,
        }


class TestSshDefaultOpen:
    def test_root_root_connect_yields_high(self, paramiko_stub) -> None:
        client = paramiko_stub["client_instance"]
        client.connect.return_value = None  # başarılı
        transport = MagicMock()
        transport.remote_version = "SSH-2.0-OpenSSH_7.4"
        client.get_transport.return_value = transport

        probe = SshDefaultCredsProbe()
        findings = probe.probe("10.0.0.5", 22)

        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "varsayılan parola" in findings[0].title.lower()
        assert "root" in findings[0].evidence["username"]


class TestSshProtected:
    def test_auth_exception_all_no_finding(self, paramiko_stub) -> None:
        client = paramiko_stub["client_instance"]
        auth_exc = paramiko_stub["AuthenticationException"]
        client.connect.side_effect = auth_exc("auth fail")

        probe = SshDefaultCredsProbe()
        findings = probe.probe("10.0.0.5", 22)
        assert findings == []

    def test_max_3_attempts(self, paramiko_stub) -> None:
        """En fazla 3 credential denemeli."""
        client = paramiko_stub["client_instance"]
        auth_exc = paramiko_stub["AuthenticationException"]
        client.connect.side_effect = auth_exc("fail")

        probe = SshDefaultCredsProbe()
        probe.probe("10.0.0.5", 22)

        # Her deneme için yeni SSHClient instance oluşturulduğundan
        # SSHClient factory 3 kez çağrılmış olmalı
        assert paramiko_stub["paramiko"].SSHClient.call_count == 3

    def test_no_valid_connection_stops(self, paramiko_stub) -> None:
        """NoValidConnectionsError → SSH kapalı, hemen çık, kredi denemeyi durdur."""
        client = paramiko_stub["client_instance"]
        no_conn = paramiko_stub["NoValidConnectionsError"]
        client.connect.side_effect = no_conn("no route")

        probe = SshDefaultCredsProbe()
        findings = probe.probe("10.0.0.5", 22)

        assert findings == []
        # Sadece 1 deneme (ilk creds'te bağlantı başarısız olunca durdu)
        assert paramiko_stub["paramiko"].SSHClient.call_count == 1


class TestSshMissingDep:
    def test_paramiko_not_installed(self) -> None:
        import sys
        probe = SshDefaultCredsProbe()
        with patch.dict(sys.modules, {"paramiko": None}):
            findings = probe.probe("10.0.0.5", 22)
        assert findings == []
