"""redis_probe.py testleri — mocked socket."""

from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch

from pentra.core.service_probes.redis_probe import RedisAuthProbe
from pentra.models import Severity


def _mock_socket(response: bytes) -> MagicMock:
    """Context manager gibi davranan socket mock'u."""
    sock = MagicMock()
    sock.__enter__ = MagicMock(return_value=sock)
    sock.__exit__ = MagicMock(return_value=False)
    sock.recv.return_value = response
    return sock


class TestRedisOpen:
    def test_pong_response_yields_critical(self) -> None:
        probe = RedisAuthProbe()
        sock = _mock_socket(b"+PONG\r\n")

        with patch("socket.create_connection", return_value=sock):
            findings = probe.probe("127.0.0.1", 6379)

        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "parolasız" in findings[0].title.lower()
        assert findings[0].target == "127.0.0.1:6379"


class TestRedisProtected:
    def test_noauth_response_no_finding(self) -> None:
        probe = RedisAuthProbe()
        sock = _mock_socket(b"-NOAUTH Authentication required.\r\n")

        with patch("socket.create_connection", return_value=sock):
            findings = probe.probe("127.0.0.1", 6379)

        assert findings == []

    def test_protected_mode_response_no_finding(self) -> None:
        probe = RedisAuthProbe()
        sock = _mock_socket(
            b"-DENIED Redis is running in protected mode because protected mode\r\n",
        )

        with patch("socket.create_connection", return_value=sock):
            findings = probe.probe("127.0.0.1", 6379)

        assert findings == []


class TestRedisUnreachable:
    def test_connection_refused_no_finding(self) -> None:
        probe = RedisAuthProbe()
        with patch("socket.create_connection", side_effect=ConnectionRefusedError()):
            findings = probe.probe("127.0.0.1", 6379)
        assert findings == []

    def test_timeout_no_finding(self) -> None:
        probe = RedisAuthProbe()
        with patch("socket.create_connection", side_effect=socket.timeout("timeout")):
            findings = probe.probe("127.0.0.1", 6379)
        assert findings == []
