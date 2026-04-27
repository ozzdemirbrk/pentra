"""Redis auth check — tests for no-password access on port 6379.

Sends a simple `PING` over the Redis RESP protocol. If the response is
`+PONG`, the connection doesn't require auth — a **CRITICAL** finding.

Level 2 rules:
    - Single PING, single connection
    - NO data read/write (`KEYS *`, `CONFIG GET`, `GET` are forbidden)
    - Connection is closed immediately afterwards
"""

from __future__ import annotations

import socket

from pentra.core.service_probes.base import ServiceProbeBase
from pentra.i18n import t
from pentra.models import Finding, Severity

# RESP protocol: *1\r\n$4\r\nPING\r\n  (single-element array)
_PING_COMMAND: bytes = b"*1\r\n$4\r\nPING\r\n"

# Response from a Redis that requires no password
_EXPECTED_OPEN: bytes = b"+PONG"

# Error markers returned when a password is required or protected-mode is on
_AUTH_REQUIRED_MARKERS: tuple[bytes, ...] = (
    b"NOAUTH Authentication required",
    b"DENIED Redis is running in protected mode",
    b"-ERR Client sent AUTH",
)


class RedisAuthProbe(ServiceProbeBase):
    default_ports: tuple[int, ...] = (6379,)
    name: str = "redis_auth"
    description_key: str = "probe.service.redis.description"

    def probe(self, host: str, port: int) -> list[Finding]:
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                sock.sendall(_PING_COMMAND)
                response = sock.recv(256)
        except (OSError, socket.timeout):
            return []

        if response.startswith(_EXPECTED_OPEN):
            return [
                Finding(
                    scanner_name="network_scanner",
                    severity=Severity.CRITICAL,
                    title=t("finding.redis.auth_open.title", port=port),
                    description=t("finding.redis.auth_open.desc"),
                    target=f"{host}:{port}",
                    remediation=t("finding.redis.auth_open.remediation"),
                    evidence=self._evidence(
                        host=host, port=port,
                        why_vulnerable=t("finding.redis.auth_open.evidence"),
                        response_snippet=response.decode("latin-1"),
                    ),
                ),
            ]

        return []
