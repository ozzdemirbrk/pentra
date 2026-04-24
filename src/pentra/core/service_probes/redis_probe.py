"""Redis auth check — port 6379'da parolasız erişim kontrolü.

Redis RESP protokolüyle basit `PING` komutu gönderir. Yanıt `+PONG` ise
bağlantı auth gerektirmiyor demektir — **CRITICAL** bulgu.

Seviye 2 kuralları:
    - Tek PING, tek bağlantı
    - Veri okuma/yazma YOK (`KEYS *`, `CONFIG GET`, `GET` komutları YASAK)
    - Bağlantı hemen kopartılır
"""

from __future__ import annotations

import socket

from pentra.core.service_probes.base import ServiceProbeBase
from pentra.i18n import t
from pentra.models import Finding, Severity

# RESP protokolü: *1\r\n$4\r\nPING\r\n  (tek elemanlı array)
_PING_COMMAND: bytes = b"*1\r\n$4\r\nPING\r\n"

# Parolasız Redis'in vereceği yanıt
_EXPECTED_OPEN: bytes = b"+PONG"

# Parola gerektirdiğinde veya korumada dönen hata işaretleri
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
