"""SSL/TLS probe — sunucunun TLS yapılandırmasındaki zafiyetleri tespit eder."""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlparse

import requests

from pentra.core.web_probes.base import WebProbeBase
from pentra.i18n import t
from pentra.models import Finding, Severity


@dataclass(frozen=True)
class _HandshakeOutcome:
    protocol_name: str
    supported: bool
    error: str | None = None


_WEAK_PROTOCOLS: tuple[tuple[str, ssl.TLSVersion, Severity], ...] = (
    ("SSLv3", ssl.TLSVersion.SSLv3, Severity.CRITICAL),
    ("TLSv1", ssl.TLSVersion.TLSv1, Severity.HIGH),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1, Severity.MEDIUM),
)


class SslTlsProbe(WebProbeBase):
    name: str = "ssl_tls"
    description_key: str = "probe.web.ssl_tls.description"
    timeout: float = 8.0

    def probe(self, url: str, session: requests.Session) -> list[Finding]:
        del session

        parsed = urlparse(url)
        if parsed.scheme != "https":
            return []

        host = parsed.hostname
        port = parsed.port or 443
        if not host:
            return []

        findings: list[Finding] = []

        for proto_name, proto_ver, severity in _WEAK_PROTOCOLS:
            outcome = _try_handshake(host, port, proto_ver, self.timeout)
            if outcome.supported:
                findings.append(
                    Finding(
                        scanner_name="web_scanner",
                        severity=severity,
                        title=t("finding.web.old_tls.title", proto=proto_name),
                        description=t("finding.web.old_tls.desc", proto=proto_name),
                        target=f"{host}:{port}",
                        remediation=t(
                            "finding.web.old_tls.remediation", proto=proto_name,
                        ),
                        evidence=self._build_evidence(
                            request_method="TLS-HANDSHAKE",
                            request_path=f"{host}:{port}",
                            why_vulnerable=t(
                                "evidence.web.ssl_tls.handshake_success",
                                proto=proto_name,
                            ),
                        ),
                    ),
                )

        cert_finding = _check_certificate(host, port, self.timeout)
        if cert_finding is not None:
            findings.append(cert_finding)

        return findings


# ---------------------------------------------------------------------
def _try_handshake(
    host: str, port: int, tls_version: ssl.TLSVersion, timeout: float,
) -> _HandshakeOutcome:
    proto_name = tls_version.name

    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = tls_version
        context.maximum_version = tls_version
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as _ssock:
                return _HandshakeOutcome(proto_name, supported=True)

    except ssl.SSLError:
        return _HandshakeOutcome(proto_name, supported=False, error="ssl-error")
    except (ConnectionError, OSError, ValueError) as e:
        return _HandshakeOutcome(proto_name, supported=False, error=str(e))


def _check_certificate(host: str, port: int, timeout: float) -> Finding | None:
    """Varsayılan doğrulamayla bağlanmayı dener; hata varsa sertifika zafiyeti raporlar."""
    context = ssl.create_default_context()

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as _ssock:
                return None

    except ssl.SSLCertVerificationError as e:
        return Finding(
            scanner_name="web_scanner",
            severity=Severity.HIGH,
            title=t("finding.web.ssl_cert_error.title"),
            description=t("finding.web.ssl_cert_error.desc", reason=str(e.reason)),
            target=f"{host}:{port}",
            remediation=t("finding.web.ssl_cert_error.remediation"),
            evidence={
                "probe_name": "ssl_tls",
                "request": f"TLS-HANDSHAKE {host}:{port}",
                "why_vulnerable": f"SSL verify error: {e.reason}",
            },
        )
    except (ConnectionError, OSError):
        return None
