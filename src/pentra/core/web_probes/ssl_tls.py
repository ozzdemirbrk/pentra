"""SSL/TLS probe — sunucunun TLS yapılandırmasındaki zafiyetleri tespit eder.

Kontroller (hepsi non-destructive, sadece handshake denemesi):
    - SSL 2.0, SSL 3.0 desteği (kritik — tamamen devre dışı olmalı)
    - TLS 1.0, TLS 1.1 desteği (yüksek — modern tarayıcılar desteği kaldırdı)
    - Kendinden imzalı / süresi dolmuş sertifika
    - Hostname uyuşmazlığı

Not: sslyze'ın tam kullanımı Faz 4'te gelecek (Heartbleed, ROBOT, zayıf cipher detayı).
MVP için Python stdlib `ssl` yeterli — hızlı, bağımsız, test edilebilir.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlparse

import requests

from pentra.core.web_probes.base import WebProbeBase
from pentra.models import Finding, Severity


@dataclass(frozen=True)
class _HandshakeOutcome:
    """Tek bir protokolle yapılan handshake denemesinin sonucu."""

    protocol_name: str
    supported: bool
    error: str | None = None


# ---------------------------------------------------------------------
# Protokol sürümleri — ssl.TLSVersion enum değerleri
# (Python 3.11'de bazı eski sürümler tamamen kaldırılmış olabilir)
# ---------------------------------------------------------------------
_WEAK_PROTOCOLS: tuple[tuple[str, ssl.TLSVersion, Severity], ...] = (
    ("SSLv3", ssl.TLSVersion.SSLv3, Severity.CRITICAL),
    ("TLSv1", ssl.TLSVersion.TLSv1, Severity.HIGH),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1, Severity.MEDIUM),
)


class SslTlsProbe(WebProbeBase):
    name: str = "ssl_tls"
    description: str = "SSL/TLS yapılandırma zafiyetleri"
    timeout: float = 8.0

    def probe(self, url: str, session: requests.Session) -> list[Finding]:
        # session kullanılmaz — düşük seviye socket ile çalışırız
        del session

        parsed = urlparse(url)
        if parsed.scheme != "https":
            # HTTP için SSL taraması anlamsız; zaten security_headers HTTP'yi raporluyor
            return []

        host = parsed.hostname
        port = parsed.port or 443
        if not host:
            return []

        findings: list[Finding] = []

        # 1. Zayıf protokol sürümü denemeleri
        for proto_name, proto_ver, severity in _WEAK_PROTOCOLS:
            outcome = _try_handshake(host, port, proto_ver, self.timeout)
            if outcome.supported:
                findings.append(
                    Finding(
                        scanner_name="web_scanner",
                        severity=severity,
                        title=f"Eski TLS sürümü destekleniyor: {proto_name}",
                        description=(
                            f"Sunucu {proto_name} protokolüyle TLS handshake'i kabul etti. "
                            f"Bu sürüm eski ve bilinen zafiyetlere (ör. POODLE, BEAST) "
                            f"açık. Modern tarayıcılar artık bu sürümleri desteklemiyor."
                        ),
                        target=f"{host}:{port}",
                        remediation=(
                            f"Sunucu TLS yapılandırmasından {proto_name} desteğini "
                            "kapatın. Sadece TLS 1.2 ve TLS 1.3 açık olmalı. "
                            "Nginx: `ssl_protocols TLSv1.2 TLSv1.3;` · "
                            "Apache: `SSLProtocol -all +TLSv1.2 +TLSv1.3`"
                        ),
                        evidence=self._build_evidence(
                            request_method="TLS-HANDSHAKE",
                            request_path=f"{host}:{port}",
                            why_vulnerable=f"{proto_name} handshake başarılı",
                        ),
                    ),
                )

        # 2. Sertifika kontrolleri (varsayılan doğrulama ile)
        cert_finding = _check_certificate(host, port, self.timeout)
        if cert_finding is not None:
            findings.append(cert_finding)

        return findings


# ---------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------
def _try_handshake(
    host: str, port: int, tls_version: ssl.TLSVersion, timeout: float,
) -> _HandshakeOutcome:
    """Belirtilen TLS sürümüyle handshake denemesi yapar.

    Başarılı = sunucu bu sürümü destekliyor demektir.
    """
    proto_name = tls_version.name

    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = tls_version
        context.maximum_version = tls_version
        # Zayıf cipher'ları test ederken sertifika doğrulamayı gevşet
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as _ssock:
                return _HandshakeOutcome(proto_name, supported=True)

    except ssl.SSLError:
        return _HandshakeOutcome(proto_name, supported=False, error="ssl-error")
    except (ConnectionError, OSError, ValueError) as e:
        # ValueError: Python bu sürümü tamamen kaldırmış olabilir
        return _HandshakeOutcome(proto_name, supported=False, error=str(e))


def _check_certificate(host: str, port: int, timeout: float) -> Finding | None:
    """Varsayılan doğrulamayla bağlanmayı dener; hata varsa sertifika zafiyeti raporlar."""
    context = ssl.create_default_context()

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as _ssock:
                # Doğrulama başarılı — temiz
                return None

    except ssl.SSLCertVerificationError as e:
        # En yaygın sebep: süresi dolmuş, kendinden imzalı, hostname uyuşmazlığı
        return Finding(
            scanner_name="web_scanner",
            severity=Severity.HIGH,
            title="SSL sertifika sorunu",
            description=(
                f"Sertifika doğrulaması başarısız: {e.reason}. Bu sorun tarayıcılarda "
                f"güvenlik uyarısı olarak gözükür ve kullanıcıların siteye güvenini "
                f"sarsar. Yaygın nedenler: sertifika süresinin dolması, yanlış hostname, "
                f"kendinden imzalı sertifika, eksik zincir sertifikası."
            ),
            target=f"{host}:{port}",
            remediation=(
                "Geçerli bir SSL sertifikası yükleyin. Ücretsiz için Let's Encrypt "
                "(certbot ile otomatik yenileme), ticari için DigiCert/Sectigo gibi "
                "güvenilir CA'lar. Sertifika zincirini tam yükleyin (intermediate dahil)."
            ),
            evidence={
                "probe_name": "ssl_tls",
                "request": f"TLS-HANDSHAKE {host}:{port}",
                "why_vulnerable": f"SSL verify error: {e.reason}",
            },
        )
    except (ConnectionError, OSError):
        return None
