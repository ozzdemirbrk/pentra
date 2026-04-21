"""ssl_tls.py probe testleri — gerçek soket çağrıları mock'lanır."""

from __future__ import annotations

import ssl
from unittest.mock import MagicMock, patch

from pentra.core.web_probes.ssl_tls import SslTlsProbe, _HandshakeOutcome
from pentra.models import Severity


class TestHttpSkipped:
    def test_http_url_returns_empty(self) -> None:
        probe = SslTlsProbe()
        session = MagicMock()
        # SSL probe HTTP için çalışmaz
        assert probe.probe("http://example.com", session) == []


class TestWeakProtocolDetection:
    def test_tls10_supported_yields_high_finding(self) -> None:
        probe = SslTlsProbe()

        # _try_handshake'i mock'la: TLSv1 destekleniyor, diğerleri değil
        def fake_handshake(host, port, tls_version, timeout):
            if tls_version == ssl.TLSVersion.TLSv1:
                return _HandshakeOutcome("TLSv1", supported=True)
            return _HandshakeOutcome(tls_version.name, supported=False)

        with (
            patch("pentra.core.web_probes.ssl_tls._try_handshake", side_effect=fake_handshake),
            patch("pentra.core.web_probes.ssl_tls._check_certificate", return_value=None),
        ):
            findings = probe.probe("https://example.com", MagicMock())

        tls10 = [f for f in findings if "TLSv1" in f.title and "TLSv1.1" not in f.title]
        assert len(tls10) == 1
        assert tls10[0].severity == Severity.HIGH

    def test_sslv3_supported_yields_critical_finding(self) -> None:
        probe = SslTlsProbe()

        def fake_handshake(host, port, tls_version, timeout):
            if tls_version == ssl.TLSVersion.SSLv3:
                return _HandshakeOutcome("SSLv3", supported=True)
            return _HandshakeOutcome(tls_version.name, supported=False)

        with (
            patch("pentra.core.web_probes.ssl_tls._try_handshake", side_effect=fake_handshake),
            patch("pentra.core.web_probes.ssl_tls._check_certificate", return_value=None),
        ):
            findings = probe.probe("https://example.com", MagicMock())

        sslv3 = [f for f in findings if "SSLv3" in f.title]
        assert len(sslv3) == 1
        assert sslv3[0].severity == Severity.CRITICAL

    def test_only_modern_protocols_no_weak_finding(self) -> None:
        probe = SslTlsProbe()

        def fake_handshake(host, port, tls_version, timeout):
            # Hiçbir zayıf protokol desteklenmiyor
            return _HandshakeOutcome(tls_version.name, supported=False)

        with (
            patch("pentra.core.web_probes.ssl_tls._try_handshake", side_effect=fake_handshake),
            patch("pentra.core.web_probes.ssl_tls._check_certificate", return_value=None),
        ):
            findings = probe.probe("https://example.com", MagicMock())

        weak_findings = [f for f in findings if "destekleniyor" in f.title]
        assert weak_findings == []


class TestCertificateCheck:
    def test_cert_error_generates_finding(self) -> None:
        from pentra.models import Finding

        probe = SslTlsProbe()
        cert_finding = Finding(
            scanner_name="web_scanner",
            severity=Severity.HIGH,
            title="SSL sertifika sorunu",
            description="mock",
            target="example.com:443",
        )

        def fake_handshake(host, port, tls_version, timeout):
            return _HandshakeOutcome(tls_version.name, supported=False)

        with (
            patch("pentra.core.web_probes.ssl_tls._try_handshake", side_effect=fake_handshake),
            patch("pentra.core.web_probes.ssl_tls._check_certificate", return_value=cert_finding),
        ):
            findings = probe.probe("https://example.com", MagicMock())

        assert len(findings) == 1
        assert findings[0].title == "SSL sertifika sorunu"
