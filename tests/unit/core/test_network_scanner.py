"""network_scanner.py — nmap mock'lu unit testler.

Gerçek nmap çağırmadan NetworkScanner'ın:
    - Doğru nmap argümanlarını ürettiğini
    - Sonuçları Finding'e doğru çevirdiğini
    - Riskli portları uygun severity'ye atadığını doğrular.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pentra.core.network_scanner import NetworkScanner
from pentra.core.rate_limiter import TokenBucket
from pentra.models import (
    AuthorizationRequest,
    ScanDepth,
    ScopeDecision,
    ScopeDecisionType,
    Severity,
    Target,
    TargetType,
)
from pentra.safety.authorization import AuthorizationManager
from pentra.storage.audit_log import AuditLog


@pytest.fixture
def scanner_deps(tmp_path: Path):
    """NetworkScanner'ın bağımlılıklarını oluşturur."""
    audit_log = AuditLog(tmp_path / "audit.log")
    auth_mgr = AuthorizationManager(secret=b"x" * 32)
    rate_limiter = TokenBucket(capacity=1000, refill_rate_per_sec=1000.0)
    return rate_limiter, audit_log, auth_mgr


@pytest.fixture
def valid_token(scanner_deps):
    """Localhost için geçerli bir token üretir."""
    _, _, auth_mgr = scanner_deps
    target = Target(TargetType.LOCALHOST, "127.0.0.1")
    request = AuthorizationRequest(target, ScanDepth.QUICK, user_accepted_terms=True)
    scope = ScopeDecision(ScopeDecisionType.ALLOWED_PRIVATE, target, "özel")
    return auth_mgr.grant(request, scope), target


# =====================================================================
# Argüman üretimi
# =====================================================================
class TestBuildNmapArgs:
    def test_quick_args(self) -> None:
        args = NetworkScanner._build_nmap_args(ScanDepth.QUICK)
        assert "-sT" in args
        assert "-F" in args
        assert "--open" in args

    def test_standard_args(self) -> None:
        args = NetworkScanner._build_nmap_args(ScanDepth.STANDARD)
        assert "-sV" in args

    def test_deep_args(self) -> None:
        args = NetworkScanner._build_nmap_args(ScanDepth.DEEP)
        assert "-O" in args
        # Derin tarama güvenli NSE script'leri + tüm portlar kapsamalı
        assert "--script=safe" in args
        assert "-p-" in args
        assert "-sV" in args


# =====================================================================
# Nmap çıktısının Finding'e çevrilmesi (mock)
# =====================================================================
class TestDoScanWithMockedNmap:
    def _make_mock_scanner(self, hosts_data: dict) -> MagicMock:
        """Mock nmap.PortScanner — scan() çağrılınca hosts_data döner."""
        mock_ps = MagicMock()
        mock_ps.all_hosts.return_value = list(hosts_data.keys())

        def getitem(host: str):
            return hosts_data[host]

        mock_ps.__getitem__ = MagicMock(side_effect=getitem)
        return mock_ps

    def _make_host_result(self, ports: dict[int, dict]) -> MagicMock:
        """Bir host için mock sonuç — {port: {state, name, ...}}."""
        proto_dict = {p: info for p, info in ports.items()}
        host = MagicMock()
        host.all_protocols.return_value = ["tcp"]
        host.__getitem__ = MagicMock(return_value=proto_dict)
        return host

    def test_open_port_becomes_finding(self, scanner_deps, valid_token) -> None:
        rate, audit, auth = scanner_deps
        token, target = valid_token

        scanner = NetworkScanner(rate_limiter=rate, audit_log=audit, auth_manager=auth)

        # Sinyal yakalamak için bir dinleyici
        findings: list = []
        scanner.finding_discovered.connect(findings.append)

        hosts_data = {
            "127.0.0.1": self._make_host_result(
                {
                    80: {"state": "open", "name": "http", "product": "", "version": ""},
                    443: {"state": "open", "name": "https", "product": "", "version": ""},
                    22: {"state": "closed", "name": "ssh", "product": "", "version": ""},
                },
            ),
        }
        mock_scanner = self._make_mock_scanner(hosts_data)

        with patch("nmap.PortScanner", return_value=mock_scanner):
            scanner.scan(target, ScanDepth.QUICK, token)

        # Sadece açık portlar → 2 finding
        assert len(findings) == 2
        titles = {f.title for f in findings}
        assert any("80/tcp" in t for t in titles)
        assert any("443/tcp" in t for t in titles)

    def test_risky_port_gets_high_severity(self, scanner_deps, valid_token) -> None:
        rate, audit, auth = scanner_deps
        token, target = valid_token

        scanner = NetworkScanner(rate_limiter=rate, audit_log=audit, auth_manager=auth)
        findings: list = []
        scanner.finding_discovered.connect(findings.append)

        # RDP açık → HIGH severity
        hosts_data = {
            "127.0.0.1": self._make_host_result(
                {3389: {"state": "open", "name": "ms-wbt-server", "product": "", "version": ""}},
            ),
        }

        with patch("nmap.PortScanner", return_value=self._make_mock_scanner(hosts_data)):
            scanner.scan(target, ScanDepth.QUICK, token)

        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_ordinary_port_gets_info_severity(self, scanner_deps, valid_token) -> None:
        rate, audit, auth = scanner_deps
        token, target = valid_token

        scanner = NetworkScanner(rate_limiter=rate, audit_log=audit, auth_manager=auth)
        findings: list = []
        scanner.finding_discovered.connect(findings.append)

        # 8080 listede değil → INFO
        hosts_data = {
            "127.0.0.1": self._make_host_result(
                {8080: {"state": "open", "name": "http-alt", "product": "", "version": ""}},
            ),
        }

        with patch("nmap.PortScanner", return_value=self._make_mock_scanner(hosts_data)):
            scanner.scan(target, ScanDepth.QUICK, token)

        assert findings[0].severity == Severity.INFO

    def test_no_hosts_does_not_emit_findings(self, scanner_deps, valid_token) -> None:
        rate, audit, auth = scanner_deps
        token, target = valid_token

        scanner = NetworkScanner(rate_limiter=rate, audit_log=audit, auth_manager=auth)
        findings: list = []
        scanner.finding_discovered.connect(findings.append)

        mock_ps = MagicMock()
        mock_ps.all_hosts.return_value = []

        with patch("nmap.PortScanner", return_value=mock_ps):
            scanner.scan(target, ScanDepth.QUICK, token)

        assert findings == []

    def test_invalid_token_blocks_scan(self, scanner_deps) -> None:
        rate, audit, auth = scanner_deps
        scanner = NetworkScanner(rate_limiter=rate, audit_log=audit, auth_manager=auth)

        # Hiç nmap çağrılmamalı
        with patch("nmap.PortScanner") as mock_class:
            # Geçersiz token
            from pentra.models import AuthorizationToken

            fake = AuthorizationToken(token_id="x", payload="y", signature="z")
            target = Target(TargetType.LOCALHOST, "127.0.0.1")
            errors: list[str] = []
            scanner.error_occurred.connect(errors.append)

            scanner.scan(target, ScanDepth.QUICK, fake)

            mock_class.assert_not_called()
            assert len(errors) == 1
            assert "yetki" in errors[0].lower() or "token" in errors[0].lower()
