"""scan_orchestrator.py — Güvenlik zinciri doğrulama testleri.

ScanOrchestrator'un görevi: yetki + kapsam + scanner seçimini koordine etmek.
Burada Scanner'ı mock'larız — orchestrator'ın kendi mantığını izole test ederiz.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from pentra.core.scan_orchestrator import ScanOrchestrator, ScanRequest
from pentra.core.scanner_base import ScannerBase
from pentra.models import ScanDepth, Target, TargetType
from pentra.safety.authorization import AuthorizationDenied, AuthorizationManager
from pentra.safety.scope_validator import ScopeValidator
from pentra.storage.audit_log import AuditLog


@pytest.fixture
def audit_log(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.log")


@pytest.fixture
def auth_manager() -> AuthorizationManager:
    return AuthorizationManager(secret=b"test-secret-32-bytes-min-length!!")


@pytest.fixture
def scope_validator() -> ScopeValidator:
    def _no_dns(hostname: str) -> list[str]:
        raise AssertionError("DNS çağrılmamalıydı")

    return ScopeValidator(dns_resolver=_no_dns)


@pytest.fixture
def scanner_factory():
    """Mock scanner üretir — gerçek tarama yapmaz."""
    factory = MagicMock()
    scanner_instance = MagicMock(spec=ScannerBase)
    factory.return_value = scanner_instance
    return factory


@pytest.fixture
def orchestrator(
    scope_validator: ScopeValidator,
    auth_manager: AuthorizationManager,
    audit_log: AuditLog,
    scanner_factory: MagicMock,
) -> ScanOrchestrator:
    return ScanOrchestrator(
        scope_validator=scope_validator,
        auth_manager=auth_manager,
        audit_log=audit_log,
        scanner_factory=scanner_factory,
    )


# =====================================================================
# Başarı yolları
# =====================================================================
class TestPrepareSuccess:
    def test_localhost_prepare_returns_prepared_scan(
        self, orchestrator: ScanOrchestrator,
    ) -> None:
        target = Target(TargetType.LOCALHOST, "127.0.0.1")
        request = ScanRequest(target, ScanDepth.QUICK, user_accepted_terms=True)

        prepared = orchestrator.prepare(request)

        assert prepared.target == target
        assert prepared.depth == ScanDepth.QUICK
        assert prepared.scope_decision.is_allowed
        assert prepared.token.token_id

    def test_audit_log_contains_expected_events(
        self, orchestrator: ScanOrchestrator, audit_log: AuditLog,
    ) -> None:
        target = Target(TargetType.LOCALHOST, "127.0.0.1")
        request = ScanRequest(target, ScanDepth.QUICK, user_accepted_terms=True)
        orchestrator.prepare(request)

        events = audit_log.read_all()
        event_types = [e.event_type for e in events]
        assert "scan_requested" in event_types
        assert "scope_evaluated" in event_types
        assert "auth_granted" in event_types

    def test_scanner_factory_called_with_target_type(
        self, orchestrator: ScanOrchestrator, scanner_factory: MagicMock,
    ) -> None:
        target = Target(TargetType.LOCALHOST, "127.0.0.1")
        request = ScanRequest(target, ScanDepth.QUICK, user_accepted_terms=True)
        orchestrator.prepare(request)

        scanner_factory.assert_called_once_with(TargetType.LOCALHOST)


# =====================================================================
# Reddedilen yollar
# =====================================================================
class TestPrepareDenied:
    def test_unchecked_terms_raises(self, orchestrator: ScanOrchestrator) -> None:
        target = Target(TargetType.LOCALHOST, "127.0.0.1")
        request = ScanRequest(target, ScanDepth.QUICK, user_accepted_terms=False)

        with pytest.raises(AuthorizationDenied):
            orchestrator.prepare(request)

    def test_denied_scope_raises(self, orchestrator: ScanOrchestrator) -> None:
        # Multicast → DENIED
        target = Target(TargetType.IP_SINGLE, "224.0.0.1")
        request = ScanRequest(target, ScanDepth.QUICK, user_accepted_terms=True)

        with pytest.raises(AuthorizationDenied, match="Kapsam"):
            orchestrator.prepare(request)

    def test_scope_denied_logs_reason(
        self, orchestrator: ScanOrchestrator, audit_log: AuditLog,
    ) -> None:
        target = Target(TargetType.IP_SINGLE, "224.0.0.1")
        request = ScanRequest(target, ScanDepth.QUICK, user_accepted_terms=True)
        with pytest.raises(AuthorizationDenied):
            orchestrator.prepare(request)

        events = audit_log.read_all()
        types = [e.event_type for e in events]
        assert "scope_evaluated" in types
        assert "scope_denied" in types
        # auth_granted hiç çıkmamalı
        assert "auth_granted" not in types

    def test_public_without_external_confirmation_raises(
        self, orchestrator: ScanOrchestrator,
    ) -> None:
        target = Target(TargetType.IP_SINGLE, "8.8.8.8")
        request = ScanRequest(
            target,
            ScanDepth.QUICK,
            user_accepted_terms=True,
            external_target_confirmed=False,
        )
        with pytest.raises(AuthorizationDenied):
            orchestrator.prepare(request)

    def test_public_with_external_confirmation_succeeds(
        self, orchestrator: ScanOrchestrator,
    ) -> None:
        target = Target(TargetType.IP_SINGLE, "8.8.8.8")
        request = ScanRequest(
            target,
            ScanDepth.QUICK,
            user_accepted_terms=True,
            external_target_confirmed=True,
        )
        prepared = orchestrator.prepare(request)
        assert prepared.scope_decision.needs_confirmation


# =====================================================================
# Cleanup (token revoke)
# =====================================================================
class TestCleanup:
    def test_cleanup_revokes_token(
        self,
        orchestrator: ScanOrchestrator,
        auth_manager: AuthorizationManager,
    ) -> None:
        target = Target(TargetType.LOCALHOST, "127.0.0.1")
        request = ScanRequest(target, ScanDepth.QUICK, user_accepted_terms=True)
        prepared = orchestrator.prepare(request)

        assert auth_manager.verify(prepared.token, prepared.target)
        orchestrator.cleanup(prepared)
        assert not auth_manager.verify(prepared.token, prepared.target)

    def test_cleanup_logs_revocation(
        self, orchestrator: ScanOrchestrator, audit_log: AuditLog,
    ) -> None:
        target = Target(TargetType.LOCALHOST, "127.0.0.1")
        request = ScanRequest(target, ScanDepth.QUICK, user_accepted_terms=True)
        prepared = orchestrator.prepare(request)
        orchestrator.cleanup(prepared)

        types = [e.event_type for e in audit_log.read_all()]
        assert "token_revoked" in types
