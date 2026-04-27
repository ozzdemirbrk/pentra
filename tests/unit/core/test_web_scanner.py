"""web_scanner.py — WebScanner skeleton tests."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pentra.core.rate_limiter import TokenBucket
from pentra.core.web_scanner import WebScanner, _select_probes
from pentra.models import (
    AuthorizationRequest,
    Finding,
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
def deps(tmp_path: Path):
    audit = AuditLog(tmp_path / "audit.log")
    auth = AuthorizationManager(secret=b"x" * 32)
    rate = TokenBucket(capacity=1000, refill_rate_per_sec=1000.0)
    return rate, audit, auth


@pytest.fixture
def valid_token_and_target(deps):
    rate, audit, auth = deps
    target = Target(TargetType.URL, "https://example.com", description="Test")
    req = AuthorizationRequest(
        target, ScanDepth.QUICK, user_accepted_terms=True, external_target_confirmed=True,
    )
    scope = ScopeDecision(ScopeDecisionType.REQUIRES_CONFIRMATION, target, "external")
    token = auth.grant(req, scope)
    return token, target


class TestProbeSelection:
    def test_all_depths_return_probes(self) -> None:
        for depth in ScanDepth:
            probes = _select_probes(depth)
            assert len(probes) >= 1
            # In future every probe is expected to be a WebProbeBase subclass
            for p in probes:
                assert hasattr(p, "probe")
                assert hasattr(p, "name")


class TestWebScannerOrchestration:
    def test_runs_registered_probes_and_emits_findings(
        self, deps, valid_token_and_target,
    ) -> None:
        rate, audit, auth = deps
        token, target = valid_token_and_target

        scanner = WebScanner(rate_limiter=rate, audit_log=audit, auth_manager=auth)

        fake_findings = [
            Finding(
                scanner_name="web_scanner", severity=Severity.HIGH,
                title="fake1", description="d", target="https://example.com",
            ),
            Finding(
                scanner_name="web_scanner", severity=Severity.LOW,
                title="fake2", description="d", target="https://example.com",
            ),
        ]

        # Build a single mock probe — use it instead of all registered probes
        fake_probe = MagicMock()
        fake_probe.name = "fake_probe"
        fake_probe.description = "fake"
        fake_probe.probe.return_value = fake_findings

        collected: list[Finding] = []
        scanner.finding_discovered.connect(collected.append)

        with patch(
            "pentra.core.web_scanner._select_probes",
            return_value=[fake_probe],
        ):
            scanner.scan(target, ScanDepth.QUICK, token)

        assert collected == fake_findings

    def test_probe_exception_does_not_stop_scanner(
        self, deps, valid_token_and_target,
    ) -> None:
        rate, audit, auth = deps
        token, target = valid_token_and_target

        scanner = WebScanner(rate_limiter=rate, audit_log=audit, auth_manager=auth)

        errors: list[str] = []
        scanner.error_occurred.connect(errors.append)
        completed: list[None] = []
        scanner.scan_completed.connect(lambda: completed.append(None))

        fake_probe = MagicMock()
        fake_probe.name = "fake_probe"
        fake_probe.description = "fake"
        fake_probe.probe.side_effect = RuntimeError("unexpected")

        with patch(
            "pentra.core.web_scanner._select_probes",
            return_value=[fake_probe],
        ):
            scanner.scan(target, ScanDepth.QUICK, token)

        # Even when the scanner catches the error, it must still emit "completed"
        assert len(errors) >= 1
        assert len(completed) == 1

    def test_invalid_token_blocks_all_probes(self, deps) -> None:
        rate, audit, auth = deps
        scanner = WebScanner(rate_limiter=rate, audit_log=audit, auth_manager=auth)

        from pentra.models import AuthorizationToken
        fake_token = AuthorizationToken(token_id="x", payload="y", signature="z")
        target = Target(TargetType.URL, "https://example.com")

        errors: list[str] = []
        scanner.error_occurred.connect(errors.append)

        fake_probe = MagicMock()
        fake_probe.name = "fake_probe"
        fake_probe.description = "fake"

        with patch(
            "pentra.core.web_scanner._select_probes",
            return_value=[fake_probe],
        ):
            scanner.scan(target, ScanDepth.QUICK, fake_token)

            # Token is invalid → no probe should run
            fake_probe.probe.assert_not_called()

        assert len(errors) == 1
