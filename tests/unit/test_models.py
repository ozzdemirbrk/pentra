"""models.py — enum + dataclass sanity tests."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

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


class TestTargetType:
    def test_values_are_lowercase_strings(self) -> None:
        for member in TargetType:
            assert member.value == member.value.lower()

    def test_includes_all_wizard_options(self) -> None:
        expected = {"localhost", "local_network", "ip_single", "ip_range", "url", "wifi"}
        assert {m.value for m in TargetType} == expected


class TestScanDepth:
    def test_has_three_levels(self) -> None:
        assert len(list(ScanDepth)) == 3
        assert {m.value for m in ScanDepth} == {"quick", "standard", "deep"}


class TestTarget:
    def test_target_is_immutable(self) -> None:
        target = Target(target_type=TargetType.LOCALHOST, value="127.0.0.1")
        with pytest.raises(AttributeError):
            target.value = "10.0.0.1"  # type: ignore[misc]

    def test_target_equality(self) -> None:
        t1 = Target(TargetType.IP_SINGLE, "192.168.1.1")
        t2 = Target(TargetType.IP_SINGLE, "192.168.1.1")
        t3 = Target(TargetType.IP_SINGLE, "192.168.1.2")
        assert t1 == t2
        assert t1 != t3


class TestScopeDecision:
    def test_is_allowed_true_only_for_private(self) -> None:
        target = Target(TargetType.LOCALHOST, "127.0.0.1")
        allowed = ScopeDecision(ScopeDecisionType.ALLOWED_PRIVATE, target, "private network")
        needs = ScopeDecision(ScopeDecisionType.REQUIRES_CONFIRMATION, target, "external")
        denied = ScopeDecision(ScopeDecisionType.DENIED, target, "multicast")

        assert allowed.is_allowed
        assert not needs.is_allowed
        assert not denied.is_allowed

    def test_needs_confirmation_flag(self) -> None:
        target = Target(TargetType.URL, "https://example.com")
        needs = ScopeDecision(ScopeDecisionType.REQUIRES_CONFIRMATION, target, "external target")
        assert needs.needs_confirmation
        assert not needs.is_denied
        assert not needs.is_allowed

    def test_is_denied(self) -> None:
        target = Target(TargetType.IP_SINGLE, "224.0.0.1")
        denied = ScopeDecision(ScopeDecisionType.DENIED, target, "multicast")
        assert denied.is_denied


class TestAuthorizationRequest:
    def test_defaults(self) -> None:
        target = Target(TargetType.LOCALHOST, "127.0.0.1")
        req = AuthorizationRequest(target=target, depth=ScanDepth.QUICK, user_accepted_terms=True)
        assert req.external_target_confirmed is False


class TestFinding:
    def test_default_timestamp_is_timezone_aware(self) -> None:
        f = Finding(
            scanner_name="test",
            severity=Severity.LOW,
            title="t",
            description="d",
            target="127.0.0.1",
        )
        assert f.discovered_at.tzinfo is not None

    def test_explicit_timestamp_preserved(self) -> None:
        ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
        f = Finding(
            scanner_name="test",
            severity=Severity.HIGH,
            title="t",
            description="d",
            target="127.0.0.1",
            discovered_at=ts,
        )
        assert f.discovered_at == ts
