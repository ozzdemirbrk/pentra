"""authorization.py — AuthorizationManager testleri."""

from __future__ import annotations

import base64
import json

import pytest

from pentra.models import (
    AuthorizationRequest,
    AuthorizationToken,
    ScanDepth,
    ScopeDecision,
    ScopeDecisionType,
    Target,
    TargetType,
)
from pentra.safety.authorization import (
    AuthorizationDenied,
    AuthorizationManager,
    hash_target,
)


# ---------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------
_SECRET = b"test-secret-32-bytes-for-unit-tests!!"


def _localhost_target() -> Target:
    return Target(TargetType.LOCALHOST, "127.0.0.1")


def _allowed_scope(target: Target) -> ScopeDecision:
    return ScopeDecision(ScopeDecisionType.ALLOWED_PRIVATE, target, "özel ağ")


def _needs_confirm_scope(target: Target) -> ScopeDecision:
    return ScopeDecision(ScopeDecisionType.REQUIRES_CONFIRMATION, target, "dış hedef")


def _denied_scope(target: Target) -> ScopeDecision:
    return ScopeDecision(ScopeDecisionType.DENIED, target, "multicast")


# ---------------------------------------------------------------------
# Kurucu
# ---------------------------------------------------------------------
class TestInit:
    def test_default_generates_random_secret(self) -> None:
        m1 = AuthorizationManager()
        m2 = AuthorizationManager()
        # Farklı örnekler farklı secret üretir — verilen aynı payload farklı imzalanır
        target = _localhost_target()
        req = AuthorizationRequest(target, ScanDepth.QUICK, user_accepted_terms=True)
        t1 = m1.grant(req, _allowed_scope(target))
        # m2 m1'in token'ını doğrulayamamalı
        assert m2.verify(t1, target) is False

    def test_short_secret_raises(self) -> None:
        with pytest.raises(ValueError, match="16 bayt"):
            AuthorizationManager(secret=b"short")

    def test_non_positive_ttl_raises(self) -> None:
        with pytest.raises(ValueError, match="ttl_sec pozitif"):
            AuthorizationManager(secret=_SECRET, ttl_sec=0)


# ---------------------------------------------------------------------
# grant() — başarı senaryoları
# ---------------------------------------------------------------------
class TestGrantSuccess:
    def test_private_target_with_accepted_terms(self) -> None:
        mgr = AuthorizationManager(secret=_SECRET)
        target = _localhost_target()
        req = AuthorizationRequest(target, ScanDepth.STANDARD, user_accepted_terms=True)
        token = mgr.grant(req, _allowed_scope(target))
        assert isinstance(token, AuthorizationToken)
        assert token.token_id
        assert token.signature
        assert token.payload
        assert mgr.verify(token, target)

    def test_external_target_with_extra_confirmation(self) -> None:
        mgr = AuthorizationManager(secret=_SECRET)
        target = Target(TargetType.IP_SINGLE, "8.8.8.8")
        req = AuthorizationRequest(
            target,
            ScanDepth.QUICK,
            user_accepted_terms=True,
            external_target_confirmed=True,
        )
        token = mgr.grant(req, _needs_confirm_scope(target))
        assert mgr.verify(token, target)

    def test_each_grant_has_unique_token_id(self) -> None:
        mgr = AuthorizationManager(secret=_SECRET)
        target = _localhost_target()
        req = AuthorizationRequest(target, ScanDepth.QUICK, user_accepted_terms=True)
        t1 = mgr.grant(req, _allowed_scope(target))
        t2 = mgr.grant(req, _allowed_scope(target))
        assert t1.token_id != t2.token_id


# ---------------------------------------------------------------------
# grant() — reddedilen senaryolar
# ---------------------------------------------------------------------
class TestGrantDenied:
    def test_unchecked_terms_raises(self) -> None:
        mgr = AuthorizationManager(secret=_SECRET)
        target = _localhost_target()
        req = AuthorizationRequest(target, ScanDepth.QUICK, user_accepted_terms=False)
        with pytest.raises(AuthorizationDenied, match="onay"):
            mgr.grant(req, _allowed_scope(target))

    def test_denied_scope_raises(self) -> None:
        mgr = AuthorizationManager(secret=_SECRET)
        target = Target(TargetType.IP_SINGLE, "224.0.0.1")
        req = AuthorizationRequest(target, ScanDepth.QUICK, user_accepted_terms=True)
        with pytest.raises(AuthorizationDenied, match="uygun değil"):
            mgr.grant(req, _denied_scope(target))

    def test_external_without_extra_confirmation_raises(self) -> None:
        mgr = AuthorizationManager(secret=_SECRET)
        target = Target(TargetType.IP_SINGLE, "8.8.8.8")
        req = AuthorizationRequest(
            target,
            ScanDepth.QUICK,
            user_accepted_terms=True,
            external_target_confirmed=False,
        )
        with pytest.raises(AuthorizationDenied, match="ek"):
            mgr.grant(req, _needs_confirm_scope(target))

    def test_mismatched_scope_target_raises(self) -> None:
        mgr = AuthorizationManager(secret=_SECRET)
        req_target = _localhost_target()
        other_target = Target(TargetType.IP_SINGLE, "192.168.1.1")
        req = AuthorizationRequest(req_target, ScanDepth.QUICK, user_accepted_terms=True)
        with pytest.raises(AuthorizationDenied, match="farklı"):
            mgr.grant(req, _allowed_scope(other_target))


# ---------------------------------------------------------------------
# verify() — çeşitli saldırı/hata senaryoları
# ---------------------------------------------------------------------
class TestVerify:
    def _make_valid_token(self, mgr: AuthorizationManager) -> tuple[AuthorizationToken, Target]:
        target = _localhost_target()
        req = AuthorizationRequest(target, ScanDepth.QUICK, user_accepted_terms=True)
        token = mgr.grant(req, _allowed_scope(target))
        return token, target

    def test_valid_token_succeeds(self) -> None:
        mgr = AuthorizationManager(secret=_SECRET)
        token, target = self._make_valid_token(mgr)
        assert mgr.verify(token, target)

    def test_tampered_signature_fails(self) -> None:
        mgr = AuthorizationManager(secret=_SECRET)
        token, target = self._make_valid_token(mgr)
        # İmzanın son karakterini değiştir
        flipped_char = "a" if token.signature[-1] != "a" else "b"
        tampered = AuthorizationToken(
            token_id=token.token_id,
            payload=token.payload,
            signature=token.signature[:-1] + flipped_char,
        )
        assert mgr.verify(tampered, target) is False

    def test_tampered_payload_fails(self) -> None:
        mgr = AuthorizationManager(secret=_SECRET)
        token, target = self._make_valid_token(mgr)
        # Payload'u decode et, ttl_sec'i yükselt, tekrar encode et — imza eşleşmez
        raw = base64.urlsafe_b64decode(token.payload)
        data = json.loads(raw)
        data["ttl_sec"] = 999999
        new_payload = base64.urlsafe_b64encode(
            json.dumps(data, sort_keys=True).encode(),
        ).decode()
        tampered = AuthorizationToken(
            token_id=token.token_id,
            payload=new_payload,
            signature=token.signature,  # eski imza artık geçerli değil
        )
        assert mgr.verify(tampered, target) is False

    def test_different_target_fails(self) -> None:
        mgr = AuthorizationManager(secret=_SECRET)
        token, _target = self._make_valid_token(mgr)
        other = Target(TargetType.IP_SINGLE, "10.0.0.1")
        assert mgr.verify(token, other) is False

    def test_expired_token_fails(self) -> None:
        clock = {"now": 1000.0}
        mgr = AuthorizationManager(
            secret=_SECRET, ttl_sec=60, time_func=lambda: clock["now"],
        )
        target = _localhost_target()
        req = AuthorizationRequest(target, ScanDepth.QUICK, user_accepted_terms=True)
        token = mgr.grant(req, _allowed_scope(target))

        # Daha TTL dolmadı
        assert mgr.verify(token, target)

        # TTL'yi aş
        clock["now"] = 1000.0 + 61
        assert mgr.verify(token, target) is False

    def test_revoked_token_fails(self) -> None:
        mgr = AuthorizationManager(secret=_SECRET)
        token, target = self._make_valid_token(mgr)
        assert mgr.verify(token, target)
        mgr.revoke(token)
        assert mgr.verify(token, target) is False

    def test_revoke_by_token_id_string(self) -> None:
        mgr = AuthorizationManager(secret=_SECRET)
        token, target = self._make_valid_token(mgr)
        mgr.revoke(token.token_id)
        assert mgr.verify(token, target) is False

    def test_garbage_payload_fails(self) -> None:
        mgr = AuthorizationManager(secret=_SECRET)
        garbage = AuthorizationToken(
            token_id="fake",
            payload="!!!not-base64!!!",
            signature="deadbeef",
        )
        assert mgr.verify(garbage, _localhost_target()) is False

    def test_valid_base64_invalid_json_fails(self) -> None:
        mgr = AuthorizationManager(secret=_SECRET)
        bad_payload = base64.urlsafe_b64encode(b"not json").decode()
        token = AuthorizationToken(
            token_id="fake", payload=bad_payload, signature="00" * 32,
        )
        assert mgr.verify(token, _localhost_target()) is False

    def test_payload_missing_required_fields_fails(self) -> None:
        mgr = AuthorizationManager(secret=_SECRET)
        partial = base64.urlsafe_b64encode(
            json.dumps({"token_id": "x"}).encode(),
        ).decode()
        token = AuthorizationToken(
            token_id="x", payload=partial, signature="00" * 32,
        )
        assert mgr.verify(token, _localhost_target()) is False


# ---------------------------------------------------------------------
# Target hash fonksiyonu
# ---------------------------------------------------------------------
class TestHashTarget:
    def test_same_target_same_hash(self) -> None:
        t1 = Target(TargetType.IP_SINGLE, "10.0.0.1")
        t2 = Target(TargetType.IP_SINGLE, "10.0.0.1")
        assert hash_target(t1) == hash_target(t2)

    def test_different_value_different_hash(self) -> None:
        t1 = Target(TargetType.IP_SINGLE, "10.0.0.1")
        t2 = Target(TargetType.IP_SINGLE, "10.0.0.2")
        assert hash_target(t1) != hash_target(t2)

    def test_different_type_different_hash(self) -> None:
        t1 = Target(TargetType.IP_SINGLE, "127.0.0.1")
        t2 = Target(TargetType.LOCALHOST, "127.0.0.1")
        assert hash_target(t1) != hash_target(t2)

    def test_hash_is_deterministic_hex(self) -> None:
        t = Target(TargetType.LOCALHOST, "127.0.0.1")
        h = hash_target(t)
        assert len(h) == 32
        assert all(c in "0123456789abcdef" for c in h)
