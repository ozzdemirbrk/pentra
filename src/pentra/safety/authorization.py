"""Authorization manager — the last barrier before a scan starts.

After the user consents in the wizard, an `AuthorizationRequest` is created.
`AuthorizationManager.grant()` validates the request and returns an
HMAC-signed `AuthorizationToken`. Every `Scanner` must pass the token
through `verify()` before sending any packet.

Token properties:
    - HMAC-SHA256 signed (forgery protection)
    - Bound to a target (hash must match — A's token won't work for B)
    - Has a TTL (default 30 minutes)
    - Signed with a per-session secret (previous session tokens become
      invalid automatically after a restart)
    - Revocable (revoked after the scan finishes)
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import os
import threading
import time
import uuid
from collections.abc import Callable

from pentra.models import (
    AuthorizationRequest,
    AuthorizationToken,
    ScopeDecision,
    Target,
)


# ---------------------------------------------------------------------
# Error classes
# ---------------------------------------------------------------------
class AuthorizationError(Exception):
    """Generic error class for the authorization flow."""


class AuthorizationDenied(AuthorizationError):
    """User consent or scope check was rejected."""


class InvalidToken(AuthorizationError):
    """Token is forged, corrupted, or expired."""


# ---------------------------------------------------------------------
# Internal metadata
# ---------------------------------------------------------------------
@dataclasses.dataclass
class _IssuedTokenInfo:
    """Information retained for an issued token (for revocation + audit)."""

    target_hash: str
    granted_at: int
    ttl_sec: int


# ---------------------------------------------------------------------
# AuthorizationManager
# ---------------------------------------------------------------------
class AuthorizationManager:
    """Central class that issues and verifies scan authorization tokens.

    If the `secret` parameter is `None`, a random one is generated at every
    application start (os.urandom). This makes previous-session tokens
    unusable.
    """

    def __init__(
        self,
        secret: bytes | None = None,
        ttl_sec: int = 30 * 60,
        time_func: Callable[[], float] | None = None,
    ) -> None:
        if secret is not None and len(secret) < 16:
            raise ValueError("secret must be at least 16 bytes")
        if ttl_sec <= 0:
            raise ValueError(f"ttl_sec must be positive, got: {ttl_sec}")

        self._secret: bytes = secret if secret is not None else os.urandom(32)
        self._ttl: int = ttl_sec
        self._time: Callable[[], float] = time_func if time_func is not None else time.time

        self._issued: dict[str, _IssuedTokenInfo] = {}
        self._revoked: set[str] = set()
        self._lock = threading.Lock()

    # -----------------------------------------------------------------
    # Main API
    # -----------------------------------------------------------------
    def grant(
        self,
        request: AuthorizationRequest,
        scope_decision: ScopeDecision,
    ) -> AuthorizationToken:
        """Return an authorization token if the request is valid; otherwise raise.

        Checks:
            1. User has ticked the main consent checkbox
            2. ScopeValidator has not denied the target
            3. For targets requiring extra consent, user provided it
            4. Targets match (request target == scope decision target)
        """
        if not request.user_accepted_terms:
            raise AuthorizationDenied(
                "User has not confirmed the consent screen — scan cannot start",
            )

        if scope_decision.target != request.target:
            raise AuthorizationDenied(
                "Scope decision and authorization request point to different targets",
            )

        if scope_decision.is_denied:
            raise AuthorizationDenied(
                f"Target is not eligible for scanning: {scope_decision.reason}",
            )

        if scope_decision.needs_confirmation and not request.external_target_confirmed:
            raise AuthorizationDenied(
                "External (public) target requires additional user confirmation",
            )

        # Valid request — issue a token
        return self._issue_token(request.target)

    def verify(self, token: AuthorizationToken, target: Target) -> bool:
        """Return whether the token is valid and belongs to the given target."""
        try:
            payload = self._decode_payload(token)
        except (InvalidToken, ValueError):
            return False

        # Signature check (constant-time)
        expected_sig = self._sign(self._payload_bytes(token))
        if not hmac.compare_digest(expected_sig, token.signature):
            return False

        # TTL
        now = int(self._time())
        if now > payload["granted_at"] + payload["ttl_sec"]:
            return False

        # Target hash match
        if payload["target_hash"] != hash_target(target):
            return False

        # Revocation check
        with self._lock:
            if payload["token_id"] in self._revoked:
                return False

        return True

    def revoke(self, token: AuthorizationToken | str) -> None:
        """Revoke a token. Parameter is an AuthorizationToken or a token_id string."""
        token_id = token.token_id if isinstance(token, AuthorizationToken) else token
        with self._lock:
            self._revoked.add(token_id)

    # -----------------------------------------------------------------
    # Internal
    # -----------------------------------------------------------------
    def _issue_token(self, target: Target) -> AuthorizationToken:
        token_id = str(uuid.uuid4())
        target_hash = hash_target(target)
        granted_at = int(self._time())

        payload = {
            "token_id": token_id,
            "target_hash": target_hash,
            "granted_at": granted_at,
            "ttl_sec": self._ttl,
        }
        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode("ascii")
        signature = self._sign(payload_bytes)

        with self._lock:
            self._issued[token_id] = _IssuedTokenInfo(
                target_hash=target_hash,
                granted_at=granted_at,
                ttl_sec=self._ttl,
            )

        return AuthorizationToken(
            token_id=token_id,
            payload=payload_b64,
            signature=signature,
        )

    def _sign(self, payload_bytes: bytes) -> str:
        return hmac.new(self._secret, payload_bytes, hashlib.sha256).hexdigest()

    @staticmethod
    def _payload_bytes(token: AuthorizationToken) -> bytes:
        try:
            return base64.urlsafe_b64decode(token.payload.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as e:
            raise InvalidToken(f"Token payload could not be decoded: {e}") from e

    def _decode_payload(self, token: AuthorizationToken) -> dict[str, object]:
        raw = self._payload_bytes(token)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise InvalidToken(f"Token JSON is invalid: {e}") from e

        required_keys = {"token_id", "target_hash", "granted_at", "ttl_sec"}
        if not required_keys.issubset(data.keys()):
            raise InvalidToken("Token payload is missing required fields")

        return data


# ---------------------------------------------------------------------
# Helper: Target hash
# ---------------------------------------------------------------------
def hash_target(target: Target) -> str:
    """Canonical short SHA256 digest of a Target.

    Instead of storing the full IP/URL in a token payload we keep its hash —
    that way audit logs don't reveal arbitrary data to a human reader.
    """
    data = f"{target.target_type.value}|{target.value}".encode("utf-8")
    return hashlib.sha256(data).hexdigest()[:32]
