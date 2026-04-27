"""Scan orchestrator — applies the safety chain in a single place.

The only legitimate way to start a scan is through here. The chain:

    Request -> ScopeValidator -> AuthorizationManager.grant -> Scanner selection
               | denied           | denied
            AuthorizationDenied   AuthorizationDenied

On success it returns a `PreparedScan` — the GUI layer runs this inside a
QThread via `scanner.scan(...)`.

NOTE: the Orchestrator **does not send packets**. The actual scan happens
inside `Scanner.scan()` on a worker thread managed by the GUI.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable

from pentra.core.scanner_base import ScannerBase
from pentra.models import (
    AuthorizationRequest,
    AuthorizationToken,
    ScanDepth,
    ScopeDecision,
    Target,
    TargetType,
)
from pentra.safety.authorization import (
    AuthorizationDenied,
    AuthorizationManager,
    hash_target,
)
from pentra.safety.scope_validator import ScopeValidator
from pentra.storage.audit_log import AuditLog, make_event

# Scanner factory — returns the correct scanner based on TargetType.
ScannerFactory = Callable[[TargetType], ScannerBase]


@dataclasses.dataclass(frozen=True)
class ScanRequest:
    """Scan request coming from the GUI — the user's choices in the wizard."""

    target: Target
    depth: ScanDepth
    user_accepted_terms: bool
    external_target_confirmed: bool = False


@dataclasses.dataclass(frozen=True)
class PreparedScan:
    """A scan that passed the safety chain and is ready to run."""

    scanner: ScannerBase
    token: AuthorizationToken
    target: Target
    depth: ScanDepth
    scope_decision: ScopeDecision


class ScanOrchestrator:
    """Central class that manages the scan lifecycle.

    Sole responsibility:
        - Apply the safety checks in order
        - Prepare the appropriate Scanner instance
        - Write every significant event to the audit log
    """

    def __init__(
        self,
        scope_validator: ScopeValidator,
        auth_manager: AuthorizationManager,
        audit_log: AuditLog,
        scanner_factory: ScannerFactory,
    ) -> None:
        self._scope = scope_validator
        self._auth = auth_manager
        self._audit = audit_log
        self._scanner_factory = scanner_factory

    # -----------------------------------------------------------------
    # Main API
    # -----------------------------------------------------------------
    def prepare(self, request: ScanRequest) -> PreparedScan:
        """Run the safety chain and return a ready scanner + token.

        Raises:
            AuthorizationDenied: if any link in the chain denied the request.
        """
        target_fp = hash_target(request.target)

        # --- 0) Log the request (keep a trace even when denied) ---
        self._audit.log_event(
            make_event(
                "scan_requested",
                target_fingerprint=target_fp,
                details={
                    "target_type": request.target.target_type.value,
                    "depth": request.depth.value,
                    "terms_accepted": request.user_accepted_terms,
                    "external_confirmed": request.external_target_confirmed,
                },
            ),
        )

        # --- 1) Scope validation ---
        scope_decision = self._scope.validate(request.target)
        self._audit.log_event(
            make_event(
                "scope_evaluated",
                target_fingerprint=target_fp,
                details={
                    "decision": scope_decision.decision.value,
                    "reason": scope_decision.reason,
                    "resolved_ips": list(scope_decision.resolved_ips),
                },
            ),
        )

        if scope_decision.is_denied:
            self._log_denied(target_fp, "scope_denied", scope_decision.reason)
            raise AuthorizationDenied(
                f"Scope check failed: {scope_decision.reason}",
            )

        # --- 2) Authorization token issue ---
        auth_request = AuthorizationRequest(
            target=request.target,
            depth=request.depth,
            user_accepted_terms=request.user_accepted_terms,
            external_target_confirmed=request.external_target_confirmed,
        )
        try:
            token = self._auth.grant(auth_request, scope_decision)
        except AuthorizationDenied as e:
            self._log_denied(target_fp, "auth_denied", str(e))
            raise

        self._audit.log_event(
            make_event(
                "auth_granted",
                target_fingerprint=target_fp,
                details={"token_id": token.token_id},
            ),
        )

        # --- 3) Pick the appropriate Scanner ---
        scanner = self._scanner_factory(request.target.target_type)

        return PreparedScan(
            scanner=scanner,
            token=token,
            target=request.target,
            depth=request.depth,
            scope_decision=scope_decision,
        )

    def cleanup(self, prepared: PreparedScan) -> None:
        """Revoke the token and write a closing log when the scan ends."""
        self._auth.revoke(prepared.token)
        self._audit.log_event(
            make_event(
                "token_revoked",
                target_fingerprint=hash_target(prepared.target),
                details={"token_id": prepared.token.token_id},
            ),
        )

    # -----------------------------------------------------------------
    # Internal
    # -----------------------------------------------------------------
    def _log_denied(self, target_fp: str, reason_type: str, reason: str) -> None:
        self._audit.log_event(
            make_event(
                reason_type,
                target_fingerprint=target_fp,
                details={"reason": reason},
            ),
        )
