"""Tarama orkestratörü — güvenlik zincirini tek bir yerde uygular.

Taramayı başlatmanın tek yasal yolu buradan geçmektir. Zincir:

    Request → ScopeValidator → AuthorizationManager.grant → Scanner seçimi
              ↓ reddedildi       ↓ reddedildi
           AuthorizationDenied   AuthorizationDenied

Başarılı ise `PreparedScan` döner — GUI katmanı bunu bir QThread içinde
`scanner.scan(...)` olarak başlatır.

NOT: Orchestrator **paket göndermez**. Gerçek tarama `Scanner.scan()` içinde
ve GUI'nin yönettiği worker thread'de olur.
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

# Scanner factory — TargetType'a göre doğru scanner'ı üretir.
ScannerFactory = Callable[[TargetType], ScannerBase]


@dataclasses.dataclass(frozen=True)
class ScanRequest:
    """GUI'den gelen tarama isteği — kullanıcının sihirbazdaki seçimleri."""

    target: Target
    depth: ScanDepth
    user_accepted_terms: bool
    external_target_confirmed: bool = False


@dataclasses.dataclass(frozen=True)
class PreparedScan:
    """Güvenlik zincirini geçmiş, çalıştırılmaya hazır tarama."""

    scanner: ScannerBase
    token: AuthorizationToken
    target: Target
    depth: ScanDepth
    scope_decision: ScopeDecision


class ScanOrchestrator:
    """Tarama yaşam döngüsünü yöneten merkezi sınıf.

    Tek sorumluluğu:
        - Güvenlik kontrollerini sırayla uygulamak
        - Uygun Scanner örneğini hazırlamak
        - Tüm önemli olayları audit log'a yazmak
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
    # Ana API
    # -----------------------------------------------------------------
    def prepare(self, request: ScanRequest) -> PreparedScan:
        """Güvenlik zincirini çalıştır, hazır scanner + token döner.

        Raises:
            AuthorizationDenied: zincirin herhangi bir halkası reddettiyse.
        """
        target_fp = hash_target(request.target)

        # --- 0) Talep loglanır (reddedilse bile iz kalsın) ---
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

        # --- 1) Scope doğrulama ---
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
                f"Kapsam kontrolü başarısız: {scope_decision.reason}",
            )

        # --- 2) Yetki üretimi ---
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

        # --- 3) Uygun Scanner seçimi ---
        scanner = self._scanner_factory(request.target.target_type)

        return PreparedScan(
            scanner=scanner,
            token=token,
            target=request.target,
            depth=request.depth,
            scope_decision=scope_decision,
        )

    def cleanup(self, prepared: PreparedScan) -> None:
        """Tarama bittiğinde token'ı iptal et ve kapanış logu yaz."""
        self._auth.revoke(prepared.token)
        self._audit.log_event(
            make_event(
                "token_revoked",
                target_fingerprint=hash_target(prepared.target),
                details={"token_id": prepared.token.token_id},
            ),
        )

    # -----------------------------------------------------------------
    # İç
    # -----------------------------------------------------------------
    def _log_denied(self, target_fp: str, reason_type: str, reason: str) -> None:
        self._audit.log_event(
            make_event(
                reason_type,
                target_fingerprint=target_fp,
                details={"reason": reason},
            ),
        )
