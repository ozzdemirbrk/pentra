"""Common base class for all scanners.

Every scanner (network, host, web, wifi) inherits from `ScannerBase` and
implements `_do_scan()`.

Safety chain:
    1. Scanner `__init__` receives rate_limiter + audit_log + auth_manager
    2. When `scan(target, depth, token)` is called, the token is first
       verified (defense in depth — even though the Orchestrator already
       verified it)
    3. If the token is valid `_do_scan()` is invoked
    4. Every step is written to the audit log
"""

from __future__ import annotations

from abc import abstractmethod

from PySide6.QtCore import QObject, Signal

from pentra.core.rate_limiter import TokenBucket
from pentra.models import Finding, ScanDepth, Target
from pentra.safety.authorization import (
    AuthorizationManager,
    AuthorizationToken,
    hash_target,
)
from pentra.storage.audit_log import AuditLog, make_event

try:
    # CveMapper is an optional dependency — injected from outside.
    from pentra.knowledge.cve_mapper import CveMapper
except ImportError:  # pragma: no cover
    CveMapper = None  # type: ignore[assignment,misc]


class ScannerBase(QObject):
    """Abstract scanner base — emits progress via Qt signals.

    Subclasses implement `_do_scan()` and `scanner_name`.
    """

    # -----------------------------------------------------------------
    # Qt signals
    # -----------------------------------------------------------------
    # (percent 0-100, localized step description)
    progress_updated = Signal(int, str)
    # A new Finding was discovered
    finding_discovered = Signal(object)
    # Scan finished successfully
    scan_completed = Signal()
    # Error — localized message
    error_occurred = Signal(str)

    def __init__(
        self,
        rate_limiter: TokenBucket,
        audit_log: AuditLog,
        auth_manager: AuthorizationManager,
        cve_mapper: CveMapper | None = None,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._rate_limiter = rate_limiter
        self._audit_log = audit_log
        self._auth_manager = auth_manager
        self._cve_mapper = cve_mapper  # No CVE enrichment when None
        self._cancelled: bool = False

    # -----------------------------------------------------------------
    # To be implemented by subclasses
    # -----------------------------------------------------------------
    @property
    @abstractmethod
    def scanner_name(self) -> str:
        """Short name visible in the audit log (e.g. 'network_scanner')."""

    @abstractmethod
    def _do_scan(self, target: Target, depth: ScanDepth) -> None:
        """Actual scan logic. Subclass emits signals.

        - `progress_updated.emit(percent, 'step description')`
        - `finding_discovered.emit(Finding(...))`
        - For cancellation, check `self.is_cancelled`
        """

    # -----------------------------------------------------------------
    # Shared entry point
    # -----------------------------------------------------------------
    def scan(
        self,
        target: Target,
        depth: ScanDepth,
        token: AuthorizationToken,
    ) -> None:
        """Start a scan. Includes token verification + audit log writes.

        On error this emits `error_occurred` and swallows the exception.
        """
        # 1. Last line of defense: token verification
        if not self._auth_manager.verify(token, target):
            self._emit_error("Authorization token is invalid or expired")
            return

        target_fp = hash_target(target)

        # 2. Start log
        self._audit_log.log_event(
            make_event(
                "scan_started",
                target_fingerprint=target_fp,
                details={
                    "scanner": self.scanner_name,
                    "depth": depth.value,
                    "target_type": target.target_type.value,
                },
            ),
        )

        # 3. Actual scan — errors are caught and reported back as a signal
        try:
            self._do_scan(target, depth)
        except Exception as e:  # noqa: BLE001 — user needs to see this; don't swallow
            self._audit_log.log_event(
                make_event(
                    "scan_failed",
                    target_fingerprint=target_fp,
                    details={
                        "scanner": self.scanner_name,
                        "error": str(e),
                    },
                ),
            )
            self._emit_error(f"Error during scan: {e}")
            return

        # 4. Success log + signal
        if self._cancelled:
            self._audit_log.log_event(
                make_event(
                    "scan_cancelled",
                    target_fingerprint=target_fp,
                    details={"scanner": self.scanner_name},
                ),
            )
        else:
            self._audit_log.log_event(
                make_event(
                    "scan_completed",
                    target_fingerprint=target_fp,
                    details={"scanner": self.scanner_name},
                ),
            )
        self.scan_completed.emit()

    # -----------------------------------------------------------------
    # Helpers (for subclasses)
    # -----------------------------------------------------------------
    def cancel(self) -> None:
        """Cancel the scan — `_do_scan` should check `is_cancelled`."""
        self._cancelled = True

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled

    def _emit_progress(self, percent: int, message: str) -> None:
        """Subclasses use this helper to emit signals."""
        self.progress_updated.emit(max(0, min(100, percent)), message)

    def _emit_finding(self, finding: Finding) -> None:
        self.finding_discovered.emit(finding)

    def _emit_error(self, message: str) -> None:
        self.error_occurred.emit(message)

    def _throttle(self, packets: int = 1) -> bool:
        """Request N tokens from the rate limiter. Blocks if needed.

        Returns False when the scan is cancelled — user code should behave accordingly.
        """
        if self._cancelled:
            return False
        return self._rate_limiter.wait_for(packets, timeout=30.0)
