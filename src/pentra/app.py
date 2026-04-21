"""Pentra uygulamasının giriş noktası.

Tüm bağımlılıkları oluşturur ve PentraWizard'ı başlatır.
"""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from pentra import __app_name__, __version__
from pentra.config import (
    DEFAULT_RATE_LIMIT_PPS,
    MAX_RATE_LIMIT_PPS,
    get_appdata_dir,
)
from pentra.core.network_scanner import NetworkScanner
from pentra.core.rate_limiter import TokenBucket
from pentra.core.scan_orchestrator import ScanOrchestrator
from pentra.core.scanner_base import ScannerBase
from pentra.gui.screens.authorization import AuthorizationPage
from pentra.gui.screens.depth_select import DepthSelectPage
from pentra.gui.screens.progress import ProgressPage
from pentra.gui.screens.report import ReportPage
from pentra.gui.screens.target_select import TargetSelectPage
from pentra.gui.wizard import PageId, PentraWizard
from pentra.models import TargetType
from pentra.safety.authorization import AuthorizationManager
from pentra.safety.scope_validator import ScopeValidator
from pentra.storage.audit_log import AuditLog


def _build_scanner_factory(
    rate_limiter: TokenBucket,
    audit_log: AuditLog,
    auth_manager: AuthorizationManager,
):
    """TargetType'a göre uygun Scanner örneği üretir."""

    def factory(target_type: TargetType) -> ScannerBase:
        # MVP (Faz 2): Tüm hedef tipleri şu an NetworkScanner'a yönlenir.
        # Faz 3+'ta TargetType'a göre farklı Scanner'lar döner.
        del target_type  # şimdilik tek scanner
        return NetworkScanner(
            rate_limiter=rate_limiter,
            audit_log=audit_log,
            auth_manager=auth_manager,
        )

    return factory


def main(argv: list[str] | None = None) -> int:
    args = sys.argv if argv is None else argv

    # ---- Qt uygulaması ----
    app = QApplication(args)
    app.setApplicationName(__app_name__)
    app.setApplicationVersion(__version__)
    app.setOrganizationName(__app_name__)

    # ---- Paylaşımlı servisler ----
    appdata = get_appdata_dir()
    audit_log = AuditLog(log_path=appdata / "audit.log")
    scope_validator = ScopeValidator()
    auth_manager = AuthorizationManager()  # secret otomatik, TTL 30 dk

    # Rate limiter: varsayılan 500 pps, burst 2000
    rate_limiter = TokenBucket(
        capacity=MAX_RATE_LIMIT_PPS,
        refill_rate_per_sec=float(DEFAULT_RATE_LIMIT_PPS),
    )

    scanner_factory = _build_scanner_factory(
        rate_limiter=rate_limiter,
        audit_log=audit_log,
        auth_manager=auth_manager,
    )

    orchestrator = ScanOrchestrator(
        scope_validator=scope_validator,
        auth_manager=auth_manager,
        audit_log=audit_log,
        scanner_factory=scanner_factory,
    )

    # ---- Sihirbaz ----
    wizard = PentraWizard(orchestrator=orchestrator)
    wizard.setPage(PageId.AUTHORIZATION, AuthorizationPage())
    wizard.setPage(PageId.TARGET_SELECT, TargetSelectPage())
    wizard.setPage(PageId.DEPTH_SELECT, DepthSelectPage())
    wizard.setPage(PageId.PROGRESS, ProgressPage())
    wizard.setPage(PageId.REPORT, ReportPage())
    wizard.setStartId(PageId.AUTHORIZATION)

    wizard.show()

    return app.exec()
