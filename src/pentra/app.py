"""Pentra application entry point.

Builds all dependencies and launches PentraWizard.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from dotenv import load_dotenv
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
from pentra.core.update_checker import UpdateChecker
from pentra.core.web_scanner import WebScanner
from pentra.core.wifi_scanner import WifiScanner
from pentra.knowledge.cve_mapper import CveMapper
from pentra.knowledge.nvd_client import NvdClient
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
from pentra.storage.scan_history import ScanHistory


def _build_scanner_factory(
    rate_limiter: TokenBucket,
    audit_log: AuditLog,
    auth_manager: AuthorizationManager,
    cve_mapper: CveMapper | None,
):
    """Produces the appropriate Scanner instance based on TargetType."""

    def factory(target_type: TargetType) -> ScannerBase:
        # URL -> WebScanner, WIFI -> WifiScanner, others -> NetworkScanner.
        if target_type == TargetType.URL:
            return WebScanner(
                rate_limiter=rate_limiter,
                audit_log=audit_log,
                auth_manager=auth_manager,
                cve_mapper=cve_mapper,
            )
        if target_type == TargetType.WIFI:
            return WifiScanner(
                rate_limiter=rate_limiter,
                audit_log=audit_log,
                auth_manager=auth_manager,
            )
        return NetworkScanner(
            rate_limiter=rate_limiter,
            audit_log=audit_log,
            auth_manager=auth_manager,
            cve_mapper=cve_mapper,
        )

    return factory


def main(argv: list[str] | None = None) -> int:
    args = sys.argv if argv is None else argv

    # ---- Load .env file (if present) ----
    # If there's a .env at project root, it loads keys like NVD_API_KEY.
    # If missing, silently skipped (values already in os.environ are used).
    _load_env_file()

    # ---- Qt application ----
    app = QApplication(args)
    app.setApplicationName(__app_name__)
    app.setApplicationVersion(__version__)
    app.setOrganizationName(__app_name__)

    # ---- Shared services ----
    appdata = get_appdata_dir()
    audit_log = AuditLog(log_path=appdata / "audit.log")
    scan_history = ScanHistory(db_path=appdata / "history.db")
    scope_validator = ScopeValidator()
    auth_manager = AuthorizationManager()  # auto-generated secret, 30 min TTL

    # Rate limiter: default 500 pps, burst 2000
    rate_limiter = TokenBucket(
        capacity=MAX_RATE_LIMIT_PPS,
        refill_rate_per_sec=float(DEFAULT_RATE_LIMIT_PPS),
    )

    # ---- NVD / CVE Mapper (optional — fast when key is in .env, otherwise anonymous) ----
    nvd_api_key = os.environ.get("NVD_API_KEY") or None
    nvd_client = NvdClient(api_key=nvd_api_key)
    cve_mapper = CveMapper(nvd_client=nvd_client)

    scanner_factory = _build_scanner_factory(
        rate_limiter=rate_limiter,
        audit_log=audit_log,
        auth_manager=auth_manager,
        cve_mapper=cve_mapper,
    )

    orchestrator = ScanOrchestrator(
        scope_validator=scope_validator,
        auth_manager=auth_manager,
        audit_log=audit_log,
        scanner_factory=scanner_factory,
    )

    # ---- Wizard ----
    wizard = PentraWizard(orchestrator=orchestrator, scan_history=scan_history)
    wizard.setPage(PageId.AUTHORIZATION, AuthorizationPage())
    wizard.setPage(PageId.TARGET_SELECT, TargetSelectPage())
    wizard.setPage(PageId.DEPTH_SELECT, DepthSelectPage())
    wizard.setPage(PageId.PROGRESS, ProgressPage())
    wizard.setPage(PageId.REPORT, ReportPage())
    wizard.setStartId(PageId.AUTHORIZATION)

    wizard.show()

    # ---- Background update check ----
    # Silently skipped when offline; if a new version exists we'll show a small dialog.
    _update_checker = UpdateChecker()

    def _on_update_available(new_version: str, release_url: str) -> None:
        # Lazy import — to avoid extending startup time
        from pentra.gui.widgets.update_notification import UpdateNotificationDialog
        dialog = UpdateNotificationDialog(
            new_version=new_version, release_url=release_url, parent=wizard,
        )
        dialog.show()

    _update_checker.update_available.connect(_on_update_available)
    _update_checker.start()
    # Worker lives for the duration of app.exec() — one-shot, Qt cleans up automatically.
    # Staying in scope inside app.exec() is enough to keep the reference alive.

    return app.exec()


def _load_env_file() -> None:
    """Load the project-root .env file into os.environ (if present).

    Search order: current working directory -> this module's parent directories.
    """
    # First the current working directory
    cwd_env = Path.cwd() / ".env"
    if cwd_env.exists():
        load_dotenv(cwd_env)
        return

    # Then walk upward from within the package (e.g. when running from source)
    here = Path(__file__).resolve()
    for parent in [here.parent, *here.parents]:
        candidate = parent / ".env"
        if candidate.exists():
            load_dotenv(candidate)
            return
