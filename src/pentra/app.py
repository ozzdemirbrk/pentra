"""Pentra uygulamasının giriş noktası.

Tüm bağımlılıkları oluşturur ve PentraWizard'ı başlatır.
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
    """TargetType'a göre uygun Scanner örneği üretir."""

    def factory(target_type: TargetType) -> ScannerBase:
        # URL → WebScanner, WIFI → WifiScanner, diğerleri → NetworkScanner.
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

    # ---- .env dosyasını yükle (varsa) ----
    # Proje kökünde .env varsa NVD_API_KEY gibi anahtarları yükler.
    # Dosya yoksa sessizce geçer (os.environ'da tanımlı olanlar kullanılır).
    _load_env_file()

    # ---- Qt uygulaması ----
    app = QApplication(args)
    app.setApplicationName(__app_name__)
    app.setApplicationVersion(__version__)
    app.setOrganizationName(__app_name__)

    # ---- Paylaşımlı servisler ----
    appdata = get_appdata_dir()
    audit_log = AuditLog(log_path=appdata / "audit.log")
    scan_history = ScanHistory(db_path=appdata / "history.db")
    scope_validator = ScopeValidator()
    auth_manager = AuthorizationManager()  # secret otomatik, TTL 30 dk

    # Rate limiter: varsayılan 500 pps, burst 2000
    rate_limiter = TokenBucket(
        capacity=MAX_RATE_LIMIT_PPS,
        refill_rate_per_sec=float(DEFAULT_RATE_LIMIT_PPS),
    )

    # ---- NVD / CVE Mapper (opsiyonel — .env'de key varsa hızlı, yoksa anonim) ----
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

    # ---- Sihirbaz ----
    wizard = PentraWizard(orchestrator=orchestrator, scan_history=scan_history)
    wizard.setPage(PageId.AUTHORIZATION, AuthorizationPage())
    wizard.setPage(PageId.TARGET_SELECT, TargetSelectPage())
    wizard.setPage(PageId.DEPTH_SELECT, DepthSelectPage())
    wizard.setPage(PageId.PROGRESS, ProgressPage())
    wizard.setPage(PageId.REPORT, ReportPage())
    wizard.setStartId(PageId.AUTHORIZATION)

    wizard.show()

    return app.exec()


def _load_env_file() -> None:
    """Proje kökündeki .env dosyasını os.environ'a yükler (varsa).

    Arama sırası: çalışma dizini → bu modülün üst klasörleri.
    """
    # Önce çalışma dizini
    cwd_env = Path.cwd() / ".env"
    if cwd_env.exists():
        load_dotenv(cwd_env)
        return

    # Sonra paket içinden yukarı doğru (ör. kaynaktan çalıştırmada)
    here = Path(__file__).resolve()
    for parent in [here.parent, *here.parents]:
        candidate = parent / ".env"
        if candidate.exists():
            load_dotenv(candidate)
            return
