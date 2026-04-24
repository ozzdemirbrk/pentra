"""Pentra ana sihirbazı — 5 ekranlı QWizard.

WizardContext sayfalar arasında paylaşılan veri kabıdır (dataclass).
Her sayfa okur ve yazar; sayfa-özel state bu obje üzerinden akar.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from PySide6.QtWidgets import QWizard

from pentra.i18n import Translator, t
from pentra.models import Finding, ScanDepth, Target

if TYPE_CHECKING:
    from pentra.core.scan_orchestrator import PreparedScan, ScanOrchestrator
    from pentra.storage.scan_history import ScanHistory


# ---------------------------------------------------------------------
# WizardContext — sayfalar arası paylaşılan veri
# ---------------------------------------------------------------------
@dataclasses.dataclass
class WizardContext:
    """5 sayfanın ortak çalışma alanı."""

    # Ekran 1 — Yetki
    user_accepted_terms: bool = False

    # Ekran 2 — Hedef
    target: Target | None = None
    external_target_confirmed: bool = False

    # Ekran 3 — Derinlik
    depth: ScanDepth | None = None

    # Ekran 4 — Tarama
    prepared_scan: "PreparedScan | None" = None
    findings: list[Finding] = dataclasses.field(default_factory=list)
    scan_started_at: datetime | None = None
    scan_ended_at: datetime | None = None
    scan_error: str | None = None

    # Ekran 5 — Rapor
    saved_report_path: str | None = None


# ---------------------------------------------------------------------
# Sayfa ID'leri — her sayfa QWizardPage setPage() ile bu ID'lerle eklenir
# ---------------------------------------------------------------------
class PageId:
    AUTHORIZATION = 0
    TARGET_SELECT = 1
    DEPTH_SELECT = 2
    PROGRESS = 3
    REPORT = 4


# ---------------------------------------------------------------------
# Sihirbaz sınıfı
# ---------------------------------------------------------------------
class PentraWizard(QWizard):
    """Ana uygulama penceresi — 5-sayfa tarama sihirbazı."""

    def __init__(
        self,
        orchestrator: "ScanOrchestrator",
        scan_history: "ScanHistory | None" = None,
        parent=None,
    ) -> None:
        super().__init__(parent)

        self.context = WizardContext()
        self.orchestrator = orchestrator
        #: Tarama geçmişi — None ise geçmiş kaydı yapılmaz (test/dev senaryosu için)
        self.scan_history: "ScanHistory | None" = scan_history

        self.setWizardStyle(QWizard.WizardStyle.ModernStyle)
        self.setOption(QWizard.WizardOption.NoBackButtonOnStartPage, True)
        self.setOption(QWizard.WizardOption.IndependentPages, False)
        self.setMinimumSize(720, 560)

        # Pencere başlığı + buton metinleri i18n üzerinden gelir.
        self._retranslate_chrome()
        Translator.instance().languageChanged.connect(
            lambda _l: self._retranslate_chrome(),
        )

        # Sayfa eklenmesi app.py'dan yapılır (bağımlılıkları enjekte etmek için)

    def _retranslate_chrome(self) -> None:
        """Pencere başlığı + wizard buton metinlerini aktif dilden yükler."""
        self.setWindowTitle(t("app.window_title"))
        self.setButtonText(QWizard.WizardButton.NextButton, t("wizard.button.next"))
        self.setButtonText(QWizard.WizardButton.BackButton, t("wizard.button.back"))
        self.setButtonText(QWizard.WizardButton.CancelButton, t("wizard.button.cancel"))
        self.setButtonText(QWizard.WizardButton.FinishButton, t("wizard.button.finish"))
        self.setButtonText(QWizard.WizardButton.CommitButton, t("wizard.button.commit"))

    # Debugging/testing yardımcısı
    def set_scan_started_now(self) -> None:
        self.context.scan_started_at = datetime.now(timezone.utc)

    def set_scan_ended_now(self) -> None:
        self.context.scan_ended_at = datetime.now(timezone.utc)
