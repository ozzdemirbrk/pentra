"""Pentra main wizard — a 5-screen QWizard.

WizardContext is the data container shared across pages (dataclass).
Each page reads and writes it; page-specific state flows through this object.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from PySide6.QtWidgets import QWizard

from pentra.i18n import Translator, t
from pentra.models import Finding, ScanDepth, Target

if TYPE_CHECKING:
    from pentra.core.scan_orchestrator import PreparedScan, ScanOrchestrator
    from pentra.storage.scan_history import ScanHistory


# ---------------------------------------------------------------------
# WizardContext — data shared across pages
# ---------------------------------------------------------------------
@dataclasses.dataclass
class WizardContext:
    """Shared working area for the five pages."""

    # Screen 1 — Authorization
    user_accepted_terms: bool = False

    # Screen 2 — Target
    target: Target | None = None
    external_target_confirmed: bool = False

    # Screen 3 — Depth
    depth: ScanDepth | None = None

    # Screen 4 — Scan
    prepared_scan: PreparedScan | None = None
    findings: list[Finding] = dataclasses.field(default_factory=list)
    scan_started_at: datetime | None = None
    scan_ended_at: datetime | None = None
    scan_error: str | None = None

    # Screen 5 — Report
    saved_report_path: str | None = None


# ---------------------------------------------------------------------
# Page IDs — every QWizardPage is added via setPage() with these IDs
# ---------------------------------------------------------------------
class PageId:
    AUTHORIZATION = 0
    TARGET_SELECT = 1
    DEPTH_SELECT = 2
    PROGRESS = 3
    REPORT = 4


# ---------------------------------------------------------------------
# Wizard class
# ---------------------------------------------------------------------
class PentraWizard(QWizard):
    """Main application window — a 5-page scan wizard."""

    def __init__(
        self,
        orchestrator: ScanOrchestrator,
        scan_history: ScanHistory | None = None,
        parent=None,
    ) -> None:
        super().__init__(parent)

        self.context = WizardContext()
        self.orchestrator = orchestrator
        #: Scan history — when None, history isn't recorded (for test/dev scenarios)
        self.scan_history: ScanHistory | None = scan_history

        self.setWizardStyle(QWizard.WizardStyle.ModernStyle)
        self.setOption(QWizard.WizardOption.NoBackButtonOnStartPage, True)
        self.setOption(QWizard.WizardOption.IndependentPages, False)
        self.setMinimumSize(720, 560)

        # Window title + button labels come via i18n.
        self._retranslate_chrome()
        Translator.instance().languageChanged.connect(
            lambda _l: self._retranslate_chrome(),
        )

        # Pages are added from app.py (so that dependencies can be injected)

    def _retranslate_chrome(self) -> None:
        """Load window title + wizard button labels from the active language."""
        self.setWindowTitle(t("app.window_title"))
        self.setButtonText(QWizard.WizardButton.NextButton, t("wizard.button.next"))
        self.setButtonText(QWizard.WizardButton.BackButton, t("wizard.button.back"))
        self.setButtonText(QWizard.WizardButton.CancelButton, t("wizard.button.cancel"))
        self.setButtonText(QWizard.WizardButton.FinishButton, t("wizard.button.finish"))
        self.setButtonText(QWizard.WizardButton.CommitButton, t("wizard.button.commit"))

    # Debugging/testing helper
    def set_scan_started_now(self) -> None:
        self.context.scan_started_at = datetime.now(UTC)

    def set_scan_ended_now(self) -> None:
        self.context.scan_ended_at = datetime.now(UTC)
