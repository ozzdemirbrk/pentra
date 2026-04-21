"""Tüm tarayıcıların ortak temel sınıfı.

Her tarayıcı (network, host, web, wifi) `ScannerBase`'den türer ve
`_do_scan()` metodunu implement eder.

Güvenlik zinciri:
    1. Scanner `__init__` rate_limiter + audit_log + auth_manager alır
    2. `scan(target, depth, token)` çağrıldığında önce token doğrulanır
       (defense in depth — Orchestrator zaten doğrulamış olsa da)
    3. Token geçerliyse `_do_scan()` çağrılır
    4. Her adım audit log'a yazılır
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
    # CveMapper opsiyonel bağımlılık — dışarıdan enjekte edilir.
    from pentra.knowledge.cve_mapper import CveMapper
except ImportError:  # pragma: no cover
    CveMapper = None  # type: ignore[assignment,misc]


class ScannerBase(QObject):
    """Tarayıcı soyut temeli — Qt sinyalleriyle ilerleme yayar.

    Alt sınıflar `_do_scan()` + `scanner_name` implement eder.
    """

    # -----------------------------------------------------------------
    # Qt sinyalleri
    # -----------------------------------------------------------------
    # (yüzde 0-100, Türkçe açıklama)
    progress_updated = Signal(int, str)
    # Yeni bir Finding keşfedildi
    finding_discovered = Signal(object)
    # Tarama başarıyla bitti
    scan_completed = Signal()
    # Hata — Türkçe mesaj
    error_occurred = Signal(str)

    def __init__(
        self,
        rate_limiter: TokenBucket,
        audit_log: AuditLog,
        auth_manager: AuthorizationManager,
        cve_mapper: "CveMapper | None" = None,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._rate_limiter = rate_limiter
        self._audit_log = audit_log
        self._auth_manager = auth_manager
        self._cve_mapper = cve_mapper  # None ise CVE zenginleştirme yapılmaz
        self._cancelled: bool = False

    # -----------------------------------------------------------------
    # Alt sınıfın implement edeceği
    # -----------------------------------------------------------------
    @property
    @abstractmethod
    def scanner_name(self) -> str:
        """Audit log'da görünecek kısa ad (ör. 'network_scanner')."""

    @abstractmethod
    def _do_scan(self, target: Target, depth: ScanDepth) -> None:
        """Gerçek tarama mantığı. Alt sınıf sinyalleri emit eder.

        - `progress_updated.emit(yüzde, 'adım açıklaması')`
        - `finding_discovered.emit(Finding(...))`
        - Cancellation için `self.is_cancelled` kontrolü
        """

    # -----------------------------------------------------------------
    # Ortak giriş noktası
    # -----------------------------------------------------------------
    def scan(
        self,
        target: Target,
        depth: ScanDepth,
        token: AuthorizationToken,
    ) -> None:
        """Tarama başlat. Token doğrulaması + audit log yazımı dahil.

        Hata durumunda `error_occurred` emit eder, exception yutar.
        """
        # 1. Son savunma hattı: token doğrulaması
        if not self._auth_manager.verify(token, target):
            self._emit_error("Yetki token'ı geçersiz veya süresi dolmuş")
            return

        target_fp = hash_target(target)

        # 2. Başlangıç log
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

        # 3. Asıl tarama — hata yakalanır, sinyal olarak geri döner
        try:
            self._do_scan(target, depth)
        except Exception as e:  # noqa: BLE001 — kullanıcı görmeli, yutmayalım
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
            self._emit_error(f"Tarama sırasında hata: {e}")
            return

        # 4. Başarı log + sinyal
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
    # Yardımcılar (alt sınıflar için)
    # -----------------------------------------------------------------
    def cancel(self) -> None:
        """Taramayı iptal et — `_do_scan` `is_cancelled`'ı kontrol etmeli."""
        self._cancelled = True

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled

    def _emit_progress(self, percent: int, message: str) -> None:
        """Alt sınıflar bu yardımcıyla sinyal emit eder."""
        self.progress_updated.emit(max(0, min(100, percent)), message)

    def _emit_finding(self, finding: Finding) -> None:
        self.finding_discovered.emit(finding)

    def _emit_error(self, message: str) -> None:
        self.error_occurred.emit(message)

    def _throttle(self, packets: int = 1) -> bool:
        """Rate limiter'dan N token iste. Beklemek gerekirse bekler.

        İptal edilmiş taramada False döner — kullanıcı kodu buna göre davranır.
        """
        if self._cancelled:
            return False
        return self._rate_limiter.wait_for(packets, timeout=30.0)
