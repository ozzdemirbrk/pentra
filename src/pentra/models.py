"""Pentra genelinde paylaşılan veri modelleri ve enum'lar.

Bu modül GUI, core, safety, storage katmanlarının tümü tarafından
import edilir — alt katmanlara bağımlılığı yoktur.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class TargetType(str, Enum):
    """Tarama hedefi tipi."""

    LOCALHOST = "localhost"
    LOCAL_NETWORK = "local_network"
    IP_SINGLE = "ip_single"
    IP_RANGE = "ip_range"
    URL = "url"
    WIFI = "wifi"


class ScanDepth(str, Enum):
    """Tarama derinliği — süre ve kapsam farkı."""

    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"


class Severity(str, Enum):
    """Bulgu önem derecesi — raporda renk kodu olarak kullanılır."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScopeDecisionType(str, Enum):
    """Kapsam doğrulama sonucu."""

    # Özel ağ (RFC1918) veya localhost — doğrudan izin
    ALLOWED_PRIVATE = "allowed_private"
    # Dış hedef — kullanıcının ek onayı gerekir
    REQUIRES_CONFIRMATION = "requires_confirmation"
    # Rezerve/multicast/link-local — tarama yasak
    DENIED = "denied"


@dataclass(frozen=True)
class Target:
    """Tarama hedefi — tarayıcılara geçirilen immutable değer nesnesi.

    `value` hedef tipine göre farklı format alır:
        - LOCALHOST: "127.0.0.1"
        - LOCAL_NETWORK: otomatik tespit edilen CIDR (ör. "192.168.1.0/24")
        - IP_SINGLE: "192.168.1.50"
        - IP_RANGE: CIDR notasyonu ("192.168.1.0/24")
        - URL: "https://example.com"
        - WIFI: SSID veya "*" (çevredeki tüm ağlar)
    """

    target_type: TargetType
    value: str
    description: str | None = None


@dataclass(frozen=True)
class ScopeDecision:
    """ScopeValidator'ın çıktısı."""

    decision: ScopeDecisionType
    target: Target
    reason: str  # Türkçe açıklama — UI'da gösterilir
    resolved_ips: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_allowed(self) -> bool:
        """Doğrudan izinli mi (ek onay gerektirmez)."""
        return self.decision == ScopeDecisionType.ALLOWED_PRIVATE

    @property
    def is_denied(self) -> bool:
        """Kesinlikle reddedildi mi."""
        return self.decision == ScopeDecisionType.DENIED

    @property
    def needs_confirmation(self) -> bool:
        """Kullanıcının ek onay vermesi gerekiyor mu."""
        return self.decision == ScopeDecisionType.REQUIRES_CONFIRMATION


@dataclass(frozen=True)
class AuthorizationRequest:
    """Yetki talebi — kullanıcı sihirbazda onay verdiğinde oluşturulur."""

    target: Target
    depth: ScanDepth
    user_accepted_terms: bool  # Ekran 1'deki ana onay
    external_target_confirmed: bool = False  # RFC1918 dışı için ek onay


@dataclass(frozen=True)
class AuthorizationToken:
    """Tek-kullanımlık tarama yetki belirteci.

    Scanner bu token'ı almadan hiçbir paket gönderemez. HMAC imzalı
    olduğu için sahte token üretilemez.
    """

    token_id: str  # UUID — izleme için
    payload: str  # base64 encoded JSON — target_hash, granted_at, ttl
    signature: str  # HMAC-SHA256 hex


@dataclass(frozen=True)
class Finding:
    """Bir güvenlik bulgusu — rapor bileşeni.

    Her tarayıcı N tane Finding döndürür.
    """

    scanner_name: str
    severity: Severity
    title: str  # Türkçe özet ("SSH açık ve şifreli parola kabul ediyor")
    description: str  # Türkçe detay
    target: str  # IP:port, URL vb.
    cve_ids: tuple[str, ...] = field(default_factory=tuple)
    remediation: str | None = None  # Türkçe onarım önerisi
    evidence: dict[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc),
    )


@dataclass(frozen=True)
class AuditEvent:
    """Denetim izine yazılan olay — değişmez, hash-zincirli."""

    event_type: str  # "scan_requested", "scan_started", "scan_completed" vb.
    timestamp: datetime
    target_fingerprint: str  # Target'ın SHA256 kısa özeti (tam değer yerine)
    details: dict[str, Any] = field(default_factory=dict)
