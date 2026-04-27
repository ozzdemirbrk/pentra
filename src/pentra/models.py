"""Shared data models and enums used across Pentra.

This module is imported by all of the GUI, core, safety, and storage layers
and has no dependencies on them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class TargetType(str, Enum):
    """Type of scan target."""

    LOCALHOST = "localhost"
    LOCAL_NETWORK = "local_network"
    IP_SINGLE = "ip_single"
    IP_RANGE = "ip_range"
    URL = "url"
    WIFI = "wifi"


class ScanDepth(str, Enum):
    """Scan depth — differs by duration and coverage."""

    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"


class Severity(str, Enum):
    """Finding severity level — used as a color code in the report."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScopeDecisionType(str, Enum):
    """Outcome of scope validation."""

    # Private network (RFC1918) or localhost — allowed directly
    ALLOWED_PRIVATE = "allowed_private"
    # External target — requires additional user confirmation
    REQUIRES_CONFIRMATION = "requires_confirmation"
    # Reserved/multicast/link-local — scanning forbidden
    DENIED = "denied"


@dataclass(frozen=True)
class Target:
    """Scan target — immutable value object passed to scanners.

    `value` takes different formats depending on the target type:
        - LOCALHOST: "127.0.0.1"
        - LOCAL_NETWORK: auto-detected CIDR (e.g. "192.168.1.0/24")
        - IP_SINGLE: "192.168.1.50"
        - IP_RANGE: CIDR notation ("192.168.1.0/24")
        - URL: "https://example.com"
        - WIFI: SSID or "*" (all nearby networks)
    """

    target_type: TargetType
    value: str
    description: str | None = None


@dataclass(frozen=True)
class ScopeDecision:
    """Output of ScopeValidator."""

    decision: ScopeDecisionType
    target: Target
    reason: str  # Localized explanation — shown in the UI
    resolved_ips: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_allowed(self) -> bool:
        """Whether the target is directly allowed (no extra confirmation needed)."""
        return self.decision == ScopeDecisionType.ALLOWED_PRIVATE

    @property
    def is_denied(self) -> bool:
        """Whether the target was firmly denied."""
        return self.decision == ScopeDecisionType.DENIED

    @property
    def needs_confirmation(self) -> bool:
        """Whether the user must provide an additional confirmation."""
        return self.decision == ScopeDecisionType.REQUIRES_CONFIRMATION


@dataclass(frozen=True)
class AuthorizationRequest:
    """Authorization request — created when the user approves in the wizard."""

    target: Target
    depth: ScanDepth
    user_accepted_terms: bool  # Main consent from screen 1
    external_target_confirmed: bool = False  # Extra consent for non-RFC1918 targets


@dataclass(frozen=True)
class AuthorizationToken:
    """Single-use scan authorization token.

    A scanner cannot send any packet without receiving this token. Because it is
    HMAC-signed, a forged token cannot be produced.
    """

    token_id: str  # UUID — for tracking
    payload: str  # base64 encoded JSON — target_hash, granted_at, ttl
    signature: str  # HMAC-SHA256 hex


@dataclass(frozen=True)
class Finding:
    """A single security finding — a building block of the report.

    Each scanner returns N Findings.
    """

    scanner_name: str
    severity: Severity
    title: str  # Localized summary (e.g. "SSH accepts default credentials")
    description: str  # Localized detail
    target: str  # IP:port, URL etc.
    cve_ids: tuple[str, ...] = field(default_factory=tuple)
    remediation: str | None = None  # Localized remediation suggestion
    evidence: dict[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc),
    )


@dataclass(frozen=True)
class AuditEvent:
    """Event written to the audit log — immutable, hash-chained."""

    event_type: str  # "scan_requested", "scan_started", "scan_completed" etc.
    timestamp: datetime
    target_fingerprint: str  # Short SHA256 digest of the target (instead of the full value)
    details: dict[str, Any] = field(default_factory=dict)
