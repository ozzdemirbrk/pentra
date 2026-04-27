"""ServiceProbeBase — auth/configuration test against an open port.

When NetworkScanner finds an open port, it calls `probe(host, port)` if a
`ServiceProbeBase` is registered for it. The probe sends a single
evidence-gathering request without extracting data.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from pentra.i18n import t
from pentra.models import Finding


class ServiceProbeBase(ABC):
    """Lightweight probe that proves a service's auth state."""

    #: Default ports this probe runs on
    default_ports: tuple[int, ...] = ()

    #: Short name used in the audit log (e.g. "redis_auth")
    name: str = ""

    #: i18n key for the description shown in the UI
    description_key: str = ""

    #: Connection timeout (seconds)
    timeout: float = 5.0

    @property
    def description(self) -> str:
        """Human-readable description translated into the active language."""
        return t(self.description_key) if self.description_key else ""

    @abstractmethod
    def probe(self, host: str, port: int) -> list[Finding]:
        """Connect to the service, detect auth state, return findings.

        Args:
            host: Target IP or hostname (already validated by scope_validator).
            port: TCP port number.

        Returns:
            List of findings. Empty list if the service requires auth (or is
            unreachable). A CRITICAL-severity Finding if auth is open.
        """

    def _evidence(
        self,
        host: str,
        port: int,
        *,
        why_vulnerable: str,
        response_snippet: str = "",
        extra: dict[str, object] | None = None,
    ) -> dict[str, object]:
        """Build a standard evidence dict."""
        evidence: dict[str, object] = {
            "probe_name": self.name,
            "target": f"{host}:{port}",
            "why_vulnerable": why_vulnerable,
        }
        if response_snippet:
            evidence["response_snippet"] = response_snippet[:200]
        if extra:
            evidence.update(extra)
        return evidence
