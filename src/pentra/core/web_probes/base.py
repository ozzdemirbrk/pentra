"""WebProbeBase — the abstract base for every web probe.

Each probe provides:
    - `name`: short name used in the audit log and in report evidence
    - `description`: short user-visible description
    - `probe(url, session)`: the actual test — returns a list of Findings

DESIGN RULES (violations are rejected in code review):
    1. probe() runs once — repeated requests to the same endpoint are FORBIDDEN
    2. Every request must have a timeout <= 10 s
    3. Close connections that are no longer in use
    4. Finding.evidence dict must include: request path, response status, short snippet
    5. Destructive payloads are FORBIDDEN — `DROP TABLE`, `rm -rf`, shell commands, etc.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

import requests

from pentra.i18n import t
from pentra.models import Finding


class WebProbeBase(ABC):
    """Non-destructive test for a single web vulnerability category."""

    # Subclass must override
    name: str = ""

    #: i18n key for the description shown in the UI
    description_key: str = ""

    # Default HTTP timeout (seconds) — probes may override
    timeout: float = 10.0

    @property
    def description(self) -> str:
        """Human-readable description translated into the active language."""
        return t(self.description_key) if self.description_key else ""

    @abstractmethod
    def probe(self, url: str, session: requests.Session) -> list[Finding]:
        """Run the probe and return findings.

        Args:
            url: Target URL (already validated by scope_validator).
            session: Shared `requests.Session` — UA, rate, etc. preconfigured.

        Returns:
            List of findings (empty list = no vulnerability / probe not applicable).

        Errors:
            Network/timeout errors must be caught inside the probe; the upper
            WebScanner layer swallows them. But programming errors such as
            `ValueError` should bubble up so tests can catch them.
        """

    def _build_evidence(
        self,
        *,
        request_method: str,
        request_path: str,
        response_status: int | None = None,
        response_snippet: str = "",
        why_vulnerable: str = "",
        extra: dict[str, object] | None = None,
    ) -> dict[str, object]:
        """Standard evidence dict — guarantees a uniform shape per Finding."""
        evidence: dict[str, object] = {
            "probe_name": self.name,
            "request": f"{request_method} {request_path}",
        }
        if response_status is not None:
            evidence["response_status"] = response_status
        if response_snippet:
            # At most 200 characters of response snippet — enough as evidence
            evidence["response_snippet"] = response_snippet[:200]
        if why_vulnerable:
            evidence["why_vulnerable"] = why_vulnerable
        if extra:
            evidence.update(extra)
        return evidence
