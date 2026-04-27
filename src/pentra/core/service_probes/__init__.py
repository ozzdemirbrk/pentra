"""Service probes — auth/configuration checks on an open port.

After NetworkScanner runs a port scan, additional non-destructive probes
may run against some of the open ports it found (databases, admin
interfaces, etc.). Example: if Redis 6379 is open, send `PING`, and if
it answers without auth, emit a CRITICAL finding.

Fully compliant with the Level 2 rules:
    - Single-shot connection
    - Only checks the auth state (NO data extraction)
    - Connection is closed afterwards
"""

from pentra.core.service_probes.base import ServiceProbeBase

__all__ = ["ServiceProbeBase"]
