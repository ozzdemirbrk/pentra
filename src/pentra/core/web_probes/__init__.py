"""Web probe modules — each probe tests one vulnerability category.

All probes inherit from `WebProbeBase` and follow the Level 2 rules:
    1. Single-shot (no loops against the same endpoint)
    2. Evidence is enough (minimum packets)
    3. Read, don't write (no persistent server-side changes)
"""

from pentra.core.web_probes.base import WebProbeBase

__all__ = ["WebProbeBase"]
