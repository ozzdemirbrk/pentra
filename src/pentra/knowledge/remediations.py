"""Remediation-guide dispatcher — returns the right guide for the active language.

`remediations_tr.py` -> Turkish guides
`remediations_en.py` -> English guides

Both expose the same `get_guide(finding) -> RemediationGuide | None` API;
this module picks one based on the active language.
"""

from __future__ import annotations

from pentra.i18n import Translator
from pentra.knowledge import remediations_en, remediations_tr
from pentra.knowledge.remediations_tr import RemediationGuide  # re-export
from pentra.models import Finding

__all__ = ["RemediationGuide", "get_guide"]


def get_guide(finding: Finding) -> RemediationGuide | None:
    """Return the remediation guide for the active language (None if missing)."""
    lang = Translator.instance().current_language
    if lang == "en":
        return remediations_en.get_guide(finding)
    return remediations_tr.get_guide(finding)
