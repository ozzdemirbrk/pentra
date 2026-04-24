"""Onarım rehberi dispatcher — aktif dile göre doğru rehberi döndürür.

`remediations_tr.py` → Türkçe rehberler
`remediations_en.py` → İngilizce rehberler

Her ikisi de aynı `get_guide(finding) -> RemediationGuide | None` API'sını
sunar; bu modül aktif dile göre birini çağırır.
"""

from __future__ import annotations

from pentra.i18n import Translator
from pentra.knowledge import remediations_en, remediations_tr
from pentra.knowledge.remediations_tr import RemediationGuide  # re-export
from pentra.models import Finding

__all__ = ["RemediationGuide", "get_guide"]


def get_guide(finding: Finding) -> RemediationGuide | None:
    """Aktif dile göre onarım rehberini döndürür (yoksa None)."""
    lang = Translator.instance().current_language
    if lang == "en":
        return remediations_en.get_guide(finding)
    return remediations_tr.get_guide(finding)
