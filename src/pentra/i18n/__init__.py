"""Pentra için çok dilli (i18n) altyapısı.

Kullanım::

    from pentra.i18n import t
    label.setText(t("auth.title"))
"""

from pentra.i18n.translator import Translator, t

__all__ = ["Translator", "t"]
