"""Internationalization (i18n) infrastructure for Pentra.

Usage::

    from pentra.i18n import t
    label.setText(t("auth.title"))
"""

from pentra.i18n.translator import Translator, t

__all__ = ["Translator", "t"]
