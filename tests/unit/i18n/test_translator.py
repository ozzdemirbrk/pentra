"""translator.py — çoğul dil çevirmeni testleri.

QSettings'in test izolasyonu için geçici INI konumuna yönlendirilir.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from PySide6.QtCore import QCoreApplication, QSettings
from PySide6.QtWidgets import QApplication

from pentra.i18n.translator import Translator, t


@pytest.fixture(autouse=True)
def _isolated_qsettings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Her test taze bir QSettings dizini ve yeni Translator örneği alır."""
    # QApplication singleton; yoksa oluştur
    app = QApplication.instance() or QApplication([])
    QCoreApplication.setOrganizationName("PentraTest")
    QCoreApplication.setApplicationName("PentraTest")
    QSettings.setDefaultFormat(QSettings.Format.IniFormat)
    QSettings.setPath(
        QSettings.Format.IniFormat,
        QSettings.Scope.UserScope,
        str(tmp_path),
    )
    # Translator singleton'ını sıfırla — her test taze başlasın
    Translator._instance = None
    yield
    Translator._instance = None
    _ = app  # tutulmazsa GC; lint sessizleştirme


# =====================================================================
# Temel çeviri
# =====================================================================
class TestTranslation:
    def test_english_key_returns_english(self) -> None:
        tr = Translator.instance()
        tr.set_language("en")
        assert t("auth.title") == "Authorization"

    def test_turkish_key_returns_turkish(self) -> None:
        tr = Translator.instance()
        tr.set_language("tr")
        assert t("auth.title") == "Yetki Onayı"

    def test_missing_key_returns_key(self) -> None:
        tr = Translator.instance()
        tr.set_language("en")
        assert t("this.does.not.exist") == "this.does.not.exist"

    def test_fallback_to_english_when_missing_in_current(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """TR'de eksik anahtar EN'ye düşmeli."""
        tr = Translator.instance()
        tr.set_language("tr")
        # EN'de var, TR'de yok olduğunu varsayıyoruz — test için EN tablosunu manipüle et
        tr._translations["en"]["_only_in_en"] = "only-en"
        assert t("_only_in_en") == "only-en"


# =====================================================================
# Dil değişimi + sinyal
# =====================================================================
class TestLanguageSwitching:
    def test_set_language_emits_signal(self) -> None:
        tr = Translator.instance()
        tr.set_language("en")
        received: list[str] = []
        tr.languageChanged.connect(received.append)
        tr.set_language("tr")
        assert received == ["tr"]

    def test_set_same_language_does_not_emit(self) -> None:
        tr = Translator.instance()
        tr.set_language("en")
        received: list[str] = []
        tr.languageChanged.connect(received.append)
        tr.set_language("en")
        assert received == []

    def test_invalid_language_raises(self) -> None:
        tr = Translator.instance()
        with pytest.raises(ValueError):
            tr.set_language("de")

    def test_set_language_persists_across_instances(self) -> None:
        """Kaydedilen dil tercihi, yeni Translator örneğinde de okunmalı."""
        tr = Translator.instance()
        tr.set_language("tr")
        # Singleton'ı sıfırla — sıfırdan instance, QSettings'ten okumalı
        Translator._instance = None
        tr2 = Translator.instance()
        assert tr2.current_language == "tr"


# =====================================================================
# Formatlama
# =====================================================================
class TestFormatting:
    def test_kwargs_format_value(self) -> None:
        tr = Translator.instance()
        tr._translations["en"]["greet"] = "Hello {name}"
        tr.set_language("en")
        assert t("greet", name="World") == "Hello World"

    def test_format_error_returns_unformatted(self) -> None:
        """Eksik kwarg → format hatası → ham string dönsün."""
        tr = Translator.instance()
        tr._translations["en"]["greet"] = "Hello {name}"
        tr.set_language("en")
        # 'name' yok — KeyError yakalanıp ham string dönmeli
        assert t("greet", wrong="x") == "Hello {name}"


# =====================================================================
# Singleton
# =====================================================================
class TestSingleton:
    def test_instance_returns_same_object(self) -> None:
        a = Translator.instance()
        b = Translator.instance()
        assert a is b
