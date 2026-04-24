"""WebProbeBase — tüm web probe'larının soyut temeli.

Her probe:
    - `name`: audit log'da ve rapor evidence'ında kullanılan kısa ad
    - `description`: Türkçe kısa açıklama (kullanıcı görür)
    - `probe(url, session)`: Gerçek test — Finding listesi döner

TASARIM KURALLARI (ihlal edilirse kod review'da red):
    1. probe() tek seferlik çalışır — aynı endpoint'e tekrar tekrar istek YASAK
    2. Gönderilen her isteğin timeout'u ≤ 10 sn olmalı
    3. Bağlantı kullanılmıyorsa kapat
    4. Finding.evidence dict'i içinde: request yolu, response status, kısa snippet
    5. Destructive payload YASAK — `DROP TABLE`, `rm -rf`, shell komutları vb.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

import requests

from pentra.i18n import t
from pentra.models import Finding


class WebProbeBase(ABC):
    """Tek bir web zafiyet kategorisi için non-destructive test."""

    # Alt sınıf zorunlu olarak üzerine yazar
    name: str = ""

    #: UI'da gösterilen açıklama için i18n anahtarı
    description_key: str = ""

    # Varsayılan HTTP timeout (saniye) — probe'lar override edebilir
    timeout: float = 10.0

    @property
    def description(self) -> str:
        """Aktif dile çevrilmiş, insan-okunur açıklama."""
        return t(self.description_key) if self.description_key else ""

    @abstractmethod
    def probe(self, url: str, session: requests.Session) -> list[Finding]:
        """Probe'u çalıştır, bulguları döndür.

        Args:
            url: Hedef URL (scope_validator tarafından doğrulanmış).
            session: Ortak `requests.Session` — UA, rate vb. önceden ayarlı.

        Returns:
            Bulgu listesi (boş liste = zafiyet yok / probe uygulanamadı).

        Hatalar:
            Network/timeout hataları probe tarafından yakalanmalı;
            WebScanner üst katmanda yutar. Ama `ValueError` gibi programlama
            hataları yukarı atılsın — test sırasında yakalanması için.
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
        """Standart evidence dict — her Finding için eşit format sağlar."""
        evidence: dict[str, object] = {
            "probe_name": self.name,
            "request": f"{request_method} {request_path}",
        }
        if response_status is not None:
            evidence["response_status"] = response_status
        if response_snippet:
            # Response snippet'i en fazla 200 karakter — kanıt için yeter
            evidence["response_snippet"] = response_snippet[:200]
        if why_vulnerable:
            evidence["why_vulnerable"] = why_vulnerable
        if extra:
            evidence.update(extra)
        return evidence
