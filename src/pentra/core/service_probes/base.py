"""ServiceProbeBase — bir port üzerinde auth/yapılandırma testi.

NetworkScanner açık port bulunca, o porta tanımlı `ServiceProbeBase`
örneği varsa `probe(host, port)` çağırır. Probe sadece kanıt üreten
tek istek gönderir, veri çekmez.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from pentra.i18n import t
from pentra.models import Finding


class ServiceProbeBase(ABC):
    """Bir servisin auth durumunu kanıtlayan hafif probe."""

    #: Bu probe'un çalıştığı varsayılan port numaraları
    default_ports: tuple[int, ...] = ()

    #: Audit log'da kullanılan kısa ad (ör. "redis_auth")
    name: str = ""

    #: UI'da gösterilen açıklama için i18n anahtarı
    description_key: str = ""

    #: Bağlantı timeout (saniye)
    timeout: float = 5.0

    @property
    def description(self) -> str:
        """Aktif dile çevrilmiş, insan-okunur açıklama."""
        return t(self.description_key) if self.description_key else ""

    @abstractmethod
    def probe(self, host: str, port: int) -> list[Finding]:
        """Servise bağlan, auth durumunu tespit et, bulguları döndür.

        Args:
            host: Hedef IP veya hostname (scope_validator ile doğrulanmış)
            port: TCP port numarası

        Returns:
            Bulgu listesi. Servis auth istiyorsa (veya erişilemezse) boş liste.
            Auth açık ise CRITICAL severity'li Finding.
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
        """Standart evidence dict oluşturur."""
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
