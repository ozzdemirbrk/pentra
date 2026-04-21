"""ServiceProbeBase — bir port üzerinde auth/yapılandırma testi.

NetworkScanner açık port bulunca, o porta tanımlı `ServiceProbeBase`
örneği varsa `probe(host, port)` çağırır. Probe sadece kanıt üreten
tek istek gönderir, veri çekmez.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from pentra.models import Finding


class ServiceProbeBase(ABC):
    """Bir servisin auth durumunu kanıtlayan hafif probe."""

    #: Bu probe'un çalıştığı varsayılan port numaraları
    default_ports: tuple[int, ...] = ()

    #: Audit log'da kullanılan kısa ad (ör. "redis_auth")
    name: str = ""

    #: Türkçe insan-okunur açıklama (UI'da gösterilir)
    description: str = ""

    #: Bağlantı timeout (saniye)
    timeout: float = 5.0

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
