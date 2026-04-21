"""Servis probe'ları — açık port üzerinde auth/yapılandırma kontrolü.

NetworkScanner port taraması yaptıktan sonra, bulduğu açık portların
bazıları için (veritabanı, admin arayüzü vb.) ek non-destructive probe
çalıştırılır. Örnek: Redis 6379 açıksa `PING` gönder, auth olmadan
yanıt veriyorsa CRITICAL bulgu.

Seviye 2 kurallarına tam uyum:
    - Tek seferlik bağlantı
    - Yalnızca auth durumunu kontrol (veri çekme YOK)
    - Bağlantı kopartılır
"""

from pentra.core.service_probes.base import ServiceProbeBase

__all__ = ["ServiceProbeBase"]
