"""Redis auth check — port 6379'da parolasız erişim kontrolü.

Redis RESP protokolüyle basit `PING` komutu gönderir. Yanıt `+PONG` ise
bağlantı auth gerektirmiyor demektir — **CRITICAL** bulgu.

Seviye 2 kuralları:
    - Tek PING, tek bağlantı
    - Veri okuma/yazma YOK (`KEYS *`, `CONFIG GET`, `GET` komutları YASAK)
    - Bağlantı hemen kopartılır
"""

from __future__ import annotations

import socket

from pentra.core.service_probes.base import ServiceProbeBase
from pentra.models import Finding, Severity

# RESP protokolü: *1\r\n$4\r\nPING\r\n  (tek elemanlı array)
_PING_COMMAND: bytes = b"*1\r\n$4\r\nPING\r\n"

# Parolasız Redis'in vereceği yanıt
_EXPECTED_OPEN: bytes = b"+PONG"

# Parola gerektirdiğinde veya korumada dönen hata işaretleri
_AUTH_REQUIRED_MARKERS: tuple[bytes, ...] = (
    b"NOAUTH Authentication required",
    b"DENIED Redis is running in protected mode",
    b"-ERR Client sent AUTH",
)


class RedisAuthProbe(ServiceProbeBase):
    default_ports: tuple[int, ...] = (6379,)
    name: str = "redis_auth"
    description: str = "Redis parola gerektirmeden erişim kontrolü"

    def probe(self, host: str, port: int) -> list[Finding]:
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                sock.sendall(_PING_COMMAND)
                response = sock.recv(256)  # PING yanıtı kısa — 256 bayt yeter
        except (OSError, socket.timeout):
            # Bağlantı başarısız → probe uygulanamadı (Redis olmayabilir)
            return []

        # Parola gerektirmiyor — kanıt bulundu
        if response.startswith(_EXPECTED_OPEN):
            return [
                Finding(
                    scanner_name="network_scanner",
                    severity=Severity.CRITICAL,
                    title=f"Redis parolasız erişilebilir — port {port}",
                    description=(
                        "Redis sunucusuna **parola olmadan** bağlanılabildi (PING → PONG). "
                        "Bu yapılandırmada saldırgan tüm anahtarları okuyabilir, silebilir, "
                        "`CONFIG SET dir /home/redis/.ssh` + `SAVE` ile SSH anahtar dosyaları "
                        "yazarak sunucuyu ele geçirebilir (`CVE-2022-0543` benzeri). "
                        "Gerçek dünyada en yaygın bulut sızıntı sebeplerinden biri."
                    ),
                    target=f"{host}:{port}",
                    remediation=(
                        "ACİL: Redis config'inde (`/etc/redis/redis.conf`) `requirepass <güçlü_parola>` "
                        "ve `bind 127.0.0.1` ayarlayın. Eğer uzaktan erişim gerekiyorsa güvenlik "
                        "duvarıyla sadece belirli IP'lere izin verin. TLS tercihen etkin (`tls-port`). "
                        "Redis 6+ için ACL (`aclfile`) kullanın."
                    ),
                    evidence=self._evidence(
                        host=host, port=port,
                        why_vulnerable="PING → +PONG yanıtı (auth gerekmeden)",
                        response_snippet=response.decode("latin-1"),
                    ),
                ),
            ]

        # Parola isteği veya protected mode yanıtı → güvenli
        return []
