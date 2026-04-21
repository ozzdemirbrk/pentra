"""MongoDB auth check — port 27017'de parolasız erişim kontrolü.

pymongo ile anonim bağlantı kurup `list_database_names()` denenir:
    - Başarılı (auth isteme yok) → CRITICAL
    - Auth hatası (OperationFailure: "requires authentication") → korunuyor

MongoDB 3.6 öncesi varsayılan auth YOKTU — milyonlarca eski install açık.
Modern MongoDB'de `--auth` flag'i var ama yine yanlış yapılandırma sık.
"""

from __future__ import annotations

from pentra.core.service_probes.base import ServiceProbeBase
from pentra.models import Finding, Severity


class MongoDbAuthProbe(ServiceProbeBase):
    default_ports: tuple[int, ...] = (27017, 27018, 27019)
    name: str = "mongodb_auth"
    description: str = "MongoDB parola gerektirmeden erişim kontrolü"
    timeout: float = 5.0

    def probe(self, host: str, port: int) -> list[Finding]:
        # pymongo lazy import — kurulu değilse probe'u sessizce geç
        try:
            from pymongo import MongoClient  # type: ignore[import-not-found]
            from pymongo.errors import (
                ConnectionFailure,
                OperationFailure,
                ServerSelectionTimeoutError,
            )
        except ImportError:
            return []

        uri = f"mongodb://{host}:{port}/"
        client = None
        try:
            client = MongoClient(
                uri,
                serverSelectionTimeoutMS=int(self.timeout * 1000),
                socketTimeoutMS=int(self.timeout * 1000),
                connectTimeoutMS=int(self.timeout * 1000),
            )
            # auth istiyorsa burada OperationFailure atar
            databases = client.list_database_names()
            # Başarılı → auth YOK, CRITICAL
            db_count = len(databases)
            return [
                Finding(
                    scanner_name="network_scanner",
                    severity=Severity.CRITICAL,
                    title=f"MongoDB parolasız erişilebilir — port {port}",
                    description=(
                        "MongoDB sunucusuna **parola olmadan** bağlanıldı ve veritabanı "
                        "listesi alındı (toplam {count} DB görülüyor). Saldırgan tüm "
                        "koleksiyonları okuyabilir, silebilir (MongoDB ransomware saldırıları "
                        "bu yolla gerçekleşir). Public cloud'da açık MongoDB örneği 2017'den "
                        "beri en sık veri sızıntısı sebebidir."
                    ).format(count=db_count),
                    target=f"{host}:{port}",
                    remediation=(
                        "ACİL: MongoDB'yi `--auth` flag'i ile yeniden başlatın, admin kullanıcı "
                        "oluşturun (`db.createUser({...})`). `mongod.conf` içinde "
                        "`security.authorization: enabled` ayarlayın. Ayrıca `net.bindIp: 127.0.0.1` "
                        "ile yalnızca localhost'a bağlanmasını sağlayın — uzaktan gerekiyorsa "
                        "güvenlik duvarıyla kısıtlayın. Tüm mevcut DB içeriğini sızmış kabul edin."
                    ),
                    evidence=self._evidence(
                        host=host, port=port,
                        why_vulnerable=f"Anonim bağlantı + list_database_names() başarılı ({db_count} DB)",
                    ),
                ),
            ]
        except OperationFailure as e:
            # "requires authentication" → auth açık, iyi
            if "authentication" in str(e).lower():
                return []
            return []
        except (ConnectionFailure, ServerSelectionTimeoutError, OSError):
            # Bağlantı kurulamadı — MongoDB olmayabilir
            return []
        except Exception:  # noqa: BLE001 — pymongo çok çeşitli hata atabilir
            return []
        finally:
            if client is not None:
                try:
                    client.close()
                except Exception:  # noqa: BLE001
                    pass
