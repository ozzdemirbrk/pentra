"""MongoDB auth check — port 27017'de parolasız erişim kontrolü."""

from __future__ import annotations

from pentra.core.service_probes.base import ServiceProbeBase
from pentra.i18n import t
from pentra.models import Finding, Severity


class MongoDbAuthProbe(ServiceProbeBase):
    default_ports: tuple[int, ...] = (27017, 27018, 27019)
    name: str = "mongodb_auth"
    description_key: str = "probe.service.mongodb.description"
    timeout: float = 5.0

    def probe(self, host: str, port: int) -> list[Finding]:
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
            databases = client.list_database_names()
            db_count = len(databases)
            return [
                Finding(
                    scanner_name="network_scanner",
                    severity=Severity.CRITICAL,
                    title=t("finding.mongodb.auth_open.title", port=port),
                    description=t("finding.mongodb.auth_open.desc", count=db_count),
                    target=f"{host}:{port}",
                    remediation=t("finding.mongodb.auth_open.remediation"),
                    evidence=self._evidence(
                        host=host, port=port,
                        why_vulnerable=t(
                            "finding.mongodb.auth_open.evidence", count=db_count,
                        ),
                    ),
                ),
            ]
        except OperationFailure as e:
            if "authentication" in str(e).lower():
                return []
            return []
        except (ConnectionFailure, ServerSelectionTimeoutError, OSError):
            return []
        except Exception:  # noqa: BLE001
            return []
        finally:
            if client is not None:
                try:
                    client.close()
                except Exception:  # noqa: BLE001
                    pass
