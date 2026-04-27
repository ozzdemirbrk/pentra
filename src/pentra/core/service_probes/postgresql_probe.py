"""PostgreSQL default credentials probe — tests default passwords on port 5432."""

from __future__ import annotations

from pentra.core.service_probes.base import ServiceProbeBase
from pentra.i18n import t
from pentra.models import Finding, Severity

_DEFAULT_CREDS: tuple[tuple[str, str], ...] = (
    ("postgres", "postgres"),
    ("postgres", ""),
)


class PostgresDefaultCredsProbe(ServiceProbeBase):
    default_ports: tuple[int, ...] = (5432,)
    name: str = "postgres_default_creds"
    description_key: str = "probe.service.postgresql.description"
    timeout: float = 5.0

    def probe(self, host: str, port: int) -> list[Finding]:
        try:
            import psycopg2  # type: ignore[import-not-found]
            from psycopg2 import OperationalError  # type: ignore[import-not-found]
        except ImportError:
            return []

        for username, password in _DEFAULT_CREDS:
            conn = None
            try:
                conn = psycopg2.connect(
                    host=host,
                    port=port,
                    user=username,
                    password=password,
                    dbname="postgres",
                    connect_timeout=int(self.timeout),
                )
                with conn.cursor() as cur:
                    cur.execute("SELECT version()")
                    version_row = cur.fetchone()
                version = str(version_row[0]).split(",")[0] if version_row else t("common.unknown")
                pwd_display = password or t("common.empty")
                return [
                    Finding(
                        scanner_name="network_scanner",
                        severity=Severity.CRITICAL,
                        title=t(
                            "finding.postgresql.default_creds.title",
                            user=username,
                            port=port,
                        ),
                        description=t(
                            "finding.postgresql.default_creds.desc",
                            user=username,
                            password=pwd_display,
                            version=version[:80],
                        ),
                        target=f"{host}:{port}",
                        remediation=t("finding.postgresql.default_creds.remediation"),
                        evidence=self._evidence(
                            host=host,
                            port=port,
                            why_vulnerable=t(
                                "finding.postgresql.default_creds.evidence",
                                user=username,
                                password=pwd_display,
                            ),
                            extra={"postgres_version": version[:120], "username": username},
                        ),
                    ),
                ]
            except OperationalError:
                continue
            except Exception:  # noqa: BLE001
                break
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:  # noqa: BLE001
                        pass

        return []
