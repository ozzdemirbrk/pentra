"""MySQL default credentials probe — tests default passwords on port 3306."""

from __future__ import annotations

from pentra.core.service_probes.base import ServiceProbeBase
from pentra.i18n import t
from pentra.models import Finding, Severity

# (user, password) — the two most common defaults
_DEFAULT_CREDS: tuple[tuple[str, str], ...] = (
    ("root", ""),
    ("root", "root"),
)


class MysqlDefaultCredsProbe(ServiceProbeBase):
    default_ports: tuple[int, ...] = (3306,)
    name: str = "mysql_default_creds"
    description_key: str = "probe.service.mysql.description"
    timeout: float = 5.0

    def probe(self, host: str, port: int) -> list[Finding]:
        try:
            import pymysql  # type: ignore[import-not-found]
            from pymysql.err import OperationalError  # type: ignore[import-not-found]
        except ImportError:
            return []

        for username, password in _DEFAULT_CREDS:
            conn = None
            try:
                conn = pymysql.connect(
                    host=host,
                    port=port,
                    user=username,
                    password=password,
                    connect_timeout=int(self.timeout),
                    read_timeout=int(self.timeout),
                    charset="utf8mb4",
                )
                with conn.cursor() as cur:
                    cur.execute("SELECT VERSION()")
                    version_row = cur.fetchone()
                version = str(version_row[0]) if version_row else t("common.unknown")
                pwd_display = password or t("common.empty")
                return [
                    Finding(
                        scanner_name="network_scanner",
                        severity=Severity.CRITICAL,
                        title=t(
                            "finding.mysql.default_creds.title",
                            user=username, port=port,
                        ),
                        description=t(
                            "finding.mysql.default_creds.desc",
                            user=username, password=pwd_display, version=version,
                        ),
                        target=f"{host}:{port}",
                        remediation=t("finding.mysql.default_creds.remediation"),
                        evidence=self._evidence(
                            host=host, port=port,
                            why_vulnerable=t(
                                "finding.mysql.default_creds.evidence",
                                user=username, password=pwd_display,
                            ),
                            extra={"mysql_version": version, "username": username},
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
