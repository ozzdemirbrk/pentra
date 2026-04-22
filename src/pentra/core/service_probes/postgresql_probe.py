"""PostgreSQL default credentials probe — port 5432'de varsayılan parola testi.

En fazla 2 kombinasyon denenir (`postgres:postgres`, `postgres:''`). Kabul
edilirse CRITICAL bulgu.
"""

from __future__ import annotations

from pentra.core.service_probes.base import ServiceProbeBase
from pentra.models import Finding, Severity

_DEFAULT_CREDS: tuple[tuple[str, str], ...] = (
    ("postgres", "postgres"),
    ("postgres", ""),
)


class PostgresDefaultCredsProbe(ServiceProbeBase):
    default_ports: tuple[int, ...] = (5432,)
    name: str = "postgres_default_creds"
    description: str = "PostgreSQL varsayılan parola kontrolü"
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
                # Bağlandık — version al, kopart
                with conn.cursor() as cur:
                    cur.execute("SELECT version()")
                    version_row = cur.fetchone()
                version = (
                    str(version_row[0]).split(",")[0]
                    if version_row else "bilinmiyor"
                )
                return [
                    Finding(
                        scanner_name="network_scanner",
                        severity=Severity.CRITICAL,
                        title=f"PostgreSQL varsayılan parola kabul ediliyor — {username}@{port}",
                        description=(
                            f"PostgreSQL sunucusuna `{username}:{password or '(boş)'}` "
                            f"bilgileriyle başarıyla bağlanıldı (sunucu: {version[:80]}). "
                            f"Saldırgan tüm şemaları okuyabilir, DROP/ALTER ile veri kaybına "
                            f"yol açabilir, uzantılar sayesinde sunucuya komut "
                            f"çalıştırabilir (`COPY ... TO PROGRAM`). Varsayılan parolayla "
                            f"üretim PostgreSQL çalıştırmak kritik bir yapılandırma hatasıdır."
                        ),
                        target=f"{host}:{port}",
                        remediation=(
                            "ACİL: `ALTER USER postgres WITH PASSWORD '<güçlü_parola>';` "
                            "ile parolayı değiştirin. `pg_hba.conf` içinde uzak bağlantılar "
                            "için `md5` veya `scram-sha-256` auth metodunu zorunlu kılın. "
                            "`postgresql.conf` içinde `listen_addresses = 'localhost'` ile "
                            "yalnızca localhost'a bağlayın — uzak erişim gerekiyorsa güvenlik "
                            "duvarıyla belirli IP'ler için izin verin."
                        ),
                        evidence=self._evidence(
                            host=host, port=port,
                            why_vulnerable=f"user={username} password={password or '(boş)'} ile bağlantı başarılı",
                            extra={"postgres_version": version[:120], "username": username},
                        ),
                    ),
                ]
            except OperationalError:
                # Auth hatası veya bağlantı sorunu — sonraki creds'i dene
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
