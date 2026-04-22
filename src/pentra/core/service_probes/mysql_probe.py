"""MySQL default credentials probe — port 3306'da varsayılan parola testi.

En fazla 2 kombinasyon denenir (`root:''`, `root:root`). Kabul edilirse
CRITICAL bulgu. Reddedilirse hemen bırakılır — fail2ban tetiklememek için.

**Seviye 2 kuralları:**
    - 2 deneme max (zincir saldırısı yok)
    - Bağlantı kurulduğunda tek `SELECT VERSION()` çalıştırılır (kanıt için)
    - Sonrasında koparılır
    - Veri çekme / tablo listesi / schema inceleme YASAK
"""

from __future__ import annotations

from pentra.core.service_probes.base import ServiceProbeBase
from pentra.models import Finding, Severity

# (user, password) — en bilinen iki default, fazla deneme lockout getirir
_DEFAULT_CREDS: tuple[tuple[str, str], ...] = (
    ("root", ""),
    ("root", "root"),
)


class MysqlDefaultCredsProbe(ServiceProbeBase):
    default_ports: tuple[int, ...] = (3306,)
    name: str = "mysql_default_creds"
    description: str = "MySQL varsayılan parola kontrolü"
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
                # Bağlandık — kanıt için version al, sonra kopart
                with conn.cursor() as cur:
                    cur.execute("SELECT VERSION()")
                    version_row = cur.fetchone()
                version = str(version_row[0]) if version_row else "bilinmiyor"
                return [
                    Finding(
                        scanner_name="network_scanner",
                        severity=Severity.CRITICAL,
                        title=f"MySQL varsayılan parola kabul ediliyor — {username}@{port}",
                        description=(
                            f"MySQL sunucusuna `{username}:{password or '(boş)'}` bilgileriyle "
                            f"başarıyla bağlanıldı (sunucu sürümü: {version}). Saldırgan tüm "
                            f"veritabanlarını okuyabilir, ALTER/DROP ile yok edebilir, "
                            f"`SELECT ... INTO OUTFILE` ile sunucuya dosya yazabilir "
                            f"(write_privilege varsa). MySQL'in üretim sisteminde varsayılan "
                            f"parolayla çalışması ciddi bir yapılandırma hatasıdır."
                        ),
                        target=f"{host}:{port}",
                        remediation=(
                            "ACİL: `ALTER USER 'root'@'%' IDENTIFIED BY '<güçlü_parola>';` "
                            "ile parolayı değiştirin. Uzaktan root erişimi gerekmiyorsa "
                            "`DROP USER 'root'@'%';` ile uzak root hesabını silin. "
                            "`bind-address = 127.0.0.1` ayarıyla MySQL'i sadece localhost'a "
                            "bağlayın. `mysql_secure_installation` scriptini çalıştırın "
                            "(anonim kullanıcıları, test DB'sini temizler)."
                        ),
                        evidence=self._evidence(
                            host=host, port=port,
                            why_vulnerable=f"user={username} password={password or '(boş)'} ile bağlantı başarılı",
                            extra={"mysql_version": version, "username": username},
                        ),
                    ),
                ]
            except OperationalError:
                # 1045 Access denied veya timeout — bu credential'ı atla, sonrakini dene
                continue
            except Exception:  # noqa: BLE001
                # Beklenmeyen hata — devam etme, lockout riski
                break
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:  # noqa: BLE001
                        pass

        return []
