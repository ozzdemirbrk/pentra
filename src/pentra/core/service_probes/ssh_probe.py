"""SSH default credentials probe — port 22'de varsayılan parola testi.

En fazla 3 kombinasyon (`root:root`, `admin:admin`, `pi:raspberry`) denenir.
Kabul edilirse HIGH bulgu — CRITICAL değil, çünkü probe tek başına veri
çekmedi (ama shell erişimi anlamına gelir, çok tehlikeli).

**Seviye 2 kuralları:**
    - 3 deneme max (fail2ban tetiklememek için)
    - Her bağlantı auth başarılıysa hemen kopart
    - Shell komut çalıştırma YASAK (invoke_shell, exec_command kullanılmaz)
    - SFTP, port forwarding YASAK

**Uyarı:** Bazı SSH sunucuları (fail2ban, fail2ban-benzeri) başarısız denemeden
sonra IP'yi bloklayabilir. Probe bunu mümkün olduğunca az tetikler.
"""

from __future__ import annotations

from pentra.core.service_probes.base import ServiceProbeBase
from pentra.models import Finding, Severity

_DEFAULT_CREDS: tuple[tuple[str, str], ...] = (
    ("root", "root"),
    ("admin", "admin"),
    ("pi", "raspberry"),   # Raspberry Pi klasik default (eski Raspbian)
)


class SshDefaultCredsProbe(ServiceProbeBase):
    default_ports: tuple[int, ...] = (22,)
    name: str = "ssh_default_creds"
    description: str = "SSH varsayılan parola kontrolü"
    timeout: float = 6.0

    def probe(self, host: str, port: int) -> list[Finding]:
        try:
            import paramiko  # type: ignore[import-not-found]
            from paramiko.ssh_exception import (  # type: ignore[import-not-found]
                AuthenticationException,
                NoValidConnectionsError,
                SSHException,
            )
        except ImportError:
            return []

        for username, password in _DEFAULT_CREDS:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(
                    hostname=host,
                    port=port,
                    username=username,
                    password=password,
                    timeout=self.timeout,
                    auth_timeout=self.timeout,
                    banner_timeout=self.timeout,
                    allow_agent=False,   # ssh-agent anahtarları kullanma
                    look_for_keys=False, # Ev dizinindeki anahtarları arama
                )
                # Bağlantı başarılı — ek hiçbir şey yapma, hemen kopart
                transport = client.get_transport()
                remote_version = ""
                if transport is not None:
                    try:
                        remote_version = transport.remote_version or ""
                    except Exception:  # noqa: BLE001
                        pass

                return [
                    Finding(
                        scanner_name="network_scanner",
                        severity=Severity.HIGH,
                        title=f"SSH varsayılan parola kabul ediliyor — {username}@{port}",
                        description=(
                            f"SSH sunucusuna `{username}:{password}` ile bağlanıldı "
                            f"(banner: {remote_version[:80] or 'bilinmiyor'}). Saldırgan "
                            f"shell açıp komut çalıştırabilir, sistem bilgilerini okuyabilir, "
                            f"yan sistemlere hareket edebilir (lateral movement). SSH brute-force "
                            f"saldırıları internette en yaygın saldırı türüdür; varsayılan "
                            f"parolayla SSH açık tutmak tüm sunucunun ele geçirilmesi demektir."
                        ),
                        target=f"{host}:{port}",
                        remediation=(
                            "ACİL: `passwd {username}` ile kullanıcının parolasını güçlü "
                            "(12+ karakter, karışık) biriyle değiştirin. Daha iyisi: "
                            "**parolayla SSH girişini tamamen kapatın**, sadece SSH key kullanın "
                            "(`PasswordAuthentication no` in `/etc/ssh/sshd_config`). "
                            "Ayrıca `PermitRootLogin no` ile root girişini devre dışı bırakın, "
                            "`fail2ban` yükleyin, SSH portunu değiştirin (22 → 22xxx) — "
                            "otomatik tarama yüzeyini küçültmek için."
                        ).format(username=username),
                        evidence=self._evidence(
                            host=host, port=port,
                            why_vulnerable=f"{username}:{password} ile SSH bağlantısı kuruldu",
                            extra={
                                "username": username,
                                "remote_version": remote_version[:120],
                            },
                        ),
                    ),
                ]
            except AuthenticationException:
                # Parola yanlış — sonraki creds'i dene (bu normal)
                continue
            except (NoValidConnectionsError, OSError):
                # Bağlantı hiç kurulamadı — SSH kapalı veya erişilemez
                return []
            except SSHException:
                # Protokol hatası — durdur
                return []
            except Exception:  # noqa: BLE001
                return []
            finally:
                try:
                    client.close()
                except Exception:  # noqa: BLE001
                    pass

        return []
