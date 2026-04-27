"""SSH default credentials probe — tests default passwords on port 22."""

from __future__ import annotations

from pentra.core.service_probes.base import ServiceProbeBase
from pentra.i18n import t
from pentra.models import Finding, Severity

_DEFAULT_CREDS: tuple[tuple[str, str], ...] = (
    ("root", "root"),
    ("admin", "admin"),
    ("pi", "raspberry"),
)


class SshDefaultCredsProbe(ServiceProbeBase):
    default_ports: tuple[int, ...] = (22,)
    name: str = "ssh_default_creds"
    description_key: str = "probe.service.ssh.description"
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
                    allow_agent=False,
                    look_for_keys=False,
                )
                transport = client.get_transport()
                remote_version = ""
                if transport is not None:
                    try:
                        remote_version = transport.remote_version or ""
                    except Exception:  # noqa: BLE001
                        pass

                banner_display = remote_version[:80] or t("common.unknown")

                return [
                    Finding(
                        scanner_name="network_scanner",
                        severity=Severity.HIGH,
                        title=t(
                            "finding.ssh.default_creds.title",
                            user=username, port=port,
                        ),
                        description=t(
                            "finding.ssh.default_creds.desc",
                            user=username, password=password, banner=banner_display,
                        ),
                        target=f"{host}:{port}",
                        remediation=t(
                            "finding.ssh.default_creds.remediation", user=username,
                        ),
                        evidence=self._evidence(
                            host=host, port=port,
                            why_vulnerable=t(
                                "finding.ssh.default_creds.evidence",
                                user=username, password=password,
                            ),
                            extra={
                                "username": username,
                                "remote_version": remote_version[:120],
                            },
                        ),
                    ),
                ]
            except AuthenticationException:
                continue
            except (NoValidConnectionsError, OSError):
                return []
            except SSHException:
                return []
            except Exception:  # noqa: BLE001
                return []
            finally:
                try:
                    client.close()
                except Exception:  # noqa: BLE001
                    pass

        return []
