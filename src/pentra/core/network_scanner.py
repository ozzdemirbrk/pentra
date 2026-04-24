"""Ağ tarayıcısı — python-nmap ile port ve servis tespiti.

Faz 2 MVP: localhost'ta top 100 portu TCP connect tarama.

Derinlikler:
    QUICK    → top 100 port, servis adları (TCP connect, hızlı)
    STANDARD → top 1000 port + servis versiyonu
    DEEP     → tüm portlar + versiyon + OS + script varsayılanları

Windows'ta `-sT` (TCP connect) kullanılır — admin/Npcap gerekmez; localhost için
yeterince hızlıdır. Diğer modlar Npcap + UAC gerektirebilir (Faz 3+ için).
"""

from __future__ import annotations

import ipaddress

from pentra.core.scanner_base import ScannerBase
from pentra.core.service_probes.base import ServiceProbeBase
from pentra.core.service_probes.elasticsearch_probe import ElasticsearchAuthProbe
from pentra.core.service_probes.mongodb_probe import MongoDbAuthProbe
from pentra.core.service_probes.mysql_probe import MysqlDefaultCredsProbe
from pentra.core.service_probes.postgresql_probe import PostgresDefaultCredsProbe
from pentra.core.service_probes.redis_probe import RedisAuthProbe
from pentra.core.service_probes.ssh_probe import SshDefaultCredsProbe
from pentra.i18n import t
from pentra.models import Finding, ScanDepth, Severity, Target, TargetType

# Port → Service probe eşlemesi. Açık port bulunduğunda ilgili probe çalışır.
def _default_service_probes() -> dict[int, ServiceProbeBase]:
    """Her port için kayıtlı probe (port numarası → probe örneği)."""
    registry: dict[int, ServiceProbeBase] = {}
    probe_classes: tuple[type[ServiceProbeBase], ...] = (
        # Auth-open checks (parolasız erişim)
        RedisAuthProbe,
        ElasticsearchAuthProbe,
        MongoDbAuthProbe,
        # Default credentials checks (varsayılan parola — max 2-3 deneme)
        MysqlDefaultCredsProbe,
        PostgresDefaultCredsProbe,
        SshDefaultCredsProbe,
    )
    for probe_cls in probe_classes:
        probe_instance = probe_cls()
        for port in probe_instance.default_ports:
            registry[port] = probe_instance
    return registry

# python-nmap'in nmap.exe'yi arayacağı yollar — Windows + Unix.
_NMAP_SEARCH_PATHS: tuple[str, ...] = (
    "nmap",
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
    "/usr/bin/nmap",
    "/usr/local/bin/nmap",
    "/opt/local/bin/nmap",
)

# Port → (severity, i18n anahtarı) — anahtar çalıştırma zamanında çevrilir
_RISKY_PORTS: dict[int, tuple[Severity, str]] = {
    21: (Severity.LOW, "note.network.port.ftp"),
    23: (Severity.MEDIUM, "note.network.port.telnet"),
    25: (Severity.LOW, "note.network.port.smtp"),
    135: (Severity.LOW, "note.network.port.rpc"),
    139: (Severity.LOW, "note.network.port.netbios"),
    445: (Severity.MEDIUM, "note.network.port.smb"),
    1433: (Severity.MEDIUM, "note.network.port.mssql"),
    3306: (Severity.MEDIUM, "note.network.port.mysql"),
    3389: (Severity.HIGH, "note.network.port.rdp"),
    5432: (Severity.MEDIUM, "note.network.port.postgres"),
    5900: (Severity.HIGH, "note.network.port.vnc"),
    6379: (Severity.HIGH, "note.network.port.redis"),
    27017: (Severity.HIGH, "note.network.port.mongodb"),
}


class NetworkScanner(ScannerBase):
    """python-nmap tabanlı port/servis tarayıcı."""

    def __init__(self, *args, service_probes=None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._service_probes: dict[int, ServiceProbeBase] = (
            service_probes if service_probes is not None else _default_service_probes()
        )

    @property
    def scanner_name(self) -> str:
        return "network_scanner"

    # -----------------------------------------------------------------
    # ScannerBase._do_scan implementasyonu
    # -----------------------------------------------------------------
    def _do_scan(self, target: Target, depth: ScanDepth) -> None:
        try:
            import nmap  # type: ignore[import-not-found]
        except ImportError as e:
            self._emit_error(t("error.network.nmap_missing", error=str(e)))
            return

        arguments = self._build_nmap_args(depth, target)
        self._emit_progress(5, t("progress.network.nmap_args", arguments=arguments))

        try:
            scanner = nmap.PortScanner(nmap_search_path=_NMAP_SEARCH_PATHS)
        except nmap.PortScannerError as e:
            self._emit_error(t("error.network.nmap_not_found", error=str(e)))
            return

        if not self._throttle(packets=1):
            return  # iptal edildi

        network_warning = _estimate_scan_time(target, depth)
        if network_warning:
            self._emit_progress(10, network_warning)
        else:
            self._emit_progress(10, t("progress.network.scanning", target=target.value))

        try:
            scanner.scan(hosts=target.value, arguments=arguments)
        except nmap.PortScannerError as e:
            self._emit_error(t("error.network.scan_failed", error=str(e)))
            return

        self._emit_progress(60, t("progress.network.processing_results"))

        hosts = scanner.all_hosts()
        if not hosts:
            self._emit_progress(100, t("progress.network.no_response"))
            return

        findings = self._extract_findings(scanner, target, hosts)
        for f in findings:
            self._emit_finding(f)
            if self._cancelled:
                return

        self._run_service_probes(hosts, scanner)

        self._emit_progress(
            100,
            t("progress.network.scan_complete", count=len(findings)),
        )

    # -----------------------------------------------------------------
    def _run_service_probes(self, hosts: list[str], scanner: object) -> None:
        """Açık portlardan kayıtlı probe'u olanlara auth kontrolü yap."""
        if not self._service_probes:
            return

        for host in hosts:
            if self._cancelled:
                return
            host_result = scanner[host]  # type: ignore[index]
            for proto in host_result.all_protocols():
                ports_dict = host_result[proto]
                for port in sorted(ports_dict.keys()):
                    state = ports_dict[port].get("state", "")
                    if state != "open":
                        continue
                    probe = self._service_probes.get(port)
                    if probe is None:
                        continue

                    self._emit_progress(
                        95,
                        t(
                            "progress.network.service_probe",
                            probe=probe.name, host=host, port=port,
                        ),
                    )
                    if not self._throttle(1):
                        return
                    try:
                        probe_findings = probe.probe(host, port)
                    except Exception as e:  # noqa: BLE001
                        self._emit_error(
                            t("error.network.probe_error", probe=probe.name, error=str(e)),
                        )
                        continue
                    for pf in probe_findings:
                        self._emit_finding(pf)
                        if self._cancelled:
                            return

    # -----------------------------------------------------------------
    # Yardımcılar
    # -----------------------------------------------------------------
    @staticmethod
    def _build_nmap_args(depth: ScanDepth, target: Target | None = None) -> str:
        """Derinliğe göre nmap argümanlarını oluşturur."""
        is_network_scan = (
            target is not None
            and target.target_type in (TargetType.LOCAL_NETWORK, TargetType.IP_RANGE)
        )
        host_discovery = "" if is_network_scan else "-Pn"

        match depth:
            case ScanDepth.QUICK:
                return f"-sT -F --open -T4 {host_discovery} -sV --version-intensity 2".strip()
            case ScanDepth.STANDARD:
                return f"-sT -sV --open -T4 {host_discovery}".strip()
            case ScanDepth.DEEP:
                # Tüm portlar + versiyon + güvenli NSE script'leri + OS tespiti.
                # -O yönetici/Npcap ister; haksa atlar, diğer sonuçlar çalışır.
                # --script=safe destructive olmayan vuln/discovery script'leri içerir.
                return f"-sT -sV -O --script=safe --open -T4 -p- {host_discovery}".strip()

    def _extract_findings(
        self,
        scanner: object,
        target: Target,
        hosts: list[str],
    ) -> list[Finding]:
        """nmap sonuçlarını Finding nesnelerine çevirir."""
        findings: list[Finding] = []

        for host in hosts:
            host_result = scanner[host]  # type: ignore[index]

            for proto in host_result.all_protocols():
                ports_dict = host_result[proto]
                port_count = len(ports_dict)

                for idx, port in enumerate(sorted(ports_dict.keys())):
                    port_info = ports_dict[port]

                    state: str = port_info.get("state", "unknown")
                    if state != "open":
                        continue

                    service: str = port_info.get("name", "unknown")
                    version: str = port_info.get("version", "")
                    product: str = port_info.get("product", "")

                    severity, note_key = _RISKY_PORTS.get(port, (Severity.INFO, ""))
                    extra_note = (
                        " " + t(note_key) if note_key else ""
                    )

                    version_part = (
                        t(
                            "finding.network.open_port.version_part",
                            product=product,
                            version=version,
                        )
                        if (product or version)
                        else ""
                    )

                    title = t(
                        "finding.network.open_port.title",
                        port=port, proto=proto, service=service,
                    )
                    description = t(
                        "finding.network.open_port.desc",
                        host=host, port=port, service=service,
                        version_part=version_part, extra_note=extra_note,
                    )

                    remediation = _build_remediation(port, service)

                    cve_ids: tuple[str, ...] = ()
                    cve_details: list[dict[str, object]] = []
                    if self._cve_mapper is not None and (product or service) and version:
                        try:
                            cves = self._cve_mapper.lookup(
                                service=product or service, version=version,
                            )
                            cve_ids = tuple(c.cve_id for c in cves[:5])
                            cve_details = [
                                {
                                    "id": c.cve_id,
                                    "cvss": c.cvss_score,
                                    "severity": c.severity,
                                    "description": c.description,
                                    "url": c.nvd_url,
                                }
                                for c in cves[:5]
                            ]
                            severity = self._escalate_severity_by_cves(
                                severity, cves,
                            )
                        except Exception:  # noqa: BLE001
                            pass

                    findings.append(
                        Finding(
                            scanner_name=self.scanner_name,
                            severity=severity,
                            title=title,
                            description=description,
                            target=f"{host}:{port}",
                            cve_ids=cve_ids,
                            remediation=remediation,
                            evidence={
                                "port": port,
                                "proto": proto,
                                "service": service,
                                "product": product,
                                "version": version,
                                "cves": cve_details,
                            },
                        ),
                    )

                    percent = 60 + int(40 * (idx + 1) / max(port_count, 1))
                    self._emit_progress(
                        percent,
                        t("progress.network.port_processed", host=host, port=port),
                    )

        return findings

    @staticmethod
    def _escalate_severity_by_cves(
        base: Severity,
        cves: "list",
    ) -> Severity:
        """CVE'lerin en kritik CVSS'i port base severity'sinden yüksekse yükselt."""
        if not cves:
            return base
        max_cvss = max((c.cvss_score or 0.0) for c in cves)
        cvss_tier: Severity
        if max_cvss >= 9.0:
            cvss_tier = Severity.CRITICAL
        elif max_cvss >= 7.0:
            cvss_tier = Severity.HIGH
        elif max_cvss >= 4.0:
            cvss_tier = Severity.MEDIUM
        elif max_cvss > 0:
            cvss_tier = Severity.LOW
        else:
            return base

        order = {
            Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
            Severity.HIGH: 3, Severity.CRITICAL: 4,
        }
        return base if order[base] >= order[cvss_tier] else cvss_tier


def _estimate_scan_time(target: Target, depth: ScanDepth) -> str:
    """CIDR hedefler için kullanıcıya süre tahmini mesajı döndürür."""
    if target.target_type not in (TargetType.LOCAL_NETWORK, TargetType.IP_RANGE):
        return ""

    try:
        network = ipaddress.ip_network(target.value, strict=False)
    except ValueError:
        return ""

    host_count = network.num_addresses
    if host_count <= 1:
        return ""

    if host_count <= 256:
        minutes_est = t("label.network.time.short")
    elif host_count <= 4096:
        minutes_est = t("label.network.time.medium")
    else:
        minutes_est = t("label.network.time.long")

    depth_text = {
        ScanDepth.QUICK: t("label.network.depth.quick"),
        ScanDepth.STANDARD: t("label.network.depth.standard"),
        ScanDepth.DEEP: t("label.network.depth.deep"),
    }.get(depth, "")

    return t(
        "progress.network.time_estimate",
        network=str(network),
        host_count=host_count,
        depth_text=depth_text,
        minutes_est=minutes_est,
    )


def _build_remediation(port: int, service: str) -> str:
    """Port için onarım önerisi — i18n üzerinden."""
    del service  # şimdilik sadece port bazlı
    if port in _RISKY_PORTS:
        return t("finding.network.open_port.remediation")
    return t("finding.network.generic_port.remediation")
