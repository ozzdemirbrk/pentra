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

from pentra.core.scanner_base import ScannerBase
from pentra.core.service_probes.base import ServiceProbeBase
from pentra.core.service_probes.elasticsearch_probe import ElasticsearchAuthProbe
from pentra.core.service_probes.mongodb_probe import MongoDbAuthProbe
from pentra.core.service_probes.redis_probe import RedisAuthProbe
from pentra.models import Finding, ScanDepth, Severity, Target

# Port → Service probe eşlemesi. Açık port bulunduğunda ilgili probe çalışır.
def _default_service_probes() -> dict[int, ServiceProbeBase]:
    """Her port için kayıtlı probe (port numarası → probe örneği)."""
    registry: dict[int, ServiceProbeBase] = {}
    for probe_cls in (RedisAuthProbe, ElasticsearchAuthProbe, MongoDbAuthProbe):
        probe_instance = probe_cls()
        for port in probe_instance.default_ports:
            registry[port] = probe_instance
    return registry

# python-nmap'in nmap.exe'yi arayacağı yollar — Windows + Unix.
# Installer PATH'e eklemeyi unutmuş/kullanıcı yeni terminal açmamış olsa da çalışır.
_NMAP_SEARCH_PATHS: tuple[str, ...] = (
    "nmap",
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
    "/usr/bin/nmap",
    "/usr/local/bin/nmap",
    "/opt/local/bin/nmap",
)

# Bilgi amaçlı riskli port haritası (çok temel, CVE eşleşmesi Faz 5'te zenginleşir)
_RISKY_PORTS: dict[int, tuple[Severity, str]] = {
    21: (Severity.LOW, "FTP — şifrelenmemiş dosya transferi, anonim erişim olabilir"),
    23: (Severity.MEDIUM, "Telnet — parola düz metin gönderilir, SSH kullanın"),
    25: (Severity.LOW, "SMTP — yanlış yapılandırılırsa open relay olabilir"),
    135: (Severity.LOW, "Windows RPC — dışarıya kapalı olmalı"),
    139: (Severity.LOW, "NetBIOS — paylaşım bilgisi sızdırabilir"),
    445: (Severity.MEDIUM, "SMB — EternalBlue gibi ciddi zaafiyet geçmişi var"),
    1433: (Severity.MEDIUM, "MSSQL — dışarıya açıksa saldırı yüzeyini artırır"),
    3306: (Severity.MEDIUM, "MySQL — dışarıya açıksa risk"),
    3389: (Severity.HIGH, "RDP — yaygın brute-force hedefi, güçlü parola + MFA şart"),
    5432: (Severity.MEDIUM, "PostgreSQL — dışarıya açıksa risk"),
    5900: (Severity.HIGH, "VNC — zayıf parola şifreleme, dışarıya açılmamalı"),
    6379: (Severity.HIGH, "Redis — varsayılan auth yok, erişim kısıtlanmalı"),
    27017: (Severity.HIGH, "MongoDB — geçmişte auth'suz yayınlarla büyük sızıntılar"),
}


class NetworkScanner(ScannerBase):
    """python-nmap tabanlı port/servis tarayıcı."""

    def __init__(self, *args, service_probes=None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # Port → ServiceProbeBase eşlemesi; None ise varsayılan (Redis/ES/Mongo)
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
        # Lazy import — test ortamı mock'layabilsin diye
        try:
            import nmap  # type: ignore[import-not-found]
        except ImportError as e:
            self._emit_error(
                f"python-nmap kütüphanesi yüklü değil: {e}. "
                f"pip install python-nmap ile kurun.",
            )
            return

        arguments = self._build_nmap_args(depth)
        self._emit_progress(5, f"Nmap argümanları: {arguments}")

        try:
            scanner = nmap.PortScanner(nmap_search_path=_NMAP_SEARCH_PATHS)
        except nmap.PortScannerError as e:
            self._emit_error(
                f"Nmap kurulu değil veya bulunamadı: {e}. "
                f"https://nmap.org/download.html adresinden kurun.",
            )
            return

        if not self._throttle(packets=1):
            return  # iptal edildi

        self._emit_progress(10, f"{target.value} taranıyor...")

        try:
            scanner.scan(hosts=target.value, arguments=arguments)
        except nmap.PortScannerError as e:
            self._emit_error(f"Tarama başarısız: {e}")
            return

        self._emit_progress(60, "Sonuçlar işleniyor...")

        hosts = scanner.all_hosts()
        if not hosts:
            self._emit_progress(
                100,
                "Hedef yanıt vermedi — firewall kapalı olabilir veya cihaz erişilemez",
            )
            return

        findings = self._extract_findings(scanner, target, hosts)
        for f in findings:
            self._emit_finding(f)
            if self._cancelled:
                return

        # Service probe aşaması — açık DB portlarında auth kontrolü
        self._run_service_probes(hosts, scanner)

        self._emit_progress(
            100,
            f"Tarama tamamlandı — {len(findings)} bulgu",
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

                    self._emit_progress(95, f"Servis probe: {probe.name} → {host}:{port}")
                    if not self._throttle(1):
                        return
                    try:
                        probe_findings = probe.probe(host, port)
                    except Exception as e:  # noqa: BLE001
                        self._emit_error(f"{probe.name} hatası: {e}")
                        continue
                    for pf in probe_findings:
                        self._emit_finding(pf)
                        if self._cancelled:
                            return

    # -----------------------------------------------------------------
    # Yardımcılar
    # -----------------------------------------------------------------
    @staticmethod
    def _build_nmap_args(depth: ScanDepth) -> str:
        """Derinliğe göre nmap argümanlarını oluşturur."""
        match depth:
            case ScanDepth.QUICK:
                # TCP connect, top 100 port + servis/versiyon (hafif)
                return "-sT -F --open -T4 -Pn -sV --version-intensity 2"
            case ScanDepth.STANDARD:
                # Top 1000 port + tam servis/versiyon
                return "-sT -sV --open -T4 -Pn"
            case ScanDepth.DEEP:
                # Tam port, versiyon, OS, varsayılan scriptler
                return "-sT -sV -O --script=default --open -T4 -Pn"

    def _extract_findings(
        self,
        scanner: object,  # nmap.PortScanner; tip checker için object
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

                    severity, extra_note = _RISKY_PORTS.get(
                        port, (Severity.INFO, ""),
                    )

                    title = f"Açık port: {port}/{proto} ({service})"
                    description_parts = [
                        f"{host} üzerinde {port} numaralı TCP portu açık.",
                        f"Servis adı: {service}.",
                    ]
                    if product or version:
                        description_parts.append(
                            f"Yazılım: {product} {version}".strip(),
                        )
                    if extra_note:
                        description_parts.append(extra_note)

                    remediation = _build_remediation(port, service)

                    # CVE eşleştirme — mapper varsa ve versiyon biliniyorsa
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
                            # CVE varsa severity'yi yükselt
                            severity = self._escalate_severity_by_cves(
                                severity, cves,
                            )
                        except Exception:  # noqa: BLE001
                            # CVE lookup başarısız olsa bile tarama devam
                            pass

                    findings.append(
                        Finding(
                            scanner_name=self.scanner_name,
                            severity=severity,
                            title=title,
                            description=" ".join(description_parts),
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

                    # İlerleme yayını: portlar arasında yüzdeyi güncelle
                    percent = 60 + int(40 * (idx + 1) / max(port_count, 1))
                    self._emit_progress(percent, f"{host}:{port} işlendi")

        return findings

    @staticmethod
    def _escalate_severity_by_cves(
        base: Severity,
        cves: "list",
    ) -> Severity:
        """CVE'lerin en kritik CVSS'i port base severity'sinden yüksekse yükselt."""
        if not cves:
            return base
        # Maksimum CVSS skoru
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

        # Base ile CVSS tier'ın maksimumunu al
        order = {
            Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
            Severity.HIGH: 3, Severity.CRITICAL: 4,
        }
        return base if order[base] >= order[cvss_tier] else cvss_tier


def _build_remediation(port: int, service: str) -> str:
    """Her port için basit Türkçe onarım önerisi. Faz 5'te genişleyecek."""
    del service  # şimdilik sadece port bazlı, ileride servise göre zenginleşir
    if port in _RISKY_PORTS:
        return (
            f"Bu port gerçekten gerekli değilse kapatın. Gerekliyse güvenlik "
            f"duvarıyla yalnızca güvendiğiniz IP aralıklarına izin verin ve "
            f"servis yazılımının güncel sürümde olduğundan emin olun."
        )
    return (
        "Gerekli değilse portu kapatın. Güvenlik duvarında yalnızca "
        "belirli IP'lere izin verecek şekilde kısıtlayın."
    )
