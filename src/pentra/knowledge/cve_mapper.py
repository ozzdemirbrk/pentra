"""Servis+versiyon → CVE listesi eşleştirme.

NVD keyword araması gevşek olduğundan (ör. "IIS 10.0" aranınca binlerce
alakasız CVE dönebiliyor), iki aşamalı filtre uygulanır:

    1. **Servis adı normalleştirme**: `microsoft-iis` → `IIS`, `openssh` → `OpenSSH`
       gibi NVD'nin kullandığı yaygın adlara çevrilir
    2. **Post-filter**: Sadece açıklaması hem servis adını hem versiyonu
       içeren CVE'ler döner (case-insensitive)
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from pentra.knowledge.nvd_client import Cve, NvdClient


# ---------------------------------------------------------------------
# Servis → CPE prefix eşlemesi
# NVD keyword araması çoğu zaman açıklamada versiyon geçmediği için 0 döner.
# CPE ile kesin versiyon eşleşmesi yaparız — çok daha doğru sonuç.
# Format: `cpe:2.3:a:vendor:product` (versiyon + wildcard'lar eklenecek)
# ---------------------------------------------------------------------
_CPE_PREFIXES: dict[str, str] = {
    "Microsoft IIS": "cpe:2.3:a:microsoft:internet_information_services",
    "Apache": "cpe:2.3:a:apache:http_server",
    "nginx": "cpe:2.3:a:f5:nginx",  # NVD f5 satın aldığından beri
    "OpenSSH": "cpe:2.3:a:openbsd:openssh",
    "MySQL": "cpe:2.3:a:oracle:mysql",
    "MariaDB": "cpe:2.3:a:mariadb:mariadb",
    "PostgreSQL": "cpe:2.3:a:postgresql:postgresql",
    "Redis": "cpe:2.3:a:redislabs:redis",
    "MongoDB": "cpe:2.3:a:mongodb:mongodb",
    "Elasticsearch": "cpe:2.3:a:elastic:elasticsearch",
    "lighttpd": "cpe:2.3:a:lighttpd:lighttpd",
    "vsftpd": "cpe:2.3:a:vsftpd_project:vsftpd",
    "ProFTPD": "cpe:2.3:a:proftpd:proftpd",
    "Exim": "cpe:2.3:a:exim:exim",
    "Postfix": "cpe:2.3:a:postfix:postfix",
    "Sendmail": "cpe:2.3:a:proofpoint:sendmail",
}


# ---------------------------------------------------------------------
# Servis adı normalleştirme
# Nmap / HTTP Server header'ındaki isim → NVD'nin kullandığı kanonik isim
# ---------------------------------------------------------------------
_SERVICE_NORMALIZATIONS: dict[str, str] = {
    # Web sunucular
    "microsoft-iis": "Microsoft IIS",
    "ms-iis": "Microsoft IIS",
    "iis": "Microsoft IIS",
    "apache": "Apache",
    "apache httpd": "Apache",
    "httpd": "Apache",
    "nginx": "nginx",
    "openresty": "nginx",  # OpenResty nginx tabanlı
    "lighttpd": "lighttpd",
    # SSH
    "openssh": "OpenSSH",
    "ssh": "OpenSSH",
    # Veritabanları
    "mysql": "MySQL",
    "mariadb": "MariaDB",
    "postgresql": "PostgreSQL",
    "postgres": "PostgreSQL",
    "redis": "Redis",
    "mongodb": "MongoDB",
    "elasticsearch": "Elasticsearch",
    "memcached": "Memcached",
    # RDP / uzak masaüstü
    "ms-wbt-server": "Remote Desktop",
    "rdp": "Remote Desktop",
    # E-posta
    "smtp": "SMTP",
    "exim": "Exim",
    "postfix": "Postfix",
    "sendmail": "Sendmail",
    # FTP
    "ftp": "FTP",
    "vsftpd": "vsftpd",
    "proftpd": "ProFTPD",
    # Diğer
    "telnet": "Telnet",
    "smb": "SMB",
    "microsoft-ds": "SMB",
    "netbios-ssn": "SMB",
    "samba": "Samba",
}


@dataclass(frozen=True)
class CveQuery:
    """Bir servis+versiyon sorgusu — CveMapper'a gelen girdi."""

    service: str
    version: str

    @property
    def is_queryable(self) -> bool:
        """Hem servis hem versiyon dolu ve tanınmış olmalı."""
        return bool(self.service.strip()) and bool(self.version.strip())


class CveMapper:
    """Servis+versiyon çiftlerini CVE listesine çevirir."""

    def __init__(self, nvd_client: NvdClient, max_cves_per_query: int = 10) -> None:
        self._nvd = nvd_client
        self._max = max_cves_per_query

    # -----------------------------------------------------------------
    def lookup(self, service: str, version: str) -> list[Cve]:
        """Tek bir servis+versiyon için CVE listesi döndürür.

        Args:
            service: Nmap/HTTP'den alınan ham servis adı (ör. `microsoft-iis`)
            version: Versiyon string'i (ör. `10.0` veya `2.4.41`)

        Returns:
            CVSS skoruna göre azalan sırada CVE listesi. Boş versiyon,
            tanınmayan servis veya ağ hatası → boş liste.
        """
        if not service.strip() or not version.strip():
            return []

        canonical = self._normalize_service(service)
        if not canonical:
            return []

        # Versiyonun başını al (bazıları "10.0.17763" gibi; "10.0" daha iyi eşleşir)
        short_version = self._shorten_version(version)

        # CPE-based search (tam versiyon eşleşmesi) — tanınmış servisler için
        # kesin ve tek doğru yol. CPE 0 dönerse, NVD'de gerçekten o versiyon
        # için kayıt yok demektir — keyword fallback YANLIŞ sonuç döndürür
        # (örn. IIS 10.0 sorunca IIS 5.0 CVE'leri gelir).
        if canonical in _CPE_PREFIXES:
            cpe_prefix = _CPE_PREFIXES[canonical]
            cpe_name = f"{cpe_prefix}:{short_version}:*:*:*:*:*:*:*"
            return self._nvd.search_by_cpe(cpe_name, max_results=self._max)

        # Tanınmayan servis — CPE haritasında yok. En iyi çaba olarak keyword
        # araması + servis adı filtresi. Sonuçlar "muhtemel ilgili" olarak
        # yorumlanmalı — versiyon eşleşmesi garanti değil.
        return self._nvd.search_cves(
            keyword=canonical,
            max_results=self._max,
            must_contain=(canonical,),
        )

    def lookup_from_server_header(self, server_header: str) -> list[Cve]:
        """HTTP `Server:` header'ını parse edip CVE listesi döndürür.

        Örnekler:
            "Microsoft-IIS/10.0" → IIS 10.0
            "Apache/2.4.41 (Ubuntu)" → Apache 2.4.41
            "nginx/1.18.0" → nginx 1.18.0
        """
        service, version = _parse_server_header(server_header)
        if not service or not version:
            return []
        return self.lookup(service, version)

    # -----------------------------------------------------------------
    @staticmethod
    def _normalize_service(service_raw: str) -> str:
        """Ham servis adını NVD kanonik formuna çevirir.

        Tanınmazsa orijinali döner — yine de NVD'ye gönderilir, post-filter
        eşleşmeleri eler.
        """
        key = service_raw.strip().lower()
        if key in _SERVICE_NORMALIZATIONS:
            return _SERVICE_NORMALIZATIONS[key]
        # Kısmi eşleşme: "http" içeren ama tam tanımlanmamış isimler
        for known_key, canonical in _SERVICE_NORMALIZATIONS.items():
            if known_key in key:
                return canonical
        return service_raw.strip()

    @staticmethod
    def _shorten_version(version: str) -> str:
        """Uzun versiyon string'ini kısaltır ama bilgi kaybetmez.

        Örnekler:
            "10.0.17763.1" → "10.0"  (2 parça yeter)
            "2.4.41" → "2.4.41" (3 parça — tipik semver)
            "Windows 10 20H2" → "10" (ilk sayı)

        Post-filter açıklamada bu substring'i arayacağı için çok kısa olmamalı.
        """
        # İlk 2-3 sayısal segmenti al
        match = re.match(r"^(\d+(?:\.\d+){1,2})", version.strip())
        if match:
            return match.group(1)
        # Sayısal yapı yok, olduğu gibi döndür
        return version.strip()


# ---------------------------------------------------------------------
# HTTP Server header parser
# ---------------------------------------------------------------------
_SERVER_HEADER_PATTERNS: tuple[re.Pattern[str], ...] = (
    # "Microsoft-IIS/10.0"
    re.compile(r"^(?P<service>[A-Za-z][\w-]*)/(?P<version>\d[\w.]*)", re.I),
    # "Apache/2.4.41 (Ubuntu)"
    re.compile(r"^(?P<service>[A-Za-z][\w-]*)\s*/\s*(?P<version>\d[\w.]*)", re.I),
)


def _parse_server_header(header: str) -> tuple[str, str]:
    """`Server: X/Y (Z)` → (X, Y). Başarısızlıkta ('', '')."""
    header = header.strip()
    for pattern in _SERVER_HEADER_PATTERNS:
        match = pattern.match(header)
        if match:
            return match.group("service"), match.group("version")
    return "", ""
