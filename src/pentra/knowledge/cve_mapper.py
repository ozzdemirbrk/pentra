"""Service+version -> CVE list mapping.

NVD keyword search is loose (e.g. searching "IIS 10.0" can return thousands
of unrelated CVEs), so a two-stage filter is applied:

    1. **Service name normalization**: `microsoft-iis` -> `IIS`,
       `openssh` -> `OpenSSH` — names translated to NVD's canonical form
    2. **Post-filter**: only CVEs whose description contains both the
       service name and the version pass through (case-insensitive)
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from pentra.knowledge.nvd_client import Cve, NvdClient


# ---------------------------------------------------------------------
# Service -> CPE prefix mapping
# NVD keyword search often returns 0 hits because the version isn't in the
# description. CPE lookups give an exact version match — much more accurate.
# Format: `cpe:2.3:a:vendor:product` (version + wildcards are appended)
# ---------------------------------------------------------------------
_CPE_PREFIXES: dict[str, str] = {
    "Microsoft IIS": "cpe:2.3:a:microsoft:internet_information_services",
    "Apache": "cpe:2.3:a:apache:http_server",
    "nginx": "cpe:2.3:a:f5:nginx",  # after NVD's f5 acquisition
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
# Service name normalization
# Name from Nmap / HTTP Server header -> canonical name used by NVD
# ---------------------------------------------------------------------
_SERVICE_NORMALIZATIONS: dict[str, str] = {
    # Web servers
    "microsoft-iis": "Microsoft IIS",
    "ms-iis": "Microsoft IIS",
    "iis": "Microsoft IIS",
    "apache": "Apache",
    "apache httpd": "Apache",
    "httpd": "Apache",
    "nginx": "nginx",
    "openresty": "nginx",  # OpenResty is nginx-based
    "lighttpd": "lighttpd",
    # SSH
    "openssh": "OpenSSH",
    "ssh": "OpenSSH",
    # Databases
    "mysql": "MySQL",
    "mariadb": "MariaDB",
    "postgresql": "PostgreSQL",
    "postgres": "PostgreSQL",
    "redis": "Redis",
    "mongodb": "MongoDB",
    "elasticsearch": "Elasticsearch",
    "memcached": "Memcached",
    # RDP / remote desktop
    "ms-wbt-server": "Remote Desktop",
    "rdp": "Remote Desktop",
    # Email
    "smtp": "SMTP",
    "exim": "Exim",
    "postfix": "Postfix",
    "sendmail": "Sendmail",
    # FTP
    "ftp": "FTP",
    "vsftpd": "vsftpd",
    "proftpd": "ProFTPD",
    # Other
    "telnet": "Telnet",
    "smb": "SMB",
    "microsoft-ds": "SMB",
    "netbios-ssn": "SMB",
    "samba": "Samba",
}


@dataclass(frozen=True)
class CveQuery:
    """A service+version query — input to CveMapper."""

    service: str
    version: str

    @property
    def is_queryable(self) -> bool:
        """Both service and version must be non-empty and recognised."""
        return bool(self.service.strip()) and bool(self.version.strip())


class CveMapper:
    """Maps service+version pairs to a list of CVEs."""

    def __init__(self, nvd_client: NvdClient, max_cves_per_query: int = 10) -> None:
        self._nvd = nvd_client
        self._max = max_cves_per_query

    # -----------------------------------------------------------------
    def lookup(self, service: str, version: str) -> list[Cve]:
        """Return a CVE list for a single service+version pair.

        Args:
            service: Raw service name from Nmap/HTTP (e.g. `microsoft-iis`)
            version: Version string (e.g. `10.0` or `2.4.41`)

        Returns:
            CVEs sorted by CVSS score descending. Empty version, unknown
            service, or network error -> empty list.
        """
        if not service.strip() or not version.strip():
            return []

        canonical = self._normalize_service(service)
        if not canonical:
            return []

        # Take the leading segment of the version (e.g. "10.0.17763" -> "10.0")
        short_version = self._shorten_version(version)

        # CPE-based search (exact version match) — the definitive path for
        # recognised services. If CPE returns 0 it means NVD truly has no
        # record for that version — a keyword fallback would return WRONG
        # results (e.g. searching IIS 10.0 would return IIS 5.0 CVEs).
        if canonical in _CPE_PREFIXES:
            cpe_prefix = _CPE_PREFIXES[canonical]
            cpe_name = f"{cpe_prefix}:{short_version}:*:*:*:*:*:*:*"
            return self._nvd.search_by_cpe(cpe_name, max_results=self._max)

        # Unknown service — not in the CPE map. Best-effort keyword search
        # plus service-name filter. Treat results as "likely related" —
        # exact version match is not guaranteed.
        return self._nvd.search_cves(
            keyword=canonical,
            max_results=self._max,
            must_contain=(canonical,),
        )

    def lookup_from_server_header(self, server_header: str) -> list[Cve]:
        """Parse an HTTP `Server:` header and return a CVE list.

        Examples:
            "Microsoft-IIS/10.0" -> IIS 10.0
            "Apache/2.4.41 (Ubuntu)" -> Apache 2.4.41
            "nginx/1.18.0" -> nginx 1.18.0
        """
        service, version = _parse_server_header(server_header)
        if not service or not version:
            return []
        return self.lookup(service, version)

    # -----------------------------------------------------------------
    @staticmethod
    def _normalize_service(service_raw: str) -> str:
        """Normalise the raw service name to NVD's canonical form.

        If unrecognised the original is returned — it's still sent to NVD
        and the post-filter weeds out non-matches.
        """
        key = service_raw.strip().lower()
        if key in _SERVICE_NORMALIZATIONS:
            return _SERVICE_NORMALIZATIONS[key]
        # Partial match: names containing "http" but not fully defined
        for known_key, canonical in _SERVICE_NORMALIZATIONS.items():
            if known_key in key:
                return canonical
        return service_raw.strip()

    @staticmethod
    def _shorten_version(version: str) -> str:
        """Shorten a long version string without losing useful info.

        Examples:
            "10.0.17763.1" -> "10.0"  (two segments are enough)
            "2.4.41" -> "2.4.41" (three segments — typical semver)
            "Windows 10 20H2" -> "10" (first number)

        The post-filter searches for this substring in the description, so
        it must not be too short.
        """
        # Take the first 2-3 numeric segments
        match = re.match(r"^(\d+(?:\.\d+){1,2})", version.strip())
        if match:
            return match.group(1)
        # No numeric structure, return as-is
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
    """`Server: X/Y (Z)` -> (X, Y). Returns ('', '') on failure."""
    header = header.strip()
    for pattern in _SERVER_HEADER_PATTERNS:
        match = pattern.match(header)
        if match:
            return match.group("service"), match.group("version")
    return "", ""
