"""Security Headers probe — HTTP yanıt header'larında kritik güvenlik ayarlarını kontrol eder.

Tek GET isteği gönderir, response header'larını analiz eder.
Sunucuda hiçbir değişiklik yapmaz, tamamen pasif (Seviye 2'nin en hafif probe'u).
"""

from __future__ import annotations

import requests

from pentra.core.web_probes.base import WebProbeBase
from pentra.i18n import t
from pentra.models import Finding, Severity


# Eksik security header'lar için meta — severity ve i18n anahtarları
_REQUIRED_HEADERS: dict[str, tuple[Severity, str, str, str]] = {
    # header_name → (severity, title_key, desc_key, remediation_key)
    "Strict-Transport-Security": (
        Severity.MEDIUM,
        "finding.web.hsts_missing.title",
        "finding.web.hsts_missing.desc",
        "finding.web.hsts_missing.remediation",
    ),
    "Content-Security-Policy": (
        Severity.MEDIUM,
        "finding.web.csp_missing.title",
        "finding.web.csp_missing.desc",
        "finding.web.csp_missing.remediation",
    ),
    "X-Frame-Options": (
        Severity.LOW,
        "finding.web.xfo_missing.title",
        "finding.web.xfo_missing.desc",
        "finding.web.xfo_missing.remediation",
    ),
    "X-Content-Type-Options": (
        Severity.LOW,
        "finding.web.xcto_missing.title",
        "finding.web.xcto_missing.desc",
        "finding.web.xcto_missing.remediation",
    ),
    "Referrer-Policy": (
        Severity.LOW,
        "finding.web.referrer_policy_missing.title",
        "finding.web.referrer_policy_missing.desc",
        "finding.web.referrer_policy_missing.remediation",
    ),
}

_LEAKY_HEADERS: tuple[str, ...] = ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version")


class SecurityHeadersProbe(WebProbeBase):
    name: str = "security_headers"
    description_key: str = "probe.web.security_headers.description"

    def probe(self, url: str, session: requests.Session) -> list[Finding]:
        findings: list[Finding] = []

        try:
            response = session.get(url, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException as e:
            return [
                Finding(
                    scanner_name="web_scanner",
                    severity=Severity.INFO,
                    title=t(
                        "finding.web.header_connection_failed.title", probe=self.name,
                    ),
                    description=t(
                        "finding.web.header_connection_failed.desc", error=str(e),
                    ),
                    target=url,
                ),
            ]

        is_https = url.lower().startswith("https://")

        # ---- Eksik güvenlik header'ları ----
        for header_name, (severity, title_key, desc_key, rem_key) in _REQUIRED_HEADERS.items():
            # HSTS sadece HTTPS sitelerde anlamlıdır
            if header_name == "Strict-Transport-Security" and not is_https:
                continue

            if header_name not in response.headers:
                findings.append(
                    Finding(
                        scanner_name="web_scanner",
                        severity=severity,
                        title=t(title_key),
                        description=t(desc_key),
                        target=url,
                        remediation=t(rem_key),
                        evidence=self._build_evidence(
                            request_method="GET",
                            request_path=url,
                            response_status=response.status_code,
                            why_vulnerable=t(
                                "evidence.web.header_missing", header=header_name,
                            ),
                        ),
                    ),
                )

        # ---- Versiyon sızdıran header'lar ----
        for leaky in _LEAKY_HEADERS:
            if leaky in response.headers:
                value = response.headers[leaky]
                findings.append(
                    Finding(
                        scanner_name="web_scanner",
                        severity=Severity.INFO,
                        title=t("finding.web.version_leak.title", header=leaky),
                        description=t(
                            "finding.web.version_leak.desc",
                            header=leaky, value=value,
                        ),
                        target=url,
                        remediation=t(
                            "finding.web.version_leak.remediation", header=leaky,
                        ),
                        evidence=self._build_evidence(
                            request_method="GET",
                            request_path=url,
                            response_status=response.status_code,
                            why_vulnerable=t(
                                "evidence.web.version_leak",
                                header=leaky, value=value,
                            ),
                            extra={
                                "leaked_header": leaky,
                                "leaked_value": value,
                            },
                        ),
                    ),
                )

        # ---- HTTPS zorunluluğu ----
        if not is_https:
            findings.append(
                Finding(
                    scanner_name="web_scanner",
                    severity=Severity.HIGH,
                    title=t("finding.web.http_not_https.title"),
                    description=t("finding.web.http_not_https.desc"),
                    target=url,
                    remediation=t("finding.web.http_not_https.remediation"),
                    evidence=self._build_evidence(
                        request_method="GET",
                        request_path=url,
                        response_status=response.status_code,
                        why_vulnerable=t("evidence.web.http_not_https"),
                    ),
                ),
            )

        return findings
