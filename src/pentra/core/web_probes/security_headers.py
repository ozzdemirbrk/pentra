"""Security Headers probe — HTTP yanıt header'larında kritik güvenlik ayarlarını kontrol eder.

Tek GET isteği gönderir, response header'larını analiz eder.
Sunucuda hiçbir değişiklik yapmaz, tamamen pasif (Seviye 2'nin en hafif probe'u).
"""

from __future__ import annotations

import requests

from pentra.core.web_probes.base import WebProbeBase
from pentra.models import Finding, Severity


# ---------------------------------------------------------------------
# Beklenen header'lar ve severity'leri
# ---------------------------------------------------------------------
_REQUIRED_HEADERS: dict[str, tuple[Severity, str, str]] = {
    # header_name → (severity, title, description+remediation)
    "Strict-Transport-Security": (
        Severity.MEDIUM,
        "HSTS eksik",
        "Strict-Transport-Security (HSTS) header'ı yanıtta yok. "
        "Bu header olmadan tarayıcı HTTPS'ten HTTP'ye düşürme saldırılarına açık olur. "
        "Önerilen değer: `max-age=31536000; includeSubDomains` (sadece HTTPS sitesinde).",
    ),
    "Content-Security-Policy": (
        Severity.MEDIUM,
        "CSP eksik",
        "Content-Security-Policy (CSP) header'ı yok. CSP, XSS saldırılarına karşı "
        "en etkili tarayıcı seviyesinde savunmadır. Başlangıç değeri: "
        "`default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'`",
    ),
    "X-Frame-Options": (
        Severity.LOW,
        "X-Frame-Options eksik (clickjacking koruması)",
        "X-Frame-Options header'ı yok. Bu header'sız sayfa başka bir sitede "
        "iframe'e gömülüp clickjacking saldırısında kullanılabilir. "
        "Önerilen: `DENY` veya `SAMEORIGIN`.",
    ),
    "X-Content-Type-Options": (
        Severity.LOW,
        "X-Content-Type-Options eksik (MIME sniffing)",
        "X-Content-Type-Options header'ı yok. Tarayıcıların content-type'ı "
        "tahmin etmesini engellemek için bu header'ı `nosniff` olarak ayarlayın.",
    ),
    "Referrer-Policy": (
        Severity.LOW,
        "Referrer-Policy eksik",
        "Referrer-Policy header'ı yok. Kullanıcının hangi sayfadan geldiği "
        "bilgisi başka sitelere sızar. Önerilen: `strict-origin-when-cross-origin`.",
    ),
}

# Server header sızıntısı (versiyon açığa çıkaran) — INFO seviyesi
_LEAKY_HEADERS: tuple[str, ...] = ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version")


class SecurityHeadersProbe(WebProbeBase):
    name: str = "security_headers"
    description: str = "HTTP yanıt header'larında eksik güvenlik ayarları tespiti"

    def probe(self, url: str, session: requests.Session) -> list[Finding]:
        findings: list[Finding] = []

        try:
            response = session.get(url, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException as e:
            # Ağ hatası — sessiz geç, WebScanner üst katmanda günceller
            return [
                Finding(
                    scanner_name="web_scanner",
                    severity=Severity.INFO,
                    title=f"{self.name}: Bağlantı başarısız",
                    description=f"Siteye bağlanılamadı: {e}",
                    target=url,
                ),
            ]

        is_https = url.lower().startswith("https://")

        # ---- Eksik güvenlik header'ları ----
        for header_name, (severity, title, description) in _REQUIRED_HEADERS.items():
            # HSTS sadece HTTPS sitelerde anlamlıdır
            if header_name == "Strict-Transport-Security" and not is_https:
                continue

            if header_name not in response.headers:
                findings.append(
                    Finding(
                        scanner_name="web_scanner",
                        severity=severity,
                        title=title,
                        description=description,
                        target=url,
                        remediation=self._remediation_for(header_name),
                        evidence=self._build_evidence(
                            request_method="GET",
                            request_path=url,
                            response_status=response.status_code,
                            why_vulnerable=f"{header_name} header'ı yanıtta yok",
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
                        title=f"Versiyon sızıntısı: {leaky}",
                        description=(
                            f"Sunucu `{leaky}: {value}` header'ını yanıtta dönüyor. "
                            "Saldırgan hedef yazılımın versiyonunu öğrenip ona özel "
                            "CVE'leri deneyebilir. Bu header'ı gizlemek güvenliği azaltmaz "
                            "ama keşif yüzeyini küçültür."
                        ),
                        target=url,
                        remediation=(
                            f"Web sunucusu yapılandırmasından `{leaky}` header'ını kaldırın. "
                            f"Nginx: `server_tokens off;` · Apache: `ServerTokens Prod`"
                        ),
                        evidence=self._build_evidence(
                            request_method="GET",
                            request_path=url,
                            response_status=response.status_code,
                            why_vulnerable=f"{leaky}: {value}",
                        ),
                    ),
                )

        # ---- HTTPS zorunluluğu ----
        if not is_https:
            findings.append(
                Finding(
                    scanner_name="web_scanner",
                    severity=Severity.HIGH,
                    title="HTTP üzerinden sunuluyor (şifresiz)",
                    description=(
                        "Site HTTP üzerinden sunuluyor. Tüm trafik (parolalar, çerezler, "
                        "form verileri) ağı dinleyen saldırgan tarafından okunabilir. "
                        "Günümüzde modern tarayıcılar da HTTP siteleri 'Güvenli Değil' "
                        "olarak işaretliyor."
                    ),
                    target=url,
                    remediation=(
                        "Sertifikayı Let's Encrypt (ücretsiz) ile alın, sunucuda HTTPS'e "
                        "yönlendirme kurun (301 redirect) ve HSTS header'ı ekleyin."
                    ),
                    evidence=self._build_evidence(
                        request_method="GET",
                        request_path=url,
                        response_status=response.status_code,
                        why_vulnerable="URL şeması http://",
                    ),
                ),
            )

        return findings

    @staticmethod
    def _remediation_for(header_name: str) -> str:
        """Her header için tek satırlık Türkçe onarım önerisi."""
        return {
            "Strict-Transport-Security":
                "Sunucu yapılandırmasına ekleyin: "
                "`Strict-Transport-Security: max-age=31536000; includeSubDomains`",
            "Content-Security-Policy":
                "Önce raporlama modunda başlayın: "
                "`Content-Security-Policy-Report-Only: default-src 'self'`, "
                "sonra gerçek CSP'ye geçin.",
            "X-Frame-Options":
                "Ekleyin: `X-Frame-Options: SAMEORIGIN` "
                "(veya modern alternatif CSP `frame-ancestors 'self'`)",
            "X-Content-Type-Options":
                "Ekleyin: `X-Content-Type-Options: nosniff`",
            "Referrer-Policy":
                "Ekleyin: `Referrer-Policy: strict-origin-when-cross-origin`",
        }.get(header_name, "Sunucu yapılandırmasında bu header'ı ekleyin.")
