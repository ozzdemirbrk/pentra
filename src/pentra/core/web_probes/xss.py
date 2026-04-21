"""Reflected XSS probe — benign payload'un yanıta kaçışsız yansımasını tespit eder.

Her parametre için özgün bir "canary" token içeren payload gönderilir.
Yanıt gövdesinde bu token:
    - `<tag>TOKEN</tag>` şeklinde kaçışsız geri geliyorsa → XSS zafiyeti
    - `&lt;tag&gt;TOKEN&lt;/tag&gt;` şeklinde escape edilmişse → güvenli
    - Hiç görünmüyorsa → parametre yanıta yansımıyor, test başarısız

**Seviye 2 kuralı**: Payload benign (sadece yorum içeren script tag'i + canary).
Gerçek cookie çalma, DOM manipülasyonu, session kaçırma YOKTUR.
"""

from __future__ import annotations

import secrets
from urllib.parse import urlencode

import requests

from pentra.core.web_probes.base import WebProbeBase
from pentra.models import Finding, Severity

# Yanıta yansıma ihtimali yüksek parametreler
_PARAMS_TO_TEST: tuple[str, ...] = (
    "q", "query", "search", "s", "keyword", "term",
    "name", "user", "username", "email", "message",
    "comment", "text", "content", "title", "subject",
    "return", "returnTo", "redirect", "next", "url",
)

# Pattern generator: her test için benzersiz canary token
# Amaç: response'ta canary görmezsek "echo yok" diyebilelim
def _make_canary() -> str:
    return "pentra" + secrets.token_hex(4)


# Test edilecek kaçış kontekstleri — her biri farklı sanitizer hatasını yakalar
def _build_payloads(canary: str) -> tuple[tuple[str, str], ...]:
    """Her payload için (payload, reflection_check) döndürür.

    reflection_check: response'ta bu string varsa kaçışsız yansımış demektir.
    """
    return (
        # Klasik: <script> tag reflection
        (f"<script>/*{canary}*/</script>", f"<script>/*{canary}*/</script>"),
        # HTML tag reflection (daha az yaygın filtrelenir)
        (f"<xss{canary}>", f"<xss{canary}>"),
        # Attribute break — class/value içinde
        (f"\"><xss{canary}>", f"><xss{canary}>"),
        # JavaScript context — tek tırnak kırma
        (f"';//{canary}", f"';//{canary}"),
    )


class XssProbe(WebProbeBase):
    name: str = "xss_reflected"
    description: str = "Yansıtılmış (Reflected) XSS tespit"
    timeout: float = 8.0

    def probe(self, url: str, session: requests.Session) -> list[Finding]:
        findings: list[Finding] = []
        reported_params: set[str] = set()

        for param in _PARAMS_TO_TEST:
            if param in reported_params:
                continue

            canary = _make_canary()
            payloads = _build_payloads(canary)

            for payload, reflection_marker in payloads:
                full_url = self._build_url_with_param(url, param, payload)

                try:
                    response = session.get(
                        full_url, timeout=self.timeout, allow_redirects=False,
                    )
                except requests.RequestException:
                    continue

                if not self._is_reflected_unescaped(response.text, reflection_marker):
                    continue

                # Kanıtlı — yansıma var + kaçış yok
                findings.append(
                    Finding(
                        scanner_name="web_scanner",
                        severity=Severity.HIGH,
                        title=f"Reflected XSS: `{param}` parametresi",
                        description=(
                            f"`{param}` parametresine gönderilen HTML/JS payload yanıta "
                            f"kaçışsız (unescaped) olarak geri döndü. Bu, saldırganın "
                            f"özel hazırlanmış bir link oluşturup kullanıcıya tıklattığında "
                            f"kullanıcının tarayıcısında JavaScript çalıştırabileceği "
                            f"anlamına gelir (session çerezi çalma, phishing, DOM manipülasyonu). "
                            f"Tetikleyici payload: `{payload}`"
                        ),
                        target=full_url,
                        remediation=(
                            "Kullanıcı girdisini HTML'e yazmadan önce **context-aware "
                            "escaping** uygulayın: HTML body → `html_escape`, "
                            "attribute → `attr_escape`, JS string → `js_escape`. "
                            "Modern framework'lerde (React, Vue, Jinja2 autoescape) "
                            "bu varsayılan olarak açıktır — `{{ variable }}` otomatik "
                            "escape eder, `{{ variable | safe }}` tehlikelidir. "
                            "Ek savunma olarak CSP header'ı ekleyin: "
                            "`Content-Security-Policy: default-src 'self'; "
                            "script-src 'self'`"
                        ),
                        evidence=self._build_evidence(
                            request_method="GET",
                            request_path=full_url,
                            response_status=response.status_code,
                            response_snippet=self._extract_context(
                                response.text, reflection_marker,
                            ),
                            why_vulnerable=(
                                f"Payload `{reflection_marker}` yanıtta kaçışsız bulundu"
                            ),
                            extra={"payload": payload, "param": param, "canary": canary},
                        ),
                    ),
                )
                reported_params.add(param)
                break  # Bir kanıt yeter

        return findings

    # -----------------------------------------------------------------
    @staticmethod
    def _is_reflected_unescaped(body: str, marker: str) -> bool:
        """Payload yanıtta tam ve escape edilmemiş halde var mı."""
        if marker not in body:
            return False
        # Aynı karakterler escape edilmiş olarak DA geçiyorsa bu bir tesadüf —
        # yine de unescaped form varsa zafiyet sayılır
        # (çoğu durumda escape varsa unescaped form hiç olmaz)
        return True

    @staticmethod
    def _extract_context(body: str, marker: str) -> str:
        """Yansımayı saran ~150 karakterlik bağlam."""
        idx = body.find(marker)
        if idx == -1:
            return body[:200]
        start = max(0, idx - 50)
        end = min(len(body), idx + len(marker) + 100)
        return body[start:end]

    @staticmethod
    def _build_url_with_param(base_url: str, param: str, payload: str) -> str:
        separator = "&" if "?" in base_url else "?"
        encoded = urlencode({param: payload})
        return f"{base_url}{separator}{encoded}"
