"""Reflected XSS probe — benign payload'un yanıta kaçışsız yansımasını tespit eder."""

from __future__ import annotations

import secrets
from urllib.parse import urlencode

import requests

from pentra.core.web_probes.base import WebProbeBase
from pentra.i18n import t
from pentra.models import Finding, Severity

_PARAMS_TO_TEST: tuple[str, ...] = (
    "q", "query", "search", "s", "keyword", "term",
    "name", "user", "username", "email", "message",
    "comment", "text", "content", "title", "subject",
    "return", "returnTo", "redirect", "next", "url",
)


def _make_canary() -> str:
    return "pentra" + secrets.token_hex(4)


def _build_payloads(canary: str) -> tuple[tuple[str, str], ...]:
    return (
        (f"<script>/*{canary}*/</script>", f"<script>/*{canary}*/</script>"),
        (f"<xss{canary}>", f"<xss{canary}>"),
        (f"\"><xss{canary}>", f"><xss{canary}>"),
        (f"';//{canary}", f"';//{canary}"),
    )


class XssProbe(WebProbeBase):
    name: str = "xss_reflected"
    description_key: str = "probe.web.xss.description"
    timeout: float = 8.0

    def probe(self, url: str, session: requests.Session) -> list[Finding]:
        findings: list[Finding] = []
        reported_params: set[str] = set()

        # --- Echo-fallback tespiti ---
        if self._site_echoes_random_param(url, session):
            return [
                Finding(
                    scanner_name="web_scanner",
                    severity=Severity.INFO,
                    title=t("finding.web.xss_echo_fallback.title"),
                    description=t("finding.web.xss_echo_fallback.desc"),
                    target=url,
                    remediation=t("finding.web.xss_echo_fallback.remediation"),
                    evidence=self._build_evidence(
                        request_method="GET",
                        request_path=url,
                        why_vulnerable="echo-fallback detected",
                    ),
                ),
            ]

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

                findings.append(
                    Finding(
                        scanner_name="web_scanner",
                        severity=Severity.HIGH,
                        title=t("finding.web.xss.title", param=param),
                        description=t(
                            "finding.web.xss.desc", param=param, payload=payload,
                        ),
                        target=full_url,
                        remediation=t("finding.web.xss.remediation"),
                        evidence=self._build_evidence(
                            request_method="GET",
                            request_path=full_url,
                            response_status=response.status_code,
                            response_snippet=self._extract_context(
                                response.text, reflection_marker,
                            ),
                            why_vulnerable=(
                                f"Payload `{reflection_marker}` reflected unescaped"
                            ),
                            extra={"payload": payload, "param": param, "canary": canary},
                        ),
                    ),
                )
                reported_params.add(param)
                break

        # --- Threshold kontrolü ---
        threshold = max(1, int(len(_PARAMS_TO_TEST) * 0.5))
        if len(findings) >= threshold:
            return [
                Finding(
                    scanner_name="web_scanner",
                    severity=Severity.INFO,
                    title=t(
                        "finding.web.xss_threshold_exceeded.title",
                        reflected_count=len(findings),
                    ),
                    description=t(
                        "finding.web.xss_threshold_exceeded.desc",
                        reflected_count=len(findings),
                        tested_count=len(_PARAMS_TO_TEST),
                    ),
                    target=url,
                    remediation=t("finding.web.xss_threshold_exceeded.remediation"),
                    evidence=self._build_evidence(
                        request_method="GET",
                        request_path=url,
                        why_vulnerable=(
                            f"{len(findings)}/{len(_PARAMS_TO_TEST)} params reflected "
                            f"— 50% threshold exceeded"
                        ),
                    ),
                ),
            ]

        return findings

    def _site_echoes_random_param(
        self, url: str, session: requests.Session,
    ) -> bool:
        """Rastgele param ile echo-fallback tespiti."""
        probe_param = f"pentra{secrets.token_hex(3)}"
        canary = _make_canary()
        test_payloads = [
            f"<script>/*{canary}*/</script>",
            f"<xss{canary}>",
            f"';//{canary}",
        ]

        for payload in test_payloads:
            test_url = self._build_url_with_param(url, probe_param, payload)
            try:
                response = session.get(
                    test_url, timeout=self.timeout, allow_redirects=False,
                )
            except requests.RequestException:
                continue

            if payload in response.text:
                return True

        return False

    # -----------------------------------------------------------------
    @staticmethod
    def _is_reflected_unescaped(body: str, marker: str) -> bool:
        return marker in body

    @staticmethod
    def _extract_context(body: str, marker: str) -> str:
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
