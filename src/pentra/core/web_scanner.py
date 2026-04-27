"""Web Scanner — runs Level 2 probes against URL targets.

Takes a URL, runs each registered probe in sequence, and emits findings
to the UI via Qt signals. Each probe focuses on one vulnerability
category (a WebProbeBase subclass) — adding a probe means writing a new class.
"""

from __future__ import annotations

import dataclasses

import requests

from pentra.core.scanner_base import ScannerBase
from pentra.core.web_probes.base import WebProbeBase
from pentra.core.web_probes.exposed_paths import ExposedPathsProbe
from pentra.core.web_probes.path_traversal import PathTraversalProbe
from pentra.core.web_probes.security_headers import SecurityHeadersProbe
from pentra.core.web_probes.sql_injection import SqlInjectionProbe
from pentra.core.web_probes.ssl_tls import SslTlsProbe
from pentra.core.web_probes.xss import XssProbe
from pentra.i18n import t
from pentra.models import Finding, ScanDepth, Severity, Target

# User-Agent — probes identifying themselves is an ethical norm
_USER_AGENT = (
    "Pentra/0.2 (+https://github.com/ozzdemirbrk/pentra; "
    "security-assessment scanner)"
)


class WebScanner(ScannerBase):
    """Scans URL targets — runs the registered probes in sequence."""

    @property
    def scanner_name(self) -> str:
        return "web_scanner"

    # -----------------------------------------------------------------
    def _do_scan(self, target: Target, depth: ScanDepth) -> None:
        probes = _select_probes(depth)
        if not probes:
            self._emit_progress(100, t("progress.web.no_probes"))
            return

        self._emit_progress(5, t("progress.web.scan_starting", target=target.value))

        session = requests.Session()
        session.headers.update({"User-Agent": _USER_AGENT})
        session.verify = True

        total = len(probes)
        total_findings = 0

        for idx, probe in enumerate(probes):
            if self._cancelled:
                return

            if not self._throttle(packets=1):
                return

            percent = 10 + int(85 * idx / total)
            self._emit_progress(
                percent,
                t(
                    "progress.web.probe_running",
                    index=idx + 1, total=total, probe=probe.description,
                ),
            )

            try:
                findings = probe.probe(target.value, session)
            except requests.RequestException as e:
                self._emit_progress(
                    percent,
                    t(
                        "progress.web.probe_network_error",
                        probe=probe.name, error=str(e),
                    ),
                )
                continue
            except Exception as e:  # noqa: BLE001
                self._emit_error(
                    t("error.web.probe_error", probe=probe.name, error=str(e)),
                )
                continue

            for f in findings:
                enriched = self._enrich_with_cves(f)
                self._emit_finding(enriched)
                total_findings += 1
                if self._cancelled:
                    return

        session.close()
        self._emit_progress(
            100,
            t("progress.web.scan_complete", count=total_findings),
        )

    # -----------------------------------------------------------------
    def _enrich_with_cves(self, finding: Finding) -> Finding:
        """Enrich Server-header leak findings with CVEs from NVD."""
        if self._cve_mapper is None:
            return finding

        # Marker on evidence — the security_headers probe sets this to
        # "Server" when the Server header leaks.
        if finding.evidence.get("leaked_header") != "Server":
            return finding

        header_value = str(finding.evidence.get("leaked_value", ""))
        if not header_value:
            return finding

        try:
            cves = self._cve_mapper.lookup_from_server_header(header_value)
        except Exception:  # noqa: BLE001
            return finding

        if not cves:
            return finding

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

        max_cvss = max((c.cvss_score or 0.0) for c in cves)
        if max_cvss >= 9.0:
            new_severity = Severity.CRITICAL
        elif max_cvss >= 7.0:
            new_severity = Severity.HIGH
        elif max_cvss >= 4.0:
            new_severity = Severity.MEDIUM
        else:
            new_severity = finding.severity

        new_evidence = dict(finding.evidence)
        new_evidence["cves"] = cve_details

        return dataclasses.replace(
            finding,
            severity=new_severity,
            cve_ids=cve_ids,
            evidence=new_evidence,
            title=t(
                "finding.web.title_with_cves",
                title=finding.title, count=len(cves),
            ),
        )


# ---------------------------------------------------------------------
# Probe registration & selection
# ---------------------------------------------------------------------
def _all_registered_probes() -> list[WebProbeBase]:
    return [
        SecurityHeadersProbe(),
        ExposedPathsProbe(),
        SslTlsProbe(),
        PathTraversalProbe(),
        SqlInjectionProbe(),
        XssProbe(),
    ]


def _select_probes(depth: ScanDepth) -> list[WebProbeBase]:
    del depth  # depth-agnostic in MVP
    return _all_registered_probes()
