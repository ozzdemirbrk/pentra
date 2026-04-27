"""Elasticsearch auth check — tests for no-password access on port 9200."""

from __future__ import annotations

import requests

from pentra.core.service_probes.base import ServiceProbeBase
from pentra.i18n import t
from pentra.models import Finding, Severity


class ElasticsearchAuthProbe(ServiceProbeBase):
    default_ports: tuple[int, ...] = (9200,)
    name: str = "elasticsearch_auth"
    description_key: str = "probe.service.elasticsearch.description"

    def probe(self, host: str, port: int) -> list[Finding]:
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}:{port}/"
            try:
                response = requests.get(
                    url,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False,
                )
            except requests.RequestException:
                continue

            if response.status_code in (401, 403):
                return []

            if response.status_code != 200:
                continue

            body = response.text[:2048]

            if ('"tagline"' in body and "Search" in body) or '"cluster_name"' in body:
                return [
                    Finding(
                        scanner_name="network_scanner",
                        severity=Severity.CRITICAL,
                        title=t("finding.elasticsearch.auth_open.title", port=port),
                        description=t("finding.elasticsearch.auth_open.desc"),
                        target=f"{host}:{port}",
                        remediation=t("finding.elasticsearch.auth_open.remediation"),
                        evidence=self._evidence(
                            host=host,
                            port=port,
                            why_vulnerable=t("finding.elasticsearch.auth_open.evidence"),
                            response_snippet=body[:300],
                            extra={"scheme": scheme},
                        ),
                    ),
                ]

        return []
