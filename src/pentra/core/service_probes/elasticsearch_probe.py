"""Elasticsearch auth check — port 9200'de parolasız erişim kontrolü.

Basit HTTP GET `/` isteği gönderir. Elasticsearch root endpoint parolasız
açıksa sürüm bilgisi + cluster adı döner (imza: `"cluster_name"` veya
`"tagline"`). Bu durumda sinekten veri çekilebiliyor demektir — CRITICAL.
"""

from __future__ import annotations

import requests

from pentra.core.service_probes.base import ServiceProbeBase
from pentra.models import Finding, Severity


class ElasticsearchAuthProbe(ServiceProbeBase):
    default_ports: tuple[int, ...] = (9200,)
    name: str = "elasticsearch_auth"
    description: str = "Elasticsearch parola gerektirmeden erişim kontrolü"

    def probe(self, host: str, port: int) -> list[Finding]:
        # Hem HTTP hem HTTPS dene (modern ES varsayılanda HTTPS olabilir)
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}:{port}/"
            try:
                response = requests.get(
                    url,
                    timeout=self.timeout,
                    verify=False,  # self-signed cert olabilir, auth kontrolü odak
                    allow_redirects=False,
                )
            except requests.RequestException:
                continue

            # 401/403 → auth isteniyor (iyi)
            if response.status_code in (401, 403):
                return []

            if response.status_code != 200:
                continue

            body = response.text[:2048]

            # Elasticsearch imzası: "You Know, for Search" tagline'ı
            if ('"tagline"' in body and "Search" in body) or '"cluster_name"' in body:
                return [
                    Finding(
                        scanner_name="network_scanner",
                        severity=Severity.CRITICAL,
                        title=f"Elasticsearch parolasız erişilebilir — port {port}",
                        description=(
                            "Elasticsearch cluster root endpoint (`/`) parolasız yanıt veriyor. "
                            "Bu yapılandırmada saldırgan `_search` endpoint'i üzerinden tüm "
                            "indeks verisini çekebilir, `_cat/indices` ile tablo listesi alabilir, "
                            "veri silebilir. 2017'den beri binlerce veri sızıntısının sebebi "
                            "bu tür açık ES örnekleri."
                        ),
                        target=f"{host}:{port}",
                        remediation=(
                            "ACİL: `elasticsearch.yml` içinde `xpack.security.enabled: true` "
                            "ayarlayın, `elasticsearch-setup-passwords auto` ile parolaları üretin. "
                            "Eğer sadece iç ağda kullanılıyorsa `network.host: 127.0.0.1` ile "
                            "sadece localhost'a bağlayın. Bulut ortamında güvenlik duvarı kuralı "
                            "(sadece belirli IP'lerden 9200 portuna izin) ekleyin."
                        ),
                        evidence=self._evidence(
                            host=host, port=port,
                            why_vulnerable="HTTP 200 + Elasticsearch cluster bilgisi döndü (auth yok)",
                            response_snippet=body[:300],
                            extra={"scheme": scheme},
                        ),
                    ),
                ]

        return []
