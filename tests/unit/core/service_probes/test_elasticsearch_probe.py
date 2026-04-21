"""elasticsearch_probe.py testleri — mocked HTTP."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests

from pentra.core.service_probes.elasticsearch_probe import ElasticsearchAuthProbe
from pentra.models import Severity


def _mock_response(status: int, text: str = "") -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.text = text
    return r


class TestElasticsearchOpen:
    def test_cluster_info_yields_critical(self) -> None:
        probe = ElasticsearchAuthProbe()
        body = '{"name":"node-1","cluster_name":"mycluster","tagline":"You Know, for Search"}'

        with patch(
            "pentra.core.service_probes.elasticsearch_probe.requests.get",
            return_value=_mock_response(200, body),
        ):
            findings = probe.probe("10.0.0.5", 9200)

        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "parolasız" in findings[0].title.lower()


class TestElasticsearchProtected:
    def test_401_no_finding(self) -> None:
        probe = ElasticsearchAuthProbe()
        with patch(
            "pentra.core.service_probes.elasticsearch_probe.requests.get",
            return_value=_mock_response(401, ""),
        ):
            findings = probe.probe("10.0.0.5", 9200)
        assert findings == []

    def test_403_no_finding(self) -> None:
        probe = ElasticsearchAuthProbe()
        with patch(
            "pentra.core.service_probes.elasticsearch_probe.requests.get",
            return_value=_mock_response(403, ""),
        ):
            findings = probe.probe("10.0.0.5", 9200)
        assert findings == []

    def test_200_but_not_es_no_finding(self) -> None:
        """200 ama ES imzası yoksa bulgu yok (başka bir HTTP servis olabilir)."""
        probe = ElasticsearchAuthProbe()
        with patch(
            "pentra.core.service_probes.elasticsearch_probe.requests.get",
            return_value=_mock_response(200, "<html>Generic page</html>"),
        ):
            findings = probe.probe("10.0.0.5", 9200)
        assert findings == []


class TestElasticsearchUnreachable:
    def test_network_error_no_finding(self) -> None:
        probe = ElasticsearchAuthProbe()
        with patch(
            "pentra.core.service_probes.elasticsearch_probe.requests.get",
            side_effect=requests.ConnectionError("refused"),
        ):
            findings = probe.probe("10.0.0.5", 9200)
        assert findings == []
