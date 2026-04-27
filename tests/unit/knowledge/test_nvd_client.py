"""nvd_client.py — NVD API client tests (mocked HTTP)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from pentra.knowledge.nvd_client import Cve, NvdClient


def _nvd_response(vulnerabilities: list) -> dict:
    """Fake NVD 2.0 API response."""
    return {
        "resultsPerPage": len(vulnerabilities),
        "startIndex": 0,
        "totalResults": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
    }


def _vuln(
    cve_id: str,
    description: str,
    cvss_v31: float | None = None,
    severity: str = "HIGH",
) -> dict:
    """Fake of a single vulnerability record."""
    entry: dict = {
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": description}],
            "published": "2024-05-01T00:00:00.000",
            "metrics": {},
        },
    }
    if cvss_v31 is not None:
        entry["cve"]["metrics"]["cvssMetricV31"] = [
            {"cvssData": {"baseScore": cvss_v31, "baseSeverity": severity}},
        ]
    return entry


class TestRateLimiting:
    def test_anonymous_has_stricter_rate_limit(self) -> None:
        client_anon = NvdClient(api_key=None)
        client_key = NvdClient(api_key="xxxxx")
        # Anonymous: capacity 5; key: capacity 50
        assert client_anon._rate_limiter.capacity == 5
        assert client_key._rate_limiter.capacity == 50


class TestSearchCves:
    def test_parses_v31_score(self) -> None:
        client = NvdClient()
        mock_response = MagicMock()
        mock_response.json.return_value = _nvd_response([
            _vuln("CVE-2024-1234", "IIS 10.0 memory corruption", cvss_v31=8.8, severity="HIGH"),
        ])
        mock_response.raise_for_status.return_value = None

        with patch.object(client._session, "get", return_value=mock_response):
            cves = client.search_cves("IIS 10.0")

        assert len(cves) == 1
        assert cves[0].cve_id == "CVE-2024-1234"
        assert cves[0].cvss_score == 8.8
        assert cves[0].severity == "HIGH"
        assert cves[0].published_date == "2024-05-01"

    def test_post_filter_must_contain(self) -> None:
        """A CVE should be filtered out if any of the must_contain strings is missing."""
        client = NvdClient()
        mock_response = MagicMock()
        mock_response.json.return_value = _nvd_response([
            _vuln("CVE-A", "Microsoft IIS 10.0 bug", cvss_v31=7.5),
            _vuln("CVE-B", "Completely unrelated Linux kernel bug", cvss_v31=9.1),
            _vuln("CVE-C", "IIS earlier versions 8.x", cvss_v31=5.0),
        ])
        mock_response.raise_for_status.return_value = None

        with patch.object(client._session, "get", return_value=mock_response):
            cves = client.search_cves("IIS 10.0", must_contain=("IIS", "10.0"))

        ids = [c.cve_id for c in cves]
        assert "CVE-A" in ids
        assert "CVE-B" not in ids  # missing "IIS"
        assert "CVE-C" not in ids  # missing "10.0"

    def test_sorted_by_cvss_desc(self) -> None:
        client = NvdClient()
        mock_response = MagicMock()
        mock_response.json.return_value = _nvd_response([
            _vuln("CVE-LOW", "X bug", cvss_v31=3.0),
            _vuln("CVE-CRIT", "X bug", cvss_v31=9.8),
            _vuln("CVE-MED", "X bug", cvss_v31=6.5),
        ])
        mock_response.raise_for_status.return_value = None

        with patch.object(client._session, "get", return_value=mock_response):
            cves = client.search_cves("X")

        scores = [c.cvss_score for c in cves]
        assert scores == sorted(scores, reverse=True)

    def test_network_error_returns_empty(self) -> None:
        client = NvdClient()
        with patch.object(
            client._session, "get",
            side_effect=requests.ConnectionError("network down"),
        ):
            cves = client.search_cves("anything")
        assert cves == []

    def test_invalid_json_returns_empty(self) -> None:
        client = NvdClient()
        mock_response = MagicMock()
        mock_response.json.side_effect = ValueError("bad json")
        mock_response.raise_for_status.return_value = None

        with patch.object(client._session, "get", return_value=mock_response):
            cves = client.search_cves("x")
        assert cves == []

    def test_cache_hit_skips_network(self) -> None:
        client = NvdClient()
        mock_response = MagicMock()
        mock_response.json.return_value = _nvd_response([
            _vuln("CVE-1", "x", cvss_v31=5.0),
        ])
        mock_response.raise_for_status.return_value = None

        with patch.object(client._session, "get", return_value=mock_response) as mock_get:
            client.search_cves("same", must_contain=("x",))
            client.search_cves("same", must_contain=("x",))
            client.search_cves("same", must_contain=("x",))
            # Only 1 HTTP request — subsequent ones are served from cache
            assert mock_get.call_count == 1

    def test_empty_results(self) -> None:
        client = NvdClient()
        mock_response = MagicMock()
        mock_response.json.return_value = _nvd_response([])
        mock_response.raise_for_status.return_value = None

        with patch.object(client._session, "get", return_value=mock_response):
            cves = client.search_cves("nothing")
        assert cves == []


class TestCvssFallback:
    def test_v30_metric_used_when_v31_missing(self) -> None:
        entry = {
            "cve": {
                "id": "CVE-X",
                "descriptions": [{"lang": "en", "value": "vuln"}],
                "metrics": {
                    "cvssMetricV30": [
                        {"cvssData": {"baseScore": 6.5, "baseSeverity": "MEDIUM"}},
                    ],
                },
            },
        }
        client = NvdClient()
        mock_response = MagicMock()
        mock_response.json.return_value = _nvd_response([entry])
        mock_response.raise_for_status.return_value = None

        with patch.object(client._session, "get", return_value=mock_response):
            cves = client.search_cves("x")
        assert cves[0].cvss_score == 6.5
        assert cves[0].severity == "MEDIUM"

    def test_v2_fallback_infers_severity(self) -> None:
        entry = {
            "cve": {
                "id": "CVE-Y",
                "descriptions": [{"lang": "en", "value": "vuln"}],
                "metrics": {
                    "cvssMetricV2": [{"cvssData": {"baseScore": 9.5}}],
                },
            },
        }
        client = NvdClient()
        mock_response = MagicMock()
        mock_response.json.return_value = _nvd_response([entry])
        mock_response.raise_for_status.return_value = None

        with patch.object(client._session, "get", return_value=mock_response):
            cves = client.search_cves("y")
        assert cves[0].severity == "CRITICAL"


class TestNvdUrl:
    def test_url_format(self) -> None:
        cve = Cve(cve_id="CVE-2024-1234", cvss_score=None, severity="UNKNOWN", description="x")
        assert cve.nvd_url == "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
