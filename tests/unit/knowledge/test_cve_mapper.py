"""cve_mapper.py — service normalization + lookup tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from pentra.knowledge.cve_mapper import CveMapper, _parse_server_header
from pentra.knowledge.nvd_client import Cve


def _fake_client_returning(
    cves: list[Cve] | None = None,
    cpe_cves: list[Cve] | None = None,
) -> MagicMock:
    """Return `cves` from keyword search and `cpe_cves` from CPE search."""
    client = MagicMock()
    client.search_cves.return_value = cves or []
    client.search_by_cpe.return_value = cpe_cves if cpe_cves is not None else []
    return client


class TestServiceNormalization:
    @pytest.mark.parametrize(
        "raw,canonical",
        [
            ("microsoft-iis", "Microsoft IIS"),
            ("ms-iis", "Microsoft IIS"),
            ("iis", "Microsoft IIS"),
            ("apache", "Apache"),
            ("httpd", "Apache"),
            ("nginx", "nginx"),
            ("openssh", "OpenSSH"),
            ("ssh", "OpenSSH"),
            ("mysql", "MySQL"),
            ("postgresql", "PostgreSQL"),
            ("mongodb", "MongoDB"),
            ("redis", "Redis"),
            ("ms-wbt-server", "Remote Desktop"),
            ("microsoft-ds", "SMB"),
        ],
    )
    def test_known_services(self, raw: str, canonical: str) -> None:
        client = _fake_client_returning([])
        mapper = CveMapper(client)
        assert mapper._normalize_service(raw) == canonical

    def test_unknown_service_returned_as_is(self) -> None:
        client = _fake_client_returning([])
        mapper = CveMapper(client)
        assert mapper._normalize_service("some-custom-app") == "some-custom-app"


class TestVersionShortening:
    @pytest.mark.parametrize(
        "raw,shortened",
        [
            ("10.0", "10.0"),
            ("10.0.17763.1", "10.0.17763"),  # first 3 segments
            ("2.4.41", "2.4.41"),
            ("1.18.0", "1.18.0"),
            ("8", "8"),  # single number stays as-is
        ],
    )
    def test_versions(self, raw: str, shortened: str) -> None:
        client = _fake_client_returning([])
        mapper = CveMapper(client)
        assert mapper._shorten_version(raw) == shortened


class TestLookup:
    def test_empty_inputs_return_empty(self) -> None:
        mapper = CveMapper(_fake_client_returning([]))
        assert mapper.lookup("", "10.0") == []
        assert mapper.lookup("iis", "") == []
        assert mapper.lookup("", "") == []

    def test_cpe_search_used_for_known_service(self) -> None:
        """Known services use CPE search FIRST."""
        client = _fake_client_returning()
        mapper = CveMapper(client)

        mapper.lookup("microsoft-iis", "10.0")

        # Was CPE search invoked
        client.search_by_cpe.assert_called_once()
        cpe_call = client.search_by_cpe.call_args
        cpe_arg = cpe_call.args[0] if cpe_call.args else cpe_call.kwargs.get("cpe_name", "")
        assert "microsoft:internet_information_services" in cpe_arg
        assert ":10.0:" in cpe_arg

    def test_cpe_result_returned_without_keyword_fallback(self) -> None:
        """If CPE returns results, keyword search is not triggered."""
        cpe_results = [Cve("CVE-2024-IIS", 9.8, "CRITICAL", "IIS bug")]
        client = _fake_client_returning(cpe_cves=cpe_results)
        mapper = CveMapper(client)

        result = mapper.lookup("microsoft-iis", "10.0")

        assert result == cpe_results
        client.search_cves.assert_not_called()

    def test_no_keyword_fallback_when_cpe_empty(self) -> None:
        """Known service + 0 CPE results -> returns [] (keyword fallback is FORBIDDEN).

        Rationale: for an exact query like IIS 10.0, a 0-result CPE means
        'no record for that version'. A keyword fallback would pull in
        older-version CVEs (false positive).
        """
        client = _fake_client_returning(cves=[Cve("CVE-X", 5.0, "MEDIUM", "x")], cpe_cves=[])
        mapper = CveMapper(client)

        result = mapper.lookup("microsoft-iis", "10.0")

        assert result == []
        client.search_by_cpe.assert_called_once()
        client.search_cves.assert_not_called()

    def test_unknown_service_only_keyword_search(self) -> None:
        """For services not in the CPE map, keyword search is used directly."""
        client = _fake_client_returning()
        mapper = CveMapper(client)

        mapper.lookup("custom-app", "1.0")

        client.search_by_cpe.assert_not_called()
        client.search_cves.assert_called_once()


class TestServerHeaderParsing:
    @pytest.mark.parametrize(
        "header,expected",
        [
            ("Microsoft-IIS/10.0", ("Microsoft-IIS", "10.0")),
            ("Apache/2.4.41", ("Apache", "2.4.41")),
            ("Apache/2.4.41 (Ubuntu)", ("Apache", "2.4.41")),
            ("nginx/1.18.0", ("nginx", "1.18.0")),
            ("nginx", ("", "")),  # no version
            ("", ("", "")),
        ],
    )
    def test_parse(self, header: str, expected: tuple[str, str]) -> None:
        assert _parse_server_header(header) == expected


class TestLookupFromServerHeader:
    def test_calls_cpe_search_for_known_service(self) -> None:
        """Microsoft IIS is in the map -> CPE search is performed."""
        client = _fake_client_returning()
        mapper = CveMapper(client)

        mapper.lookup_from_server_header("Microsoft-IIS/10.0")

        client.search_by_cpe.assert_called_once()
        cpe_arg = client.search_by_cpe.call_args.args[0]
        assert "microsoft:internet_information_services" in cpe_arg
        assert ":10.0:" in cpe_arg
        # Known service — keyword fallback is FORBIDDEN
        client.search_cves.assert_not_called()

    def test_unparseable_header_returns_empty_without_network(self) -> None:
        client = _fake_client_returning([])
        mapper = CveMapper(client)
        result = mapper.lookup_from_server_header("some-garbage")
        assert result == []
        client.search_cves.assert_not_called()
