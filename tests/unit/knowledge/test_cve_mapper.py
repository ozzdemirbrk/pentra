"""cve_mapper.py — servis normalleştirme + lookup testleri."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from pentra.knowledge.cve_mapper import CveMapper, _parse_server_header
from pentra.knowledge.nvd_client import Cve


def _fake_client_returning(
    cves: list[Cve] | None = None,
    cpe_cves: list[Cve] | None = None,
) -> MagicMock:
    """Keyword araması için `cves`, CPE araması için `cpe_cves` döndürür."""
    client = MagicMock()
    client.search_cves.return_value = cves or []
    client.search_by_cpe.return_value = cpe_cves if cpe_cves is not None else []
    return client


class TestServiceNormalization:
    @pytest.mark.parametrize("raw,canonical", [
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
    ])
    def test_known_services(self, raw: str, canonical: str) -> None:
        client = _fake_client_returning([])
        mapper = CveMapper(client)
        assert mapper._normalize_service(raw) == canonical

    def test_unknown_service_returned_as_is(self) -> None:
        client = _fake_client_returning([])
        mapper = CveMapper(client)
        assert mapper._normalize_service("some-custom-app") == "some-custom-app"


class TestVersionShortening:
    @pytest.mark.parametrize("raw,shortened", [
        ("10.0", "10.0"),
        ("10.0.17763.1", "10.0.17763"),  # ilk 3 parça
        ("2.4.41", "2.4.41"),
        ("1.18.0", "1.18.0"),
        ("8", "8"),  # tek sayı varsa aynısı
    ])
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
        """Tanınmış servis için ÖNCE CPE ile arama yapılır."""
        client = _fake_client_returning()
        mapper = CveMapper(client)

        mapper.lookup("microsoft-iis", "10.0")

        # CPE araması çağrıldı mı
        client.search_by_cpe.assert_called_once()
        cpe_call = client.search_by_cpe.call_args
        cpe_arg = cpe_call.args[0] if cpe_call.args else cpe_call.kwargs.get("cpe_name", "")
        assert "microsoft:internet_information_services" in cpe_arg
        assert ":10.0:" in cpe_arg

    def test_cpe_result_returned_without_keyword_fallback(self) -> None:
        """CPE sonuç veriyorsa keyword araması tetiklenmez."""
        cpe_results = [Cve("CVE-2024-IIS", 9.8, "CRITICAL", "IIS bug")]
        client = _fake_client_returning(cpe_cves=cpe_results)
        mapper = CveMapper(client)

        result = mapper.lookup("microsoft-iis", "10.0")

        assert result == cpe_results
        client.search_cves.assert_not_called()

    def test_no_keyword_fallback_when_cpe_empty(self) -> None:
        """Tanınmış servis + CPE 0 → [] döner (keyword fallback YASAK).

        Sebep: IIS 10.0 gibi kesin bir sorgu için CPE 0 dönüşü 'o versiyonda
        kayıt yok' demektir. Keyword fallback eski sürüm CVE'lerini çeker
        (false positive).
        """
        client = _fake_client_returning(cves=[Cve("CVE-X", 5.0, "MEDIUM", "x")], cpe_cves=[])
        mapper = CveMapper(client)

        result = mapper.lookup("microsoft-iis", "10.0")

        assert result == []
        client.search_by_cpe.assert_called_once()
        client.search_cves.assert_not_called()

    def test_unknown_service_only_keyword_search(self) -> None:
        """CPE haritasında olmayan servis için doğrudan keyword kullanılır."""
        client = _fake_client_returning()
        mapper = CveMapper(client)

        mapper.lookup("custom-app", "1.0")

        client.search_by_cpe.assert_not_called()
        client.search_cves.assert_called_once()


class TestServerHeaderParsing:
    @pytest.mark.parametrize("header,expected", [
        ("Microsoft-IIS/10.0", ("Microsoft-IIS", "10.0")),
        ("Apache/2.4.41", ("Apache", "2.4.41")),
        ("Apache/2.4.41 (Ubuntu)", ("Apache", "2.4.41")),
        ("nginx/1.18.0", ("nginx", "1.18.0")),
        ("nginx", ("", "")),  # versiyon yok
        ("", ("", "")),
    ])
    def test_parse(self, header: str, expected: tuple[str, str]) -> None:
        assert _parse_server_header(header) == expected


class TestLookupFromServerHeader:
    def test_calls_cpe_search_for_known_service(self) -> None:
        """Microsoft IIS haritada var → CPE araması yapılır."""
        client = _fake_client_returning()
        mapper = CveMapper(client)

        mapper.lookup_from_server_header("Microsoft-IIS/10.0")

        client.search_by_cpe.assert_called_once()
        cpe_arg = client.search_by_cpe.call_args.args[0]
        assert "microsoft:internet_information_services" in cpe_arg
        assert ":10.0:" in cpe_arg
        # Tanınmış servis — keyword fallback YASAK
        client.search_cves.assert_not_called()

    def test_unparseable_header_returns_empty_without_network(self) -> None:
        client = _fake_client_returning([])
        mapper = CveMapper(client)
        result = mapper.lookup_from_server_header("some-garbage")
        assert result == []
        client.search_cves.assert_not_called()
