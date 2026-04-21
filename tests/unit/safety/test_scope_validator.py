"""scope_validator.py — kapsamlı test seti.

Test kategorileri:
    - IPv4 tek adres sınıflandırma (loopback / RFC1918 / public / denied)
    - CIDR aralıkları
    - URL hedefleri (DNS mock'lanır)
    - Geçersiz format hataları
    - Edge case'ler (broadcast, 0.0.0.0, IPv6)
"""

from __future__ import annotations

import socket
from collections.abc import Callable

import pytest

from pentra.models import ScopeDecisionType, Target, TargetType
from pentra.safety.scope_validator import ScopeValidator


def _make_validator(resolver: Callable[[str], list[str]] | None = None) -> ScopeValidator:
    """Test için ScopeValidator — varsayılan olarak DNS çağırmayan fake resolver."""
    if resolver is None:
        def _fail(_: str) -> list[str]:
            raise AssertionError("DNS resolver testte çağrılmamalıydı")
        resolver = _fail
    return ScopeValidator(dns_resolver=resolver)


# =====================================================================
# LOCALHOST
# =====================================================================
class TestLocalhost:
    def test_standard_loopback_allowed(self) -> None:
        v = _make_validator()
        target = Target(TargetType.LOCALHOST, "127.0.0.1")
        result = v.validate(target)
        assert result.decision == ScopeDecisionType.ALLOWED_PRIVATE
        assert result.is_allowed

    def test_any_loopback_range_ip_allowed(self) -> None:
        v = _make_validator()
        target = Target(TargetType.LOCALHOST, "127.1.2.3")
        result = v.validate(target)
        assert result.is_allowed

    def test_non_loopback_value_for_localhost_denied(self) -> None:
        """Localhost tipi için 127.x dışında IP geçilmiş — karar DENIED."""
        v = _make_validator()
        target = Target(TargetType.LOCALHOST, "192.168.1.1")
        result = v.validate(target)
        assert result.decision == ScopeDecisionType.DENIED


# =====================================================================
# WIFI
# =====================================================================
class TestWifi:
    def test_wifi_always_allowed_passive(self) -> None:
        v = _make_validator()
        target = Target(TargetType.WIFI, "*")
        result = v.validate(target)
        assert result.is_allowed


# =====================================================================
# IP_SINGLE
# =====================================================================
class TestSingleIpRFC1918:
    @pytest.mark.parametrize(
        "ip",
        ["10.0.0.1", "10.255.255.254", "172.16.0.1", "172.31.255.254", "192.168.1.1", "192.168.255.254"],
    )
    def test_rfc1918_allowed(self, ip: str) -> None:
        v = _make_validator()
        target = Target(TargetType.IP_SINGLE, ip)
        assert v.validate(target).is_allowed


class TestSingleIpPublic:
    @pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "172.217.16.142", "93.184.216.34"])
    def test_public_requires_confirmation(self, ip: str) -> None:
        v = _make_validator()
        target = Target(TargetType.IP_SINGLE, ip)
        result = v.validate(target)
        assert result.needs_confirmation
        assert not result.is_allowed
        assert not result.is_denied


class TestSingleIpDenied:
    @pytest.mark.parametrize(
        "ip,reason_contains",
        [
            ("224.0.0.1", "Multicast"),
            ("239.255.255.255", "Multicast"),
            ("169.254.1.1", "Link-local"),
            ("0.0.0.0", "0.0.0.0"),
            ("255.255.255.255", "broadcast"),
            ("240.0.0.1", "Rezerve"),
        ],
    )
    def test_denied_ranges(self, ip: str, reason_contains: str) -> None:
        v = _make_validator()
        target = Target(TargetType.IP_SINGLE, ip)
        result = v.validate(target)
        assert result.is_denied
        assert reason_contains.lower() in result.reason.lower()

    def test_invalid_format_denied(self) -> None:
        v = _make_validator()
        target = Target(TargetType.IP_SINGLE, "999.999.999.999")
        result = v.validate(target)
        assert result.is_denied

    def test_empty_string_denied(self) -> None:
        v = _make_validator()
        target = Target(TargetType.IP_SINGLE, "")
        result = v.validate(target)
        assert result.is_denied

    def test_ipv6_denied(self) -> None:
        v = _make_validator()
        target = Target(TargetType.IP_SINGLE, "::1")
        result = v.validate(target)
        assert result.is_denied
        assert "IPv6" in result.reason


# =====================================================================
# IP_RANGE / LOCAL_NETWORK (CIDR)
# =====================================================================
class TestCidrPrivate:
    @pytest.mark.parametrize(
        "cidr",
        ["192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"],
    )
    def test_full_private_cidr_allowed(self, cidr: str) -> None:
        v = _make_validator()
        target = Target(TargetType.IP_RANGE, cidr)
        assert v.validate(target).is_allowed

    def test_local_network_type_also_works(self) -> None:
        v = _make_validator()
        target = Target(TargetType.LOCAL_NETWORK, "192.168.1.0/24")
        assert v.validate(target).is_allowed


class TestCidrExternal:
    def test_small_public_cidr_requires_confirmation(self) -> None:
        v = _make_validator()
        target = Target(TargetType.IP_RANGE, "8.8.8.0/24")
        result = v.validate(target)
        assert result.needs_confirmation

    def test_too_large_public_cidr_denied(self) -> None:
        """/16'dan daha büyük public ağlar DoS riski — DENIED."""
        v = _make_validator()
        target = Target(TargetType.IP_RANGE, "8.0.0.0/8")
        result = v.validate(target)
        assert result.is_denied
        assert "büyük" in result.reason.lower()


class TestCidrInvalid:
    def test_bad_cidr_format_denied(self) -> None:
        v = _make_validator()
        target = Target(TargetType.IP_RANGE, "not-a-cidr")
        result = v.validate(target)
        assert result.is_denied

    def test_ipv6_cidr_denied(self) -> None:
        v = _make_validator()
        target = Target(TargetType.IP_RANGE, "::1/128")
        result = v.validate(target)
        assert result.is_denied
        assert "IPv6" in result.reason


# =====================================================================
# URL
# =====================================================================
class TestUrl:
    def test_http_url_with_private_resolution_allowed(self) -> None:
        v = _make_validator(resolver=lambda h: ["192.168.1.10"])
        target = Target(TargetType.URL, "http://router.local")
        result = v.validate(target)
        assert result.is_allowed
        assert "192.168.1.10" in result.resolved_ips

    def test_https_url_with_public_resolution_requires_confirmation(self) -> None:
        v = _make_validator(resolver=lambda h: ["93.184.216.34"])
        target = Target(TargetType.URL, "https://example.com")
        result = v.validate(target)
        assert result.needs_confirmation

    def test_url_resolving_to_denied_range_denied(self) -> None:
        v = _make_validator(resolver=lambda h: ["224.0.0.1"])
        target = Target(TargetType.URL, "http://multicast.example")
        result = v.validate(target)
        assert result.is_denied

    def test_url_with_ip_hostname(self) -> None:
        v = _make_validator()  # DNS çağrılmamalı, hostname zaten IP
        target = Target(TargetType.URL, "http://192.168.1.50/admin")
        result = v.validate(target)
        assert result.is_allowed

    def test_unsupported_scheme_denied(self) -> None:
        v = _make_validator()
        target = Target(TargetType.URL, "ftp://example.com")
        result = v.validate(target)
        assert result.is_denied
        assert "http" in result.reason.lower()

    def test_missing_scheme_denied(self) -> None:
        v = _make_validator()
        target = Target(TargetType.URL, "example.com")  # urlparse scheme=''
        result = v.validate(target)
        assert result.is_denied

    def test_dns_failure_denied(self) -> None:
        def _fail(hostname: str) -> list[str]:
            raise socket.gaierror(f"ad çözümlenemedi: {hostname}")

        v = _make_validator(resolver=_fail)
        target = Target(TargetType.URL, "https://nonexistent.invalid")
        result = v.validate(target)
        assert result.is_denied
        assert "çözümlene" in result.reason.lower()

    def test_empty_resolution_list_denied(self) -> None:
        v = _make_validator(resolver=lambda h: [])
        target = Target(TargetType.URL, "https://example.com")
        result = v.validate(target)
        assert result.is_denied

    def test_mixed_resolution_strictest_wins(self) -> None:
        """Biri public, biri özel ise: public baskın — ek onay."""
        v = _make_validator(resolver=lambda h: ["8.8.8.8", "192.168.1.1"])
        target = Target(TargetType.URL, "https://mixed.example")
        result = v.validate(target)
        assert result.needs_confirmation

    def test_url_with_no_hostname_denied(self) -> None:
        v = _make_validator()
        target = Target(TargetType.URL, "http://")
        result = v.validate(target)
        assert result.is_denied
