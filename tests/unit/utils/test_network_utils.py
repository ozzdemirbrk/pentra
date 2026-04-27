"""network_utils.py — yerel subnet tespit testleri."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from pentra.utils.network_utils import (
    get_local_ip,
    guess_local_cidr,
    is_valid_cidr,
)


class TestGetLocalIp:
    def test_successful_socket_returns_ip(self) -> None:
        fake_sock = MagicMock()
        fake_sock.getsockname.return_value = ("192.168.1.42", 54321)

        with patch("socket.socket", return_value=fake_sock):
            ip = get_local_ip()
        assert ip == "192.168.1.42"

    def test_os_error_returns_none(self) -> None:
        fake_sock = MagicMock()
        fake_sock.connect.side_effect = OSError("network unreachable")

        with patch("socket.socket", return_value=fake_sock):
            ip = get_local_ip()
        assert ip is None


class TestGuessLocalCidr:
    def test_default_24_prefix(self) -> None:
        with patch("pentra.utils.network_utils.get_local_ip", return_value="192.168.1.42"):
            cidr = guess_local_cidr()
        assert cidr == "192.168.1.0/24"

    def test_custom_prefix(self) -> None:
        with patch("pentra.utils.network_utils.get_local_ip", return_value="10.1.2.3"):
            cidr = guess_local_cidr(prefix_length=16)
        assert cidr == "10.1.0.0/16"

    def test_none_when_ip_unknown(self) -> None:
        with patch("pentra.utils.network_utils.get_local_ip", return_value=None):
            assert guess_local_cidr() is None

    def test_invalid_prefix_raises(self) -> None:
        with pytest.raises(ValueError, match="prefix_length"):
            guess_local_cidr(prefix_length=40)
        with pytest.raises(ValueError, match="prefix_length"):
            guess_local_cidr(prefix_length=4)


class TestIsValidCidr:
    @pytest.mark.parametrize(
        "cidr",
        [
            "192.168.1.0/24",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.1.1/32",
            "0.0.0.0/0",
        ],
    )
    def test_valid_cidrs(self, cidr: str) -> None:
        assert is_valid_cidr(cidr)

    @pytest.mark.parametrize(
        "cidr",
        [
            "not-a-cidr",
            "999.999.999.999/24",
            "192.168.1.0/33",
            "",
            "192.168.1.0/",
        ],
    )
    def test_invalid_cidrs(self, cidr: str) -> None:
        assert not is_valid_cidr(cidr)

    def test_plain_ip_without_prefix_is_valid(self) -> None:
        # ipaddress.ip_network("192.168.1.1") → /32 olarak kabul edilir
        assert is_valid_cidr("192.168.1.1")
