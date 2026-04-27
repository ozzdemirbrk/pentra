"""wifi_scanner.py — netsh output parsing and finding generation tests."""

from __future__ import annotations

from pentra.core.wifi_scanner import (
    WifiNetwork,
    _evaluate_network,
    _parse_netsh_output,
)
from pentra.models import Severity

# ---------------------------------------------------------------------
# Sample netsh outputs
# ---------------------------------------------------------------------
_NETSH_ENGLISH = """
Interface name : Wi-Fi
There are 4 networks currently visible.

SSID 1 : MyHomeNetwork
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:dd:ee:ff
         Signal             : 80%
         Radio type         : 802.11n
         Channel            : 6

SSID 2 : CafeWifi
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : 11:22:33:44:55:66
         Signal             : 65%

SSID 3 : OldRouter
    Network type            : Infrastructure
    Authentication          : WEP
    Encryption              : WEP
    BSSID 1                 : 77:88:99:aa:bb:cc
         Signal             : 40%

SSID 4 : ModernHome
    Network type            : Infrastructure
    Authentication          : WPA3-Personal
    Encryption              : CCMP
    BSSID 1                 : dd:ee:ff:00:11:22
         Signal             : 90%
"""

_NETSH_TURKISH = """
Arabirim adı : Wi-Fi
Şu anda 1 ağ görünüyor.

SSID 1 : TurkTelekom_ABCD
    Ağ türü                 : Altyapı
    Kimlik doğrulama        : WPA2-Personal
    Şifreleme               : CCMP
    BSSID 1                 : 00:11:22:33:44:55
         Sinyal             : 75%
"""


class TestParseNetshEnglish:
    def test_finds_all_networks(self) -> None:
        networks = _parse_netsh_output(_NETSH_ENGLISH)
        assert len(networks) == 4
        ssids = {n.ssid for n in networks}
        assert ssids == {"MyHomeNetwork", "CafeWifi", "OldRouter", "ModernHome"}

    def test_authentication_parsed(self) -> None:
        networks = _parse_netsh_output(_NETSH_ENGLISH)
        by_ssid = {n.ssid: n for n in networks}
        assert by_ssid["MyHomeNetwork"].authentication == "WPA2-Personal"
        assert by_ssid["CafeWifi"].authentication == "Open"
        assert by_ssid["OldRouter"].authentication == "WEP"
        assert by_ssid["ModernHome"].authentication == "WPA3-Personal"

    def test_encryption_parsed(self) -> None:
        networks = _parse_netsh_output(_NETSH_ENGLISH)
        by_ssid = {n.ssid: n for n in networks}
        assert by_ssid["MyHomeNetwork"].encryption == "CCMP"
        assert by_ssid["CafeWifi"].encryption == "None"
        assert by_ssid["OldRouter"].encryption == "WEP"

    def test_bssid_captured(self) -> None:
        networks = _parse_netsh_output(_NETSH_ENGLISH)
        home = next(n for n in networks if n.ssid == "MyHomeNetwork")
        assert "aa:bb:cc:dd:ee:ff" in home.bssids

    def test_max_signal(self) -> None:
        networks = _parse_netsh_output(_NETSH_ENGLISH)
        modern = next(n for n in networks if n.ssid == "ModernHome")
        assert modern.max_signal_percent == 90


class TestParseNetshTurkish:
    def test_turkish_labels_work(self) -> None:
        networks = _parse_netsh_output(_NETSH_TURKISH)
        assert len(networks) == 1
        assert networks[0].ssid == "TurkTelekom_ABCD"
        assert networks[0].authentication == "WPA2-Personal"
        assert networks[0].encryption == "CCMP"
        assert "00:11:22:33:44:55" in networks[0].bssids


class TestParseEdgeCases:
    def test_empty_output(self) -> None:
        assert _parse_netsh_output("") == []

    def test_no_networks_only_header(self) -> None:
        output = "Interface name : Wi-Fi\nThere are 0 networks currently visible.\n"
        assert _parse_netsh_output(output) == []

    def test_multiple_bssids_per_ssid(self) -> None:
        output = """SSID 1 : Test
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:aa:aa:aa:aa:aa
         Signal             : 50%
    BSSID 2                 : bb:bb:bb:bb:bb:bb
         Signal             : 70%
"""
        networks = _parse_netsh_output(output)
        assert len(networks) == 1
        assert len(networks[0].bssids) == 2
        assert networks[0].max_signal_percent == 70


# ---------------------------------------------------------------------
# Finding evaluation
# ---------------------------------------------------------------------
class TestEvaluation:
    def test_open_network_is_high(self) -> None:
        net = WifiNetwork(ssid="Cafe", authentication="Open", encryption="None")
        f = _evaluate_network(net)
        assert f is not None
        assert f.severity == Severity.HIGH
        assert "Şifresiz" in f.title

    def test_wep_network_is_high(self) -> None:
        net = WifiNetwork(ssid="OldRouter", authentication="WEP", encryption="WEP")
        f = _evaluate_network(net)
        assert f is not None
        assert f.severity == Severity.HIGH
        assert "WEP" in f.title

    def test_wpa_old_is_medium(self) -> None:
        net = WifiNetwork(
            ssid="LegacyAP",
            authentication="WPA-Personal",
            encryption="TKIP",
        )
        f = _evaluate_network(net)
        assert f is not None
        assert f.severity == Severity.MEDIUM

    def test_wpa2_is_info(self) -> None:
        net = WifiNetwork(
            ssid="Home",
            authentication="WPA2-Personal",
            encryption="CCMP",
        )
        f = _evaluate_network(net)
        assert f is not None
        assert f.severity == Severity.INFO

    def test_wpa3_is_info(self) -> None:
        net = WifiNetwork(
            ssid="Modern",
            authentication="WPA3-Personal",
            encryption="CCMP",
        )
        f = _evaluate_network(net)
        assert f is not None
        assert f.severity == Severity.INFO

    def test_hidden_ssid_still_evaluated(self) -> None:
        net = WifiNetwork(ssid="", authentication="Open", encryption="None")
        f = _evaluate_network(net)
        assert f is not None
        assert f.severity == Severity.HIGH
        assert "gizli" in f.title.lower()
