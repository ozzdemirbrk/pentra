"""Wi-Fi pasif tarayıcı — çevredeki kablosuz ağları listeler.

Windows'ta `netsh wlan show networks mode=bssid` çıktısını parse eder.
Hiç paket göndermez (pasif) — sadece Windows'un zaten topladığı liste.

Bulgular:
    - **Şifresiz (Open)** ağ → HIGH (dinleme/MITM açık)
    - **WEP** → HIGH (kırık şifreleme, dakikalarda kırılır)
    - **WPA-Personal (eski WPA)** → MEDIUM (TKIP zayıf)
    - **WPA2** → INFO (sağlıklı, sadece listeleme amaçlı)
    - **WPA3** → INFO (en iyi, tercih edilen)

WPS durumu netsh'ta güvenilir raporlanmaz → manuel kontrol için not eklenir.
"""

from __future__ import annotations

import platform
import re
import subprocess
from dataclasses import dataclass

from pentra.core.scanner_base import ScannerBase
from pentra.i18n import t
from pentra.models import Finding, ScanDepth, Severity, Target


@dataclass(frozen=True)
class WifiNetwork:
    """Parse edilmiş bir Wi-Fi ağı kaydı."""

    ssid: str
    authentication: str
    encryption: str
    bssids: tuple[str, ...] = ()
    max_signal_percent: int = 0


# netsh etiketleri — Türkçe/İngilizce Windows yerelleştirmesi destekli
_SSID_RE = re.compile(r"^SSID\s+\d+\s*:\s*(?P<ssid>.*?)\s*$", re.I)
_AUTH_RE = re.compile(
    r"^\s*(?:Authentication|Kimlik\s*[Dd]o[ğg]rulama)\s*:\s*(?P<val>.+?)\s*$", re.I,
)
_ENCR_RE = re.compile(
    r"^\s*(?:Encryption|[SŞş]ifreleme)\s*:\s*(?P<val>.+?)\s*$", re.I,
)
_BSSID_RE = re.compile(
    r"^\s*BSSID\s+\d+\s*:\s*(?P<mac>[0-9A-Fa-f:]{11,17})\s*$", re.I,
)
_SIGNAL_RE = re.compile(
    r"^\s*(?:Signal|Sinyal)\s*:\s*(?P<pct>\d+)\s*%?\s*$", re.I,
)


class WifiScanner(ScannerBase):
    """Çevredeki Wi-Fi ağlarını pasif olarak listeler (Windows)."""

    @property
    def scanner_name(self) -> str:
        return "wifi_scanner"

    def _do_scan(self, target: Target, depth: ScanDepth) -> None:
        del target, depth  # Wi-Fi taraması hedef-bağımsız

        if platform.system() != "Windows":
            self._emit_error(t("error.wifi.platform_not_supported"))
            return

        self._emit_progress(10, t("progress.wifi.running_netsh"))
        output = _run_netsh_wlan()
        if output is None:
            self._emit_error(t("error.wifi.netsh_failed"))
            return

        self._emit_progress(50, t("progress.wifi.processing_output"))
        networks = _parse_netsh_output(output)
        if not networks:
            self._emit_progress(100, t("progress.wifi.no_networks"))
            return

        self._emit_progress(
            70, t("progress.wifi.networks_detected", count=len(networks)),
        )

        for idx, net in enumerate(networks):
            if self._cancelled:
                return
            finding = _evaluate_network(net)
            if finding is not None:
                self._emit_finding(finding)

            pct = 70 + int(30 * (idx + 1) / len(networks))
            self._emit_progress(
                pct,
                t(
                    "progress.wifi.network_evaluated",
                    ssid=net.ssid or t("label.wifi.hidden_ssid"),
                ),
            )

        self._emit_progress(
            100, t("progress.wifi.scan_complete", count=len(networks)),
        )


# ---------------------------------------------------------------------
# netsh çalıştırma
# ---------------------------------------------------------------------
def _run_netsh_wlan() -> str | None:
    """`netsh wlan show networks mode=bssid` çalıştır, çıktıyı döndür."""
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None

    if result.returncode != 0:
        return None

    for encoding in ("utf-8", "cp1254", "cp1252", "latin-1"):
        try:
            return result.stdout.decode(encoding)
        except UnicodeDecodeError:
            continue
    return result.stdout.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------
def _parse_netsh_output(output: str) -> list[WifiNetwork]:
    """netsh çıktısından WifiNetwork listesi çıkar."""
    networks: list[WifiNetwork] = []

    current_ssid: str | None = None
    current_auth: str = ""
    current_encr: str = ""
    current_bssids: list[str] = []
    current_max_signal: int = 0

    def _finalize() -> None:
        nonlocal current_ssid, current_auth, current_encr, current_bssids, current_max_signal
        if current_ssid is not None:
            networks.append(
                WifiNetwork(
                    ssid=current_ssid,
                    authentication=current_auth,
                    encryption=current_encr,
                    bssids=tuple(current_bssids),
                    max_signal_percent=current_max_signal,
                ),
            )
        current_ssid = None
        current_auth = ""
        current_encr = ""
        current_bssids = []
        current_max_signal = 0

    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        if not line:
            continue

        ssid_m = _SSID_RE.match(line)
        if ssid_m:
            _finalize()
            current_ssid = ssid_m.group("ssid").strip()
            continue

        if current_ssid is None:
            continue

        auth_m = _AUTH_RE.match(line)
        if auth_m:
            current_auth = auth_m.group("val").strip()
            continue

        encr_m = _ENCR_RE.match(line)
        if encr_m:
            current_encr = encr_m.group("val").strip()
            continue

        bssid_m = _BSSID_RE.match(line)
        if bssid_m:
            current_bssids.append(bssid_m.group("mac").strip())
            continue

        signal_m = _SIGNAL_RE.match(line)
        if signal_m:
            pct = int(signal_m.group("pct"))
            if pct > current_max_signal:
                current_max_signal = pct
            continue

    _finalize()
    return networks


# ---------------------------------------------------------------------
# Finding üretimi
# ---------------------------------------------------------------------
def _evaluate_network(net: WifiNetwork) -> Finding | None:
    """Bir ağın güvenlik durumuna göre Finding döndür (yoksa None)."""
    ssid_display = net.ssid if net.ssid else t("label.wifi.hidden_ssid")
    auth_lower = net.authentication.lower()
    encr_lower = net.encryption.lower()

    base_evidence: dict[str, object] = {
        "probe_name": "wifi_scanner",
        "ssid": ssid_display,
        "auth": net.authentication,
        "encryption": net.encryption,
        "bssid_count": len(net.bssids),
        "signal_percent": net.max_signal_percent,
    }

    # --- Açık (şifresiz) ağ ---
    if (
        auth_lower in ("open", "ak", "açık")
        or "open" in auth_lower
        or encr_lower in ("none", "yok", "hiçbiri")
    ):
        return Finding(
            scanner_name="wifi_scanner",
            severity=Severity.HIGH,
            title=t("finding.wifi.open.title", ssid=ssid_display),
            description=t("finding.wifi.open.desc", ssid=ssid_display),
            target=f"wifi://{ssid_display}",
            remediation=t("finding.wifi.open.remediation"),
            evidence=base_evidence,
        )

    # --- WEP ağ (kırık şifreleme) ---
    if "wep" in auth_lower or "wep" in encr_lower:
        return Finding(
            scanner_name="wifi_scanner",
            severity=Severity.HIGH,
            title=t("finding.wifi.wep.title", ssid=ssid_display),
            description=t("finding.wifi.wep.desc", ssid=ssid_display),
            target=f"wifi://{ssid_display}",
            remediation=t("finding.wifi.wep.remediation"),
            evidence=base_evidence,
        )

    # --- Eski WPA (TKIP) ---
    if "wpa-" in auth_lower or ("wpa" in auth_lower and "wpa2" not in auth_lower and "wpa3" not in auth_lower):
        return Finding(
            scanner_name="wifi_scanner",
            severity=Severity.MEDIUM,
            title=t("finding.wifi.oldwpa.title", ssid=ssid_display),
            description=t("finding.wifi.oldwpa.desc", ssid=ssid_display),
            target=f"wifi://{ssid_display}",
            remediation=t("finding.wifi.oldwpa.remediation"),
            evidence=base_evidence,
        )

    # WPA2 / WPA3 — sağlıklı, sadece bilgi
    if net.authentication:
        return Finding(
            scanner_name="wifi_scanner",
            severity=Severity.INFO,
            title=t(
                "finding.wifi.secure.title",
                ssid=ssid_display, auth=net.authentication,
            ),
            description=t(
                "finding.wifi.secure.desc",
                auth=net.authentication, encryption=net.encryption,
            ),
            target=f"wifi://{ssid_display}",
            remediation=t("finding.wifi.secure.remediation"),
            evidence=base_evidence,
        )

    return None
