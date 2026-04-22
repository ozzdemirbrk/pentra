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
from pentra.models import Finding, ScanDepth, Severity, Target


@dataclass(frozen=True)
class WifiNetwork:
    """Parse edilmiş bir Wi-Fi ağı kaydı."""

    ssid: str
    authentication: str  # "Open" / "WEP" / "WPA2-Personal" / "WPA3-Personal" vb.
    encryption: str  # "None" / "WEP" / "CCMP" / "TKIP" vb.
    bssids: tuple[str, ...] = ()
    max_signal_percent: int = 0


# Etiketlerin Türkçe/İngilizce karşılıkları (Windows yerelleştirme)
# Dikkat: Yerelleştirilmiş Windows'ta bu karakterlerin doğru eşleşmesi lazım.
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
            self._emit_error(
                "Wi-Fi taraması yalnızca Windows'ta desteklenir "
                "(netsh wlan komutu). v2'de Linux/macOS desteği gelecek.",
            )
            return

        self._emit_progress(10, "netsh wlan komutu çalıştırılıyor...")
        output = _run_netsh_wlan()
        if output is None:
            self._emit_error(
                "netsh wlan komutu başarısız — Wi-Fi adaptörü kapalı olabilir "
                "veya komut bulunamadı. Windows Wi-Fi'ı açtığınızdan emin olun.",
            )
            return

        self._emit_progress(50, "Çıktı işleniyor...")
        networks = _parse_netsh_output(output)
        if not networks:
            self._emit_progress(
                100, "Çevrede Wi-Fi ağı bulunamadı (netsh herhangi bir ağ döndürmedi)",
            )
            return

        self._emit_progress(
            70, f"{len(networks)} Wi-Fi ağı tespit edildi, değerlendiriliyor...",
        )

        # Her ağ için bulgu üret
        for idx, net in enumerate(networks):
            if self._cancelled:
                return
            finding = _evaluate_network(net)
            if finding is not None:
                self._emit_finding(finding)

            # İlerleme güncelle
            pct = 70 + int(30 * (idx + 1) / len(networks))
            self._emit_progress(pct, f"{net.ssid or '(gizli SSID)'} değerlendirildi")

        self._emit_progress(
            100, f"Wi-Fi taraması tamamlandı — {len(networks)} ağ analiz edildi",
        )


# ---------------------------------------------------------------------
# netsh çalıştırma
# ---------------------------------------------------------------------
def _run_netsh_wlan() -> str | None:
    """`netsh wlan show networks mode=bssid` çalıştır, çıktıyı döndür.

    Hata durumunda None. Çıktı stdout (UTF-8 veya yerel codepage) olarak alınır.
    """
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

    # Windows netsh genelde yerel codepage döndürür — utf-8 ya da cp1254 deneyelim
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
    """netsh çıktısından WifiNetwork listesi çıkar.

    Basit state machine: SSID satırı yeni ağ başlatır, sonraki satırlar
    aynı ağa ait Auth/Encr/BSSID/Signal bilgilerini biriktirir.
    """
    networks: list[WifiNetwork] = []

    current_ssid: str | None = None
    current_auth: str = ""
    current_encr: str = ""
    current_bssids: list[str] = []
    current_max_signal: int = 0

    def _finalize() -> None:
        """Biriken bilgileri bir WifiNetwork olarak kaydet."""
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
            # Önceki ağı kaydet, yenisini başlat
            _finalize()
            current_ssid = ssid_m.group("ssid").strip()
            continue

        if current_ssid is None:
            # Henüz ilk SSID'ye ulaşmadık — başlık satırı
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

    # Son ağı da ekle
    _finalize()
    return networks


# ---------------------------------------------------------------------
# Finding üretimi
# ---------------------------------------------------------------------
def _evaluate_network(net: WifiNetwork) -> Finding | None:
    """Bir ağın güvenlik durumuna göre Finding döndür (yoksa None)."""
    ssid_display = net.ssid if net.ssid else "(gizli SSID)"
    auth_lower = net.authentication.lower()
    encr_lower = net.encryption.lower()

    # --- Açık (şifresiz) ağ ---
    if (
        auth_lower in ("open", "ak", "açık")
        or "open" in auth_lower
        or encr_lower in ("none", "yok", "hiçbiri")
    ):
        return Finding(
            scanner_name="wifi_scanner",
            severity=Severity.HIGH,
            title=f"Şifresiz Wi-Fi ağı: {ssid_display}",
            description=(
                f"`{ssid_display}` ağı şifresiz yayın yapıyor. Bu ağa bağlanan "
                f"kullanıcıların tüm (HTTPS dışındaki) trafiği ortamdaki herkes "
                f"tarafından dinlenebilir — parolalar, çerezler, form verileri. "
                f"Ayrıca MITM (Man-in-the-Middle) saldırılarına açıktır. Eğer bu "
                f"sizin ağınızsa ACİL olarak parola + WPA2/WPA3 ekleyin."
            ),
            target=f"wifi://{ssid_display}",
            remediation=(
                "Wi-Fi router yönetim panelinden (genelde 192.168.1.1) **WPA2-Personal** "
                "veya **WPA3-Personal** şifrelemesini etkinleştirin. Güçlü (12+ karakter, "
                "karışık) parola belirleyin. SSID'yi gizlemek GÜVENLİK DEĞİLDİR — "
                "asıl koruma şifreleme + güçlü paroladır. Misafir için ayrı bir "
                "misafir Wi-Fi oluşturup iç ağdan izole edin."
            ),
            evidence={
                "probe_name": "wifi_scanner",
                "ssid": ssid_display,
                "auth": net.authentication,
                "encryption": net.encryption,
                "bssid_count": len(net.bssids),
                "signal_percent": net.max_signal_percent,
            },
        )

    # --- WEP ağ (kırık şifreleme) ---
    if "wep" in auth_lower or "wep" in encr_lower:
        return Finding(
            scanner_name="wifi_scanner",
            severity=Severity.HIGH,
            title=f"WEP şifrelemeli Wi-Fi ağı: {ssid_display}",
            description=(
                f"`{ssid_display}` ağı WEP şifreleme kullanıyor — 2007'den beri "
                f"kırık kabul edilen bir algoritma. Modern bir dizüstü bilgisayar "
                f"(aircrack-ng) birkaç dakikada WEP anahtarını çözebilir. "
                f"Bu ağ pratik olarak şifresiz sayılmalıdır."
            ),
            target=f"wifi://{ssid_display}",
            remediation=(
                "ACİL: Router yönetim panelinden şifreleme algoritmasını WEP'ten "
                "**WPA2-Personal (AES/CCMP)** veya **WPA3-Personal**'a değiştirin. "
                "Aynı anda WPA parolasını da yenileyin. Eski cihazların WEP desteği "
                "gerektirmesi durumunda o cihazları ayrı bir ağa taşıyın veya değiştirin."
            ),
            evidence={
                "probe_name": "wifi_scanner",
                "ssid": ssid_display,
                "auth": net.authentication,
                "encryption": net.encryption,
                "bssid_count": len(net.bssids),
            },
        )

    # --- Eski WPA (TKIP) ---
    if "wpa-" in auth_lower or ("wpa" in auth_lower and "wpa2" not in auth_lower and "wpa3" not in auth_lower):
        return Finding(
            scanner_name="wifi_scanner",
            severity=Severity.MEDIUM,
            title=f"Eski WPA şifrelemeli Wi-Fi ağı: {ssid_display}",
            description=(
                f"`{ssid_display}` ağı orijinal WPA (TKIP) kullanıyor — WPA2'ye göre "
                f"zayıf, bilinen saldırılara açık. WPA2-AES'e geçmeniz önerilir."
            ),
            target=f"wifi://{ssid_display}",
            remediation=(
                "Router'da şifrelemeyi WPA → **WPA2-Personal (AES/CCMP)** olarak değiştirin. "
                "Router modern değilse (2015 öncesi) yenisini almayı değerlendirin — "
                "WPA3 destekli modeller tercih edilir."
            ),
            evidence={
                "probe_name": "wifi_scanner",
                "ssid": ssid_display,
                "auth": net.authentication,
                "encryption": net.encryption,
            },
        )

    # WPA2 / WPA3 — sağlıklı, sadece bilgi
    if net.authentication:
        return Finding(
            scanner_name="wifi_scanner",
            severity=Severity.INFO,
            title=f"Wi-Fi ağı tespit edildi: {ssid_display} ({net.authentication})",
            description=(
                f"Bu ağ modern şifreleme ({net.authentication}, {net.encryption}) "
                f"kullanıyor. Güvenli durumda görünüyor. Yine de güçlü parola "
                f"kullandığınızdan ve firmware'inizin güncel olduğundan emin olun."
            ),
            target=f"wifi://{ssid_display}",
            remediation=(
                "Güçlü parola + güncel router firmware + misafir ağ ayrımı. "
                "Eğer hâlâ WPA2 kullanıyorsanız router WPA3 destekliyorsa WPA3'e geçin."
            ),
            evidence={
                "probe_name": "wifi_scanner",
                "ssid": ssid_display,
                "auth": net.authentication,
                "encryption": net.encryption,
                "signal_percent": net.max_signal_percent,
            },
        )

    # Kimlik doğrulama bilgisi yok — nadiren olur, atla
    return None
