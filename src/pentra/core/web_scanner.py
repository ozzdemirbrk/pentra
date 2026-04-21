"""Web Scanner — URL hedeflerinde Seviye 2 probe'ları çalıştırır.

Bir URL alır, kayıtlı probe'ların her birini sırayla çalıştırır, bulguları
Qt sinyalleri üzerinden UI'ye yayar. Her probe tek bir zafiyet kategorisine
odaklanır (WebProbeBase alt sınıfı) — yeni probe eklemek = yeni sınıf yazmak.
"""

from __future__ import annotations

import requests

from pentra.core.scanner_base import ScannerBase
from pentra.core.web_probes.base import WebProbeBase
from pentra.core.web_probes.exposed_paths import ExposedPathsProbe
from pentra.core.web_probes.path_traversal import PathTraversalProbe
from pentra.core.web_probes.security_headers import SecurityHeadersProbe
from pentra.core.web_probes.sql_injection import SqlInjectionProbe
from pentra.core.web_probes.ssl_tls import SslTlsProbe
from pentra.core.web_probes.xss import XssProbe
from pentra.models import ScanDepth, Target

# User-Agent — probe'ların kendilerini tanıtması bir etik norm
_USER_AGENT = (
    "Pentra/0.2 (+https://github.com/ozzdemirbrk/pentra; "
    "security-assessment scanner)"
)


class WebScanner(ScannerBase):
    """URL hedeflerini tarar — kayıtlı probe'ları sırayla çalıştırır."""

    @property
    def scanner_name(self) -> str:
        return "web_scanner"

    # -----------------------------------------------------------------
    # ScannerBase._do_scan implementasyonu
    # -----------------------------------------------------------------
    def _do_scan(self, target: Target, depth: ScanDepth) -> None:
        probes = _select_probes(depth)
        if not probes:
            self._emit_progress(100, "Bu derinlik için uygun probe yok")
            return

        self._emit_progress(5, f"Web taraması başlıyor: {target.value}")

        # Paylaşımlı HTTP oturumu
        session = requests.Session()
        session.headers.update({"User-Agent": _USER_AGENT})
        # SSL sertifikasını doğrula (MVP'de — sonradan opt-out eklenebilir)
        session.verify = True

        total = len(probes)
        total_findings = 0

        for idx, probe in enumerate(probes):
            if self._cancelled:
                return

            if not self._throttle(packets=1):
                return

            percent = 10 + int(85 * idx / total)
            self._emit_progress(
                percent, f"[{idx + 1}/{total}] Probe: {probe.description}",
            )

            try:
                findings = probe.probe(target.value, session)
            except requests.RequestException as e:
                # Probe kendi yakalayamadıysa: bilgilendirme, devam
                self._emit_progress(
                    percent, f"{probe.name} ağ hatası — atlanıyor: {e}",
                )
                continue
            except Exception as e:  # noqa: BLE001
                # Beklenmeyen hata — raporla ama taramayı durdurma
                self._emit_error(f"{probe.name} hatası: {e}")
                continue

            for f in findings:
                self._emit_finding(f)
                total_findings += 1
                if self._cancelled:
                    return

        session.close()
        self._emit_progress(
            100, f"Web taraması tamamlandı — {total_findings} bulgu",
        )


# ---------------------------------------------------------------------
# Probe kaydı & seçimi
# ---------------------------------------------------------------------
def _all_registered_probes() -> list[WebProbeBase]:
    """Tüm kayıtlı probe örneklerini döner.

    Yeni probe eklendikçe bu fonksiyona import + instance eklenir.
    """
    return [
        SecurityHeadersProbe(),
        ExposedPathsProbe(),
        SslTlsProbe(),
        PathTraversalProbe(),
        SqlInjectionProbe(),
        XssProbe(),
    ]


def _select_probes(depth: ScanDepth) -> list[WebProbeBase]:
    """Derinliğe göre probe listesi.

    MVP: tüm derinliklerde tüm probe'lar. Faz 4'te alt kümeye bölünebilir.
    """
    del depth  # MVP'de derinlikten bağımsız
    return _all_registered_probes()
