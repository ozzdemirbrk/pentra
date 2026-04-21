"""NVD (National Vulnerability Database) API istemcisi.

NVD REST 2.0 API kullanır: https://services.nvd.nist.gov/rest/json/cves/2.0
Anonymous: 5 istek / 30 saniye. API key ile: 50 istek / 30 saniye.
Ücretsiz API key: https://nvd.nist.gov/developers/request-an-api-key

Özellikler:
    - Rate limit (TokenBucket) — otomatik bekleme
    - Oturum-içi bellek cache — aynı sorgu tekrar edilmez
    - Timeout + hata yutma — ağ hatası varsa boş liste döner (scanner durmasın)
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Any

import requests

from pentra.core.rate_limiter import TokenBucket

logger = logging.getLogger(__name__)

_NVD_ENDPOINT: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_DEFAULT_TIMEOUT: float = 15.0


@dataclasses.dataclass(frozen=True)
class Cve:
    """Tek bir CVE kaydının özeti."""

    cve_id: str
    cvss_score: float | None  # 0.0 — 10.0, bilinmiyorsa None
    severity: str  # "CRITICAL" / "HIGH" / "MEDIUM" / "LOW" / "NONE" / "UNKNOWN"
    description: str  # İlk 300 karakter (özet için)
    published_date: str = ""  # "2024-01-15" formatı (opsiyonel)

    @property
    def nvd_url(self) -> str:
        """CVE'nin NVD detay sayfası URL'i."""
        return f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"


class NvdClient:
    """NVD REST API için hafif istemci.

    Kullanımı:
        client = NvdClient()  # anonymous
        cves = client.search_cves("Microsoft IIS 10.0")

        # API key ile:
        client = NvdClient(api_key="xxxxx")
    """

    def __init__(
        self,
        api_key: str | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        self._api_key = api_key
        self._timeout = timeout
        self._cache: dict[str, list[Cve]] = {}

        # Rate limiter — API key varsa 50/30s, yoksa 5/30s
        if api_key:
            self._rate_limiter = TokenBucket(
                capacity=50, refill_rate_per_sec=50.0 / 30.0,
            )
        else:
            self._rate_limiter = TokenBucket(
                capacity=5, refill_rate_per_sec=5.0 / 30.0,
            )

        self._session = requests.Session()
        if api_key:
            self._session.headers["apiKey"] = api_key

    def search_by_cpe(self, cpe_name: str, max_results: int = 20) -> list[Cve]:
        """CPE URI ile tam versiyon eşleşmesi — keyword'den çok daha doğru.

        CPE formatı: `cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*`
        Örnek: `cpe:2.3:a:microsoft:internet_information_services:10.0:*:*:*:*:*:*:*`

        Bu endpoint NVD'nin `cpeName` parametresini kullanır — açıklama metninde
        versiyon geçmese bile (NVD'nin CPE indeksinden) CVE'leri getirir.
        """
        cache_key = f"cpe||{cpe_name}||{max_results}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        if not self._rate_limiter.wait_for(1, timeout=60.0):
            logger.warning("NVD rate limit timeout — CPE araması iptal")
            return []

        params = {"cpeName": cpe_name, "resultsPerPage": min(max_results, 200)}
        try:
            response = self._session.get(
                _NVD_ENDPOINT, params=params, timeout=self._timeout,
            )
            response.raise_for_status()
            data = response.json()
        except (requests.RequestException, ValueError) as e:
            logger.warning("NVD CPE isteği başarısız: %s", e)
            return []

        cves = _parse_nvd_response(data, must_contain=())
        cves = cves[:max_results]
        cves.sort(key=lambda c: (c.cvss_score or 0.0), reverse=True)

        self._cache[cache_key] = cves
        return cves

    def search_cves(
        self,
        keyword: str,
        max_results: int = 20,
        must_contain: tuple[str, ...] = (),
    ) -> list[Cve]:
        """Keyword araması — NVD'de açıklama içinde eşleşen CVE'leri döndürür.

        Args:
            keyword: NVD'ye gönderilecek arama metni (ör. "Microsoft IIS 10.0")
            max_results: En fazla kaç CVE dönsün
            must_contain: Post-filter — CVE açıklaması bu string'leri (case-insensitive)
                içermiyorsa elenir. Örn: ("IIS", "10.0"). NVD keyword araması gevşek
                olduğu için bu filtre kritik.

        Returns:
            CVE listesi. Hata / ağ sorunu / sonuç yok → boş liste.
        """
        cache_key = f"{keyword}||{','.join(must_contain)}||{max_results}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        # Rate limit (hata verirse timeout ile döner)
        if not self._rate_limiter.wait_for(1, timeout=60.0):
            logger.warning("NVD rate limit timeout — istek iptal edildi")
            return []

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(max_results * 3, 200),  # post-filter'dan sonra az kalmasın
        }

        try:
            response = self._session.get(
                _NVD_ENDPOINT, params=params, timeout=self._timeout,
            )
            response.raise_for_status()
        except requests.RequestException as e:
            logger.warning("NVD API isteği başarısız: %s", e)
            return []

        try:
            data = response.json()
        except ValueError as e:
            logger.warning("NVD JSON parse hatası: %s", e)
            return []

        cves = _parse_nvd_response(data, must_contain)
        cves = cves[:max_results]

        # CVSS skoruna göre azalan sırala (en kritik önce)
        cves.sort(key=lambda c: (c.cvss_score or 0.0), reverse=True)

        self._cache[cache_key] = cves
        return cves


# ---------------------------------------------------------------------
# NVD JSON parser
# ---------------------------------------------------------------------
def _parse_nvd_response(
    data: dict[str, Any],
    must_contain: tuple[str, ...],
) -> list[Cve]:
    """NVD 2.0 API cevabını Cve listesine çevirir + post-filter uygular."""
    vulnerabilities = data.get("vulnerabilities", [])
    must_lower = tuple(s.lower() for s in must_contain)

    results: list[Cve] = []
    for entry in vulnerabilities:
        cve_obj = entry.get("cve", {})
        cve_id = cve_obj.get("id", "")
        if not cve_id:
            continue

        description = _extract_description(cve_obj)
        if not description:
            continue

        # Post-filter: must_contain stringlerinin hepsi açıklamada olmalı
        desc_lower = description.lower()
        if must_lower and not all(s in desc_lower for s in must_lower):
            continue

        score, severity = _extract_cvss(cve_obj)
        published = cve_obj.get("published", "")[:10]  # "YYYY-MM-DD"

        results.append(
            Cve(
                cve_id=cve_id,
                cvss_score=score,
                severity=severity,
                description=description[:300],
                published_date=published,
            ),
        )

    return results


def _extract_description(cve_obj: dict[str, Any]) -> str:
    """İngilizce açıklamayı çıkarır (NVD Türkçe vermez)."""
    descriptions = cve_obj.get("descriptions", [])
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value", "")
    # İngilizce yoksa ilk varı döndür
    if descriptions:
        return descriptions[0].get("value", "")
    return ""


def _extract_cvss(cve_obj: dict[str, Any]) -> tuple[float | None, str]:
    """CVSS 3.1 / 3.0 / 2.0 önceliğiyle skor ve severity çıkarır."""
    metrics = cve_obj.get("metrics", {})

    # v3.1 öncelikli
    for metric_key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(metric_key, [])
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity", "UNKNOWN")
            if score is not None:
                return float(score), str(severity).upper()

    # v2.0 fallback
    entries = metrics.get("cvssMetricV2", [])
    if entries:
        cvss_data = entries[0].get("cvssData", {})
        score = cvss_data.get("baseScore")
        if score is not None:
            # v2'de severity farklı — skor aralığından türetiliyor
            score_f = float(score)
            if score_f >= 9.0:
                sev = "CRITICAL"
            elif score_f >= 7.0:
                sev = "HIGH"
            elif score_f >= 4.0:
                sev = "MEDIUM"
            else:
                sev = "LOW"
            return score_f, sev

    return None, "UNKNOWN"
