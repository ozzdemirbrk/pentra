"""Exposed Paths probe — hassas dosya/klasörlerin public erişimini kontrol eder.

Üç katmanlı false-positive savunması:

    1. **Soft-404 baseline**: Probe başında rastgele bir yol istenir. 200 dönerse
       sunucu 404 yerine catch-all sayfa veriyor demektir; sonraki probe'lar bu
       baseline'la karşılaştırılır (boyut + ilk 500 karakter). Benzer = atla.

    2. **Content-Type filtresi**: `.env`, `.sql`, `.htaccess` gibi teknik dosyalar
       `text/html` dönüyorsa büyük ihtimalle HTML anasayfa — sahte pozitif.

    3. **Spesifik içerik validator'ı**: Her path için yalnızca gerçek dosyanın
       üreteceği içerik pattern'i aranır (`.env` → çoklu `KEY=VALUE`, SQL dump →
       `CREATE TABLE`, git config → `[core]` başta vs.).
"""

from __future__ import annotations

import dataclasses
import re
import secrets
from collections.abc import Callable
from urllib.parse import urljoin

import requests

from pentra.core.web_probes.base import WebProbeBase
from pentra.models import Finding, Severity


# ---------------------------------------------------------------------
# Content validator'lar — her biri (is_real, evidence_snippet) döndürür
# ---------------------------------------------------------------------
Validator = Callable[[requests.Response], tuple[bool, str]]


def _is_html(response: requests.Response) -> bool:
    """Content-Type'ı HTML mi kontrol et."""
    ctype = response.headers.get("Content-Type", "").lower()
    return "html" in ctype


def _env_validator(response: requests.Response) -> tuple[bool, str]:
    """Gerçek .env: HTML değil + en az 2 `KEY=VALUE` satırı."""
    if _is_html(response):
        return False, ""
    lines = response.text[:4096].splitlines()
    env_like = [
        line for line in lines
        if re.match(r"^[A-Z_][A-Z_0-9]*\s*=", line)
    ]
    if len(env_like) >= 2:
        return True, "\n".join(env_like[:5])
    return False, ""


def _git_config_validator(response: requests.Response) -> tuple[bool, str]:
    """git/config: içerik `[core]` veya `[remote` ile başlamalı."""
    if _is_html(response):
        return False, ""
    stripped = response.text.lstrip()[:200]
    if stripped.startswith("[core]") or stripped.startswith("[remote"):
        return True, stripped
    return False, ""


def _git_head_validator(response: requests.Response) -> tuple[bool, str]:
    """git/HEAD: genelde tek satır `ref: refs/heads/main`."""
    if _is_html(response):
        return False, ""
    text = response.text.strip()
    if re.match(r"^ref:\s+refs/heads/\S+$", text) and len(text) < 100:
        return True, text
    return False, ""


def _sql_dump_validator(response: requests.Response) -> tuple[bool, str]:
    """SQL dump: HTML değil + CREATE TABLE / INSERT INTO / DROP TABLE anahtar kelimeleri."""
    if _is_html(response):
        return False, ""
    upper = response.text[:8192].upper()
    keywords = ("CREATE TABLE", "INSERT INTO", "DROP TABLE", "-- MYSQL DUMP", "-- POSTGRESQL")
    for kw in keywords:
        if kw in upper:
            idx = upper.find(kw)
            return True, response.text[max(0, idx - 20):idx + 200]
    return False, ""


def _wp_config_validator(response: requests.Response) -> tuple[bool, str]:
    """WordPress wp-config.php yedeği: <?php + DB_NAME/DB_PASSWORD sabitleri."""
    if _is_html(response):
        return False, ""
    text = response.text[:4096]
    has_php = text.lstrip().startswith("<?php")
    has_db = any(k in text for k in ("DB_NAME", "DB_PASSWORD", "DB_USER", "DB_HOST"))
    if has_php and has_db:
        return True, text[:300]
    return False, ""


def _config_json_validator(response: requests.Response) -> tuple[bool, str]:
    """config.json: gerçek JSON (HTML değil) + object yapısı."""
    if _is_html(response):
        return False, ""
    text = response.text[:4096].lstrip()
    if text.startswith("{") and '"' in text and ":" in text:
        return True, text[:200]
    return False, ""


def _config_yml_validator(response: requests.Response) -> tuple[bool, str]:
    """config.yml: HTML değil + YAML-vari `key: value` satırları."""
    if _is_html(response):
        return False, ""
    lines = response.text[:4096].splitlines()
    yml_like = [line for line in lines if re.match(r"^\s*[a-zA-Z_][\w-]*:\s*\S", line)]
    if len(yml_like) >= 2:
        return True, "\n".join(yml_like[:5])
    return False, ""


def _htaccess_validator(response: requests.Response) -> tuple[bool, str]:
    """.htaccess: HTML değil + Apache direktif anahtar kelimeleri."""
    if _is_html(response):
        return False, ""
    upper = response.text[:4096].upper()
    keywords = ("REWRITEENGINE", "REWRITERULE", "AUTHTYPE", "REQUIRE", "<IFMODULE")
    if any(kw in upper for kw in keywords):
        return True, response.text[:200]
    return False, ""


def _ds_store_validator(response: requests.Response) -> tuple[bool, str]:
    """.DS_Store: binary — başında `Bud1` magic string'i vardır."""
    if _is_html(response):
        return False, ""
    # .DS_Store büyük ihtimalle binary olarak okunur; ilk bayt kontrolü
    content = response.content[:16] if response.content else b""
    if b"Bud1" in content or b"\x00\x00\x00\x01Bud1" in content:
        return True, "[.DS_Store binary, Bud1 magic tespit edildi]"
    return False, ""


def _phpinfo_validator(response: requests.Response) -> tuple[bool, str]:
    """phpinfo.php: özel başlık + tablo yapısı."""
    # phpinfo'nun kendisi HTML dönecektir — soft 404 baseline'ı farklı korumalı
    text = response.text[:4096]
    if "phpinfo()" in text or re.search(r"<title>phpinfo\(\)", text, re.I):
        return True, "phpinfo() çıktısı tespit edildi"
    if re.search(r"PHP Version \d+\.\d+\.\d+", text):
        return True, re.search(r"PHP Version \d+\.\d+\.\d+", text).group(0)
    return False, ""


def _server_status_validator(response: requests.Response) -> tuple[bool, str]:
    """Apache server-status: "Apache Server Status" başlığı."""
    text = response.text[:4096]
    if "Apache Server Status" in text:
        return True, "Apache Server Status sayfası tespit edildi"
    if "Server uptime:" in text and "Server Version:" in text:
        return True, "server-status çıktısı tespit edildi"
    return False, ""


def _admin_validator(response: requests.Response) -> tuple[bool, str]:
    """/admin: HTML bekleniyor ama login formu/admin ipucu olmalı.

    Soft-404 baseline'ı farklı olmalı. Bu validator giriş ipucu arar.
    """
    text = response.text[:8192].lower()
    hints = (
        "admin panel", "admin login", "dashboard",
        "<title>admin", "adminlogin", "admin-password",
        "login</title>", "<h1>login",
    )
    for hint in hints:
        if hint in text:
            return True, f"Panel ipucu: `{hint}`"
    # Giriş formu var mı
    if re.search(r'<form[^>]*action=[^>]*(login|admin|auth)', text):
        return True, "Login formu tespit edildi"
    return False, ""


def _phpmyadmin_validator(response: requests.Response) -> tuple[bool, str]:
    """phpMyAdmin'in kendine özgü string'leri."""
    text = response.text[:8192]
    hints = ("phpMyAdmin", "pma_username", "pmahomme", "pma_password")
    for h in hints:
        if h in text:
            return True, f"phpMyAdmin imzası: `{h}`"
    return False, ""


# ---------------------------------------------------------------------
# Path kayıtları
# ---------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class _PathCheck:
    path: str
    severity: Severity
    title: str
    description: str
    validator: Validator
    remediation: str


_SENSITIVE_PATHS: tuple[_PathCheck, ...] = (
    _PathCheck(
        "/.env", Severity.CRITICAL, ".env dosyası public erişilebilir",
        "`.env` dosyası web kökünden erişilebilir. Bu dosyada genellikle veritabanı "
        "parolaları, API anahtarları, secret key'ler bulunur.",
        _env_validator,
        "`.env` dosyası kesinlikle web kökünde olmamalı — uygulamanın bir üst dizininde tutun. "
        "Sunucuda erişimi engelleyin ve dosyadaki tüm parolaları/anahtarları DEĞİŞTİRİN.",
    ),
    _PathCheck(
        "/.git/config", Severity.HIGH, ".git deposu public erişilebilir",
        "`.git/config` dosyası public. Saldırgan tüm kaynak kodunu ve gizli "
        "dosya geçmişini çıkarabilir (`git-dumper` ile).",
        _git_config_validator,
        "Web dizinindeki `.git/` klasörünü tamamen kaldırın. Deploy sürecinde `.git`'i hariç tutun. "
        "Nginx: `location ~ /\\.git { deny all; }`",
    ),
    _PathCheck(
        "/.git/HEAD", Severity.HIGH, ".git/HEAD public",
        "`.git/HEAD` public — kaynak kodu çıkarma saldırısına açık.",
        _git_head_validator,
        "Web dizinindeki `.git/` klasörünü tamamen kaldırın.",
    ),
    _PathCheck(
        "/backup.sql", Severity.CRITICAL, "Veritabanı yedeği public (backup.sql)",
        "`/backup.sql` erişilebilir. Tüm DB şeması + veriler sızabilir.",
        _sql_dump_validator,
        "Yedek dosyalarını asla web dizininde tutmayın. Hemen silin, DB parolalarını değiştirin.",
    ),
    _PathCheck(
        "/database.sql", Severity.CRITICAL, "Veritabanı yedeği public (database.sql)",
        "`/database.sql` erişilebilir. DB içeriği sızabilir.",
        _sql_dump_validator,
        "Yedek dosyalarını asla web dizininde tutmayın. Hemen silin, DB parolalarını değiştirin.",
    ),
    _PathCheck(
        "/dump.sql", Severity.CRITICAL, "Veritabanı dump'ı public (dump.sql)",
        "`/dump.sql` erişilebilir. DB içeriği sızabilir.",
        _sql_dump_validator,
        "Yedek dosyalarını silin, DB parolalarını değiştirin.",
    ),
    _PathCheck(
        "/wp-config.php.bak", Severity.CRITICAL, "WordPress yapılandırma yedeği (.bak) sızmış",
        "`wp-config.php.bak` erişilebilir. DB parolası ve secret key'ler içerir.",
        _wp_config_validator,
        "Yedekleri silin ve WordPress DB parolası + secret key'leri değiştirin.",
    ),
    _PathCheck(
        "/wp-config.php.save", Severity.CRITICAL, "WordPress yapılandırma yedeği (.save) sızmış",
        "`wp-config.php.save` erişilebilir.",
        _wp_config_validator,
        "Yedekleri silin ve WordPress DB parolası + secret key'leri değiştirin.",
    ),
    _PathCheck(
        "/config.json", Severity.HIGH, "config.json public",
        "Uygulama yapılandırması dışarıya sızıyor — sırlar içerebilir.",
        _config_json_validator,
        "Yapılandırma dosyalarını web dizininde tutmayın.",
    ),
    _PathCheck(
        "/config.yml", Severity.HIGH, "config.yml public",
        "Uygulama yapılandırması dışarıya sızıyor — sırlar içerebilir.",
        _config_yml_validator,
        "Yapılandırma dosyalarını web dizininde tutmayın.",
    ),
    _PathCheck(
        "/.htaccess", Severity.MEDIUM, ".htaccess dosyası erişilebilir",
        "`.htaccess` Apache yapılandırması normalde okunamamalı.",
        _htaccess_validator,
        "Sunucu yapılandırmasını düzeltin — `.htaccess` dışa erişilemez olmalı.",
    ),
    _PathCheck(
        "/.DS_Store", Severity.LOW, ".DS_Store sızmış (macOS meta veri)",
        "`.DS_Store` dosyası klasör içindeki dosya listesini içerir — gizli dosya "
        "adlarını saldırgana verir.",
        _ds_store_validator,
        "`.DS_Store` dosyasını deploy'dan hariç tutun (`.gitignore`: `**/.DS_Store`).",
    ),
    _PathCheck(
        "/server-status", Severity.MEDIUM, "Apache server-status public",
        "`/server-status` sayfası aktif bağlantıları, istekleri, vhosts bilgisini dışa açar.",
        _server_status_validator,
        "Apache `mod_status` modülünü kapatın veya sadece localhost'a izin verin.",
    ),
    _PathCheck(
        "/phpinfo.php", Severity.HIGH, "phpinfo.php public",
        "`phpinfo.php` erişilebilir. PHP yapılandırması, yollar, environment değişkenleri sızıyor.",
        _phpinfo_validator,
        "`phpinfo.php`'yi silin — geliştirme araçları production'da olmamalı.",
    ),
    _PathCheck(
        "/admin", Severity.INFO, "Admin paneli tespit edildi",
        "`/admin` yolu gerçek bir admin paneline işaret ediyor. Bu tek başına zafiyet değil "
        "ama saldırgan odağı olur; güçlü kimlik doğrulama + IP kısıtlaması önerilir.",
        _admin_validator,
        "Admin paneline sadece VPN veya belirli IP'ler üzerinden erişime izin verin. "
        "Güçlü parola + MFA zorunlu.",
    ),
    _PathCheck(
        "/phpmyadmin", Severity.LOW, "phpMyAdmin public",
        "`/phpmyadmin` erişilebilir ve phpMyAdmin imzası tespit edildi. "
        "Brute-force + zafiyet denemesinin ilk hedefi olur.",
        _phpmyadmin_validator,
        "phpMyAdmin'i kaldırın veya VPN arkasına taşıyın.",
    ),
)


# ---------------------------------------------------------------------
# Soft-404 baseline
# ---------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class _Baseline:
    """Rastgele yol denemesinden elde edilen "bulunamadı yanıtı" imzası."""

    status: int
    length: int
    snippet: str  # ilk 500 karakter


def _capture_baseline(base_url: str, session: requests.Session, timeout: float) -> _Baseline | None:
    """Sunucu 404 davranışını öğrenmek için rastgele yol dener."""
    random_path = f"/pentra-nonexistent-{secrets.token_hex(8)}"
    full = urljoin(base_url.rstrip("/") + "/", random_path.lstrip("/"))
    try:
        response = session.get(full, timeout=timeout, allow_redirects=False)
    except requests.RequestException:
        return None
    return _Baseline(
        status=response.status_code,
        length=len(response.content or b""),
        snippet=response.text[:500] if response.text else "",
    )


def _looks_like_baseline(response: requests.Response, baseline: _Baseline) -> bool:
    """Yanıt baseline'a benziyor mu — aynı soft-404 sayfası mı."""
    # Status farklı ise farklı yanıt
    if response.status_code != baseline.status:
        return False
    # Boyut %10 içinde ise aynı sayfa kabul et
    actual_length = len(response.content or b"")
    if baseline.length > 0:
        diff_ratio = abs(actual_length - baseline.length) / baseline.length
        if diff_ratio < 0.1:
            return True
    # Snippet neredeyse aynı ise aynı sayfa
    snippet = response.text[:500] if response.text else ""
    if snippet and baseline.snippet and snippet == baseline.snippet:
        return True
    return False


# ---------------------------------------------------------------------
# Ana probe sınıfı
# ---------------------------------------------------------------------
class ExposedPathsProbe(WebProbeBase):
    name: str = "exposed_paths"
    description: str = "Hassas dosya/klasörlerin public erişim kontrolü"

    def probe(self, url: str, session: requests.Session) -> list[Finding]:
        findings: list[Finding] = []
        base = url.rstrip("/")

        # 1. Soft-404 baseline
        baseline = _capture_baseline(base, session, self.timeout)

        # 2. Her hassas yolu test et
        for check in _SENSITIVE_PATHS:
            full_url = urljoin(base + "/", check.path.lstrip("/"))

            try:
                response = session.get(
                    full_url, timeout=self.timeout, allow_redirects=False,
                )
            except requests.RequestException:
                continue

            # 404 / 403 / 301 / 302 → dosya yok veya erişim kapalı, atla
            if response.status_code not in (200, 204):
                continue

            # Soft-404 filtresi
            if baseline is not None and _looks_like_baseline(response, baseline):
                continue

            # Spesifik content validator
            is_real, evidence_snippet = check.validator(response)
            if not is_real:
                continue

            findings.append(
                Finding(
                    scanner_name="web_scanner",
                    severity=check.severity,
                    title=check.title,
                    description=check.description,
                    target=full_url,
                    remediation=check.remediation,
                    evidence=self._build_evidence(
                        request_method="GET",
                        request_path=full_url,
                        response_status=response.status_code,
                        response_snippet=evidence_snippet[:200],
                        why_vulnerable=(
                            "Content validator eşleşti — gerçek dosya imzası tespit edildi"
                        ),
                        extra={"content_type": response.headers.get("Content-Type", "")},
                    ),
                ),
            )

        # 3. security.txt — ters mantık (yoksa uyar)
        security_url = urljoin(base + "/", ".well-known/security.txt")
        try:
            sec_response = session.get(
                security_url, timeout=self.timeout, allow_redirects=False,
            )
            # Soft-404 durumunda da "yok" olarak kabul et
            is_missing = (
                sec_response.status_code == 404
                or (baseline is not None and _looks_like_baseline(sec_response, baseline))
            )
            if is_missing:
                findings.append(
                    Finding(
                        scanner_name="web_scanner",
                        severity=Severity.INFO,
                        title="security.txt yok",
                        description=(
                            "`/.well-known/security.txt` dosyası yok. Güvenlik "
                            "araştırmacılarının size zafiyet bildirebilmesi için "
                            "bu dosyayı yayınlayın."
                        ),
                        target=security_url,
                        remediation=(
                            "`/.well-known/security.txt` dosyası oluşturun. "
                            "İçerik örneği: `Contact: mailto:security@example.com`, "
                            "`Expires: 2027-01-01T00:00:00Z`. Detay: https://securitytxt.org"
                        ),
                        evidence=self._build_evidence(
                            request_method="GET",
                            request_path=security_url,
                            response_status=sec_response.status_code,
                            why_vulnerable="Dosya yok veya erişilemiyor",
                        ),
                    ),
                )
        except requests.RequestException:
            pass

        return findings
